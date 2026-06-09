"""Model client abstraction.

The lab runs the **same agent code** against one of two model backends; which
one is just configuration, so there is a single code path to reason about:

* **Local SLM** (``OFFLINE_MODE=true``, the default) — a real **small language
  model** served locally through an OpenAI-compatible endpoint. The default
  runtime is **Microsoft Foundry Local** (``foundry model run phi-3.5-mini``),
  which exposes the *same* OpenAI client surface as Azure AI Foundry, so the
  app talks to it with zero Azure resources and zero cost. Any OpenAI-compatible
  server works too (e.g. Ollama at ``http://localhost:11434/v1``).

* **Azure AI Foundry** (``OFFLINE_MODE=false``) — the same call goes to a real
  Foundry model deployment via the **Azure AI Foundry project SDK**
  (``AIProjectClient.get_openai_client()``), orchestrated with the
  **Microsoft Agent Framework**.

Interactive and lab runs require a real model: Foundry Local, another
OpenAI-compatible local endpoint, or Azure AI Foundry. There is no fake model
fallback in the app path.
"""

from __future__ import annotations

import logging
import os
import random
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from functools import lru_cache

from src.config import get_settings

logger = logging.getLogger("zava.model")

# API version used when routing through the APIM AI gateway (AzureOpenAI client).
_AOAI_API_VERSION = "2024-10-21"


class ModelSafetyBlocked(RuntimeError):
    """Raised when the Azure Foundry deployment blocks a model request."""


def _is_rate_limit_error(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status_code == 429:
        return True
    body = getattr(exc, "body", None)
    error = body.get("error", {}) if isinstance(body, dict) else {}
    code = str(error.get("code") or getattr(exc, "code", "")).lower()
    text = str(exc).lower()
    return any(
        marker in code or marker in text
        for marker in ("429", "rate_limit", "ratelimit", "too_many_requests", "too many requests")
    )


def _rate_limited_answer(deployments: list[str]) -> str:
    return (
        "The Azure AI model pool is busy right now. I retried all configured "
        f"deployments ({', '.join(deployments)}) and waited for capacity to free up. "
        "Please retry in a moment; the request was not processed."
    )


def _raise_if_content_filter(exc: Exception) -> None:
    body = getattr(exc, "body", None)
    error = body.get("error", {}) if isinstance(body, dict) else {}
    text = str(exc)
    if error.get("code") == "content_filter" or "content_filter" in text or "ResponsibleAIPolicyViolation" in text:
        raise ModelSafetyBlocked(
            "Azure Foundry content filter blocked this prompt or retrieved context."
        ) from exc


def _ensure_azure_cli_on_path() -> None:
    """Help DefaultAzureCredential find Azure CLI in local Windows labs."""
    az_dir = Path(r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin")
    if os.name != "nt" or not (az_dir / "az.cmd").exists():
        return
    path_parts = os.environ.get("PATH", "").split(os.pathsep)
    if str(az_dir) not in path_parts:
        os.environ["PATH"] = os.pathsep.join([str(az_dir), *path_parts])


@lru_cache
def _local_client() -> tuple[object, str] | None:
    """Build an OpenAI-compatible client for the local SLM, or return ``None``
    if neither Foundry Local nor a configured endpoint is available.

    Resolution order:
      1. Foundry Local via ``foundry-local-sdk`` (auto-discovers endpoint+model).
      2. ``LOCAL_MODEL_ENDPOINT`` (any OpenAI-compatible server, incl. Ollama).
    """
    settings = get_settings()

    # 1) Foundry Local SDK — best experience, auto-starts the service.
    if not settings.local_model_endpoint:
        try:
            from foundry_local import FoundryLocalManager  # type: ignore  # noqa: PLC0415
            from openai import OpenAI  # noqa: PLC0415

            manager = FoundryLocalManager(settings.local_model_name)
            model_info = manager.get_model_info(settings.local_model_name)
            client = OpenAI(
                base_url=manager.endpoint,
                api_key=manager.api_key or "not-needed",
                timeout=settings.local_model_timeout_seconds,
            )
            logger.info("model: using Foundry Local (%s)", model_info.id)
            return client, model_info.id
        except Exception:  # SDK missing / service unavailable -> try endpoint.
            pass

    # 2) Explicit OpenAI-compatible endpoint (Foundry Local fixed port, Ollama…).
    if settings.local_model_endpoint:
        try:
            from openai import OpenAI  # noqa: PLC0415

            client = OpenAI(
                base_url=settings.local_model_endpoint,
                api_key=settings.local_model_key or "not-needed",
                timeout=settings.local_model_timeout_seconds,
            )
            logger.info(
                "model: using local SLM endpoint %s (%s)",
                settings.local_model_endpoint,
                settings.local_model_name,
            )
            return client, settings.local_model_name
        except Exception:
            logger.warning("model: local SLM endpoint configured but openai client unavailable")

    return None


def _call_foundry_with_pool(client: object, system_prompt: str, user_message: str, context: str) -> str:
    settings = get_settings()
    deployments = list(settings.active_model_deployments)
    max_rounds = max(1, settings.foundry_rate_limit_retry_rounds + 1)

    last_rate_limit: Exception | None = None
    for round_index in range(max_rounds):
        attempt_order = deployments[:]
        random.shuffle(attempt_order)
        for deployment in attempt_order:
            try:
                completion = client.chat.completions.create(  # type: ignore[attr-defined]
                    model=deployment,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"{user_message}\n\nContext:\n{context}"},
                    ],
                )
                return completion.choices[0].message.content or ""
            except Exception as exc:
                _raise_if_content_filter(exc)
                if not _is_rate_limit_error(exc):
                    raise
                last_rate_limit = exc
                logger.warning("model: deployment %s rate-limited; trying next deployment", deployment)

        if round_index < max_rounds - 1:
            wait_seconds = settings.foundry_rate_limit_backoff_seconds * (round_index + 1)
            logger.warning(
                "model: all deployments rate-limited; waiting %.1fs before retry round %d/%d",
                wait_seconds,
                round_index + 2,
                max_rounds,
            )
            time.sleep(wait_seconds)

    if last_rate_limit is not None:
        logger.error("model: all deployments remained rate-limited after %d rounds", max_rounds)
        return _rate_limited_answer(deployments)
    raise RuntimeError("No Azure AI Foundry model deployments are configured.")


def _call_local_slm(system_prompt: str, user_message: str, context: str) -> str | None:
    """Call the local SLM; return ``None`` when no real model is available."""
    built = _local_client()
    if built is None:
        return None
    client, model_name = built

    try:
        completion = client.chat.completions.create(  # type: ignore[attr-defined]
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{user_message}\n\nContext:\n{context}"},
            ],
            temperature=0.2,
            max_tokens=400,
        )
        return completion.choices[0].message.content or ""
    except Exception as exc:
        logger.warning("model: local SLM call failed (%s)", exc)
        return None


def _call_local_slm_with_timeout(system_prompt: str, user_message: str, context: str) -> str | None:
    settings = get_settings()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(_call_local_slm, system_prompt, user_message, context).result(
            timeout=settings.local_model_timeout_seconds
        )
    except FutureTimeoutError:
        logger.warning("model: local model path timed out after %.1fs", settings.local_model_timeout_seconds)
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def compose_answer(system_prompt: str, user_message: str, context: str = "") -> str:
    settings = get_settings()

    use_vulnerable_local_model = not settings.enable_content_safety and bool(settings.local_model_endpoint)
    if settings.offline_mode or use_vulnerable_local_model:
        answer = _call_local_slm_with_timeout(system_prompt, user_message, context)
        if answer is not None:
            return answer
        if use_vulnerable_local_model:
            raise RuntimeError(
                "Vulnerable baseline mode requires the local unguarded model endpoint, "
                "but LOCAL_MODEL_ENDPOINT is not reachable. Refusing to fall back to a "
                "governed Foundry deployment for the baseline prompts."
            )
        raise RuntimeError(
            "No real local model is reachable. Start Microsoft Foundry Local "
            f"(`foundry model run {settings.local_model_name}`) or set "
            "LOCAL_MODEL_ENDPOINT to an OpenAI-compatible endpoint."
        )

    # --- Azure AI Foundry + Microsoft Agent Framework path -----------------
    # Lazy imports so offline mode needs no Azure SDKs.
    _ensure_azure_cli_on_path()
    from azure.ai.projects import AIProjectClient  # noqa: PLC0415
    from azure.identity import DefaultAzureCredential  # noqa: PLC0415

    from src.agents.gateway import model_client_base_url  # noqa: PLC0415

    credential = DefaultAzureCredential()
    gateway_url = model_client_base_url()
    if gateway_url:
        # SECURE (V10): route the call through Azure API Management. APIM holds
        # the model key and enforces rate-limit / authn / observability policies
        # (infra/apim.tf); the app authenticates with its Entra token only.
        from azure.identity import get_bearer_token_provider  # noqa: PLC0415
        from openai import AzureOpenAI  # noqa: PLC0415

        token_provider = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default"
        )
        client = AzureOpenAI(
            azure_endpoint=gateway_url,
            azure_ad_token_provider=token_provider,
            api_version=_AOAI_API_VERSION,
            timeout=60.0,
        )
    else:
        # LAB-VULN(V10): app talks to the deployment directly (static key path).
        if not settings.foundry_project_endpoint:
            raise RuntimeError(
                "FOUNDRY_PROJECT_ENDPOINT is required when OFFLINE_MODE=false. "
                "Set it to the Azure AI Foundry project endpoint."
            )
        project = AIProjectClient(
            endpoint=settings.foundry_project_endpoint,
            credential=credential,
        )
        client = project.get_openai_client()
    return _call_foundry_with_pool(client, system_prompt, user_message, context)
