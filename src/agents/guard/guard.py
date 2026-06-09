"""Safety guard used as Agent Framework middleware.

Centralizes the input/output protections that the lab toggles on. Each is a
*separate, independently testable aspect* of the guardrail stack, mirroring the
distinct features of Azure AI Content Safety / Foundry guardrails:

* **Content Safety harm categories** (V1) — the four Azure categories *Sexual,
  Hate, Violence, Self-Harm*, each with its **own severity threshold** (0-7),
  exactly like the per-category sliders in the portal.
* **Custom category** (V1) — an org-specific "off-topic/politics" rule that is
  *not* a model harm category, mirroring Azure Content Safety **custom
  categories / blocklists**; toggled separately (an alternative to scoping it
  in the system prompt).
* **Prompt Shields** (V2) — detect direct jailbreaks in user input *and*
  indirect prompt-injection payloads embedded in retrieved documents.
* **PII redaction** (V3) — detect + redact PII before it reaches the model,
  the logs, or the response, mirroring Azure AI Language PII.
* **Groundedness** (V6) — flag answers not supported by retrieved sources.

When the matching toggle is **off**, each guard is a no-op so the vulnerable
baseline behaves unsafely on purpose.

When a guard toggle is **on**, the corresponding Azure service is required:
Azure AI Content Safety for harm categories, Prompt Shields and Groundedness;
Azure AI Language for PII. Missing configuration or service failures fail closed
with a clear setup error instead of silently using local keyword checks.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from src.config import get_settings

logger = logging.getLogger("zava.guard")

# Content Safety severity (0-7) at/above which a category counts as a block.
# The default lives in config (CONTENT_SAFETY_SEVERITY_THRESHOLD) so a learner
# can tune strictness without editing code, exactly like the Azure portal.
_CS_API_VERSION = "2024-09-01"
_CS_GROUNDEDNESS_API_VERSION = "2024-09-15-preview"
_PII_MAX_DOCUMENT_CHARS = 4500

# --- A2A (agent-to-agent) forbidden cross-agent directives (V11) ------------
# State-changing actions one agent must never be able to command in another via
# an unverified handoff message. These deliberately do NOT overlap with the
# jailbreak patterns above — a forged handoff looks like a normal instruction.
_A2A_ACTION_PATTERNS = [
    r"\btransfer\b.*\bto\b",
    r"\bwire\b.*\b(funds|money|\$?\d)",
    r"\bsend\b.*\b(statement|email|payment)\b",
    r"\bpay\b.*\b\$?\d",
]

class SafetyViolation(RuntimeError):
    """Raised when a guard blocks content."""

    def __init__(self, reason: str, category: str) -> None:
        super().__init__(reason)
        self.category = category


class SecurityConfigurationError(SafetyViolation):
    """Raised when an enabled Azure security control is not configured."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, "configuration")


@dataclass
class PiiResult:
    text: str
    entities: list[dict[str, str]] = field(default_factory=list)


# --- Azure service dispatch helpers ----------------------------------------
# Enabled guards require Azure endpoints. httpx is used directly for the
# Content Safety REST surface (analyze / shieldPrompt / detectGroundedness);
# Azure AI Language PII uses its SDK (lazy-imported so the vulnerable baseline
# never needs it installed).
def _content_safety_creds() -> tuple[str, str | None] | None:
    s = get_settings()
    if s.content_safety_endpoint:
        return s.content_safety_endpoint.rstrip("/"), s.content_safety_key or None
    return None


def _language_creds() -> tuple[str, str | None] | None:
    s = get_settings()
    if s.language_endpoint:
        return s.language_endpoint.rstrip("/"), s.language_key or None
    return None


def _ai_service_headers(key: str | None) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if key:
        headers["Ocp-Apim-Subscription-Key"] = key
        return headers

    _ensure_azure_cli_on_path()
    from azure.identity import DefaultAzureCredential

    token = DefaultAzureCredential().get_token(
        "https://cognitiveservices.azure.com/.default"
    ).token
    headers["Authorization"] = f"Bearer {token}"
    return headers


def _ensure_azure_cli_on_path() -> None:
    """Help DefaultAzureCredential find Azure CLI in local Windows labs."""
    az_dir = Path(r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin")
    if os.name != "nt" or not (az_dir / "az.cmd").exists():
        return
    path_parts = os.environ.get("PATH", "").split(os.pathsep)
    if str(az_dir) not in path_parts:
        os.environ["PATH"] = os.pathsep.join([str(az_dir), *path_parts])


def _azure_check_content_safety(text: str, creds: tuple[str, str]) -> None:
    """Genuine Azure AI Content Safety ``text:analyze`` — raises on a harm hit."""
    endpoint, key = creds
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:analyze?api-version={_CS_API_VERSION}",
        headers=_ai_service_headers(key),
        json={"text": text, "outputType": "FourSeverityLevels"},
        timeout=10.0,
    )
    resp.raise_for_status()
    settings = get_settings()
    # Azure returns category names Hate / Sexual / Violence / SelfHarm; map to
    # our snake_case keys so each gets its own per-category threshold (mirroring
    # the per-category sliders in the Content Safety portal).
    _alias = {"selfharm": "self_harm"}
    payload = resp.json()
    for item in payload.get("categoriesAnalysis", []):
        category = str(item.get("category", "harmful")).lower()
        key = _alias.get(category, category)
        threshold = settings.category_threshold(key)
        if int(item.get("severity", 0)) >= threshold:
            raise SafetyViolation(f"Blocked harmful content ({key}).", key)
    if settings.content_safety_block_off_topic and payload.get("blocklistsMatch"):
        raise SafetyViolation("Request is outside Zava's financial scope.", "off_topic")
    for item in payload.get("customCategoryAnalysis", []):
        if settings.content_safety_block_off_topic and item.get("detected"):
            raise SafetyViolation("Request is outside Zava's financial scope.", "off_topic")


def _azure_shield_prompt(text: str, source: str) -> None:
    """Genuine Azure AI Content Safety ``text:shieldPrompt`` — raises on attack."""
    creds = _content_safety_creds()
    if creds is None:
        raise SecurityConfigurationError(
            "Prompt Shields are enabled but CONTENT_SAFETY_ENDPOINT is not configured."
        )
    endpoint, key = creds
    body = {"userPrompt": text} if source == "user" else {"documents": [text]}
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:shieldPrompt?api-version={_CS_API_VERSION}",
        headers=_ai_service_headers(key),
        json=body,
        timeout=10.0,
    )
    resp.raise_for_status()
    payload = resp.json()
    attacked = bool(payload.get("userPromptAnalysis", {}).get("attackDetected")) or any(
        d.get("attackDetected") for d in payload.get("documentsAnalysis", [])
    )
    if attacked:
        raise SafetyViolation(
            f"Prompt-injection attempt detected in {source} content.",
            "jailbreak" if source == "user" else "indirect_injection",
        )


def _pii_chunks(text: str) -> list[str]:
    if len(text) <= _PII_MAX_DOCUMENT_CHARS:
        return [text]
    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= _PII_MAX_DOCUMENT_CHARS:
            chunks.append(remaining)
            break
        split_at = remaining.rfind("\n", 0, _PII_MAX_DOCUMENT_CHARS)
        if split_at < _PII_MAX_DOCUMENT_CHARS // 2:
            split_at = _PII_MAX_DOCUMENT_CHARS
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:]
    return chunks


def _azure_redact_pii(text: str, creds: tuple[str, str]) -> PiiResult:
    """Genuine Azure AI Language ``recognize_pii_entities`` redaction."""
    from azure.ai.textanalytics import TextAnalyticsClient
    from azure.core.credentials import AzureKeyCredential
    from azure.identity import DefaultAzureCredential

    endpoint, key = creds
    credential = AzureKeyCredential(key) if key else DefaultAzureCredential()
    client = TextAnalyticsClient(endpoint=endpoint, credential=credential)
    redacted_chunks: list[str] = []
    found: list[dict[str, str]] = []
    for chunk in _pii_chunks(text):
        result = client.recognize_pii_entities([chunk])[0]
        if result.is_error:  # pragma: no cover - service-side error
            raise RuntimeError(getattr(result, "error", "PII recognition failed"))
        found.extend({"category": entity.category, "text": entity.text} for entity in result.entities)
        redacted_chunks.append(result.redacted_text)
    return PiiResult(text="".join(redacted_chunks), entities=found)


# ---------------------------------------------------------------------------
def check_content_safety(text: str) -> None:
    """Raise ``SafetyViolation`` if ``text`` hits a harmful/off-topic category.

    Uses Azure AI Content Safety. The off-topic blocklist is represented by the
    service response (for example a custom category / blocklist match), not by a
    local keyword detector.
    """
    if not get_settings().enable_content_safety:
        return  # LAB-VULN(V1/V2): no content filtering
    creds = _content_safety_creds()
    if creds is None:
        raise SecurityConfigurationError(
            "Content Safety is enabled but CONTENT_SAFETY_ENDPOINT is not configured."
        )
    try:
        _azure_check_content_safety(text, creds)
    except SafetyViolation:
        raise
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise SecurityConfigurationError(f"Content Safety check failed closed: {exc}") from exc


def shield_prompt(text: str, source: str = "user") -> None:
    """Detect jailbreak (user) / indirect injection (document) payloads.

    Defense-in-depth layer that complements the server-side Prompt Shields RAI
    policy on the model deployment: this is the only place each retrieved RAG
    chunk / tool output is shielded *before* the prompt is assembled. Uses Azure
    Content Safety ``text:shieldPrompt`` is required when this guard is enabled.
    """
    if not get_settings().enable_prompt_shields:
        return  # LAB-VULN(V2): prompt shields disabled
    if _content_safety_creds() is None:
        raise SecurityConfigurationError(
            "Prompt Shields are enabled but CONTENT_SAFETY_ENDPOINT is not configured."
        )
    try:
        _azure_shield_prompt(text, source)
        return
    except SafetyViolation:
        raise
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise SecurityConfigurationError(f"Prompt Shields check failed closed: {exc}") from exc


def guard_agent_message(text: str, from_agent: str, to_agent: str) -> None:
    """Re-scan a *cross-agent control message* before one agent acts on another
    agent's request (V11 — Agent Communication Poisoning, OWASP Agentic T12).

    Prompt Shields (V6) catches obvious jailbreak phrasing in user/document
    content, but a poisoned upstream agent can emit a perfectly plausible-looking
    *instruction* ("transfer $9999 …") that no jailbreak pattern matches. The
    fix is to treat every inter-agent message as untrusted and block embedded
    state-changing directives crossing the boundary.

    No-op when the toggle is off, so the vulnerable baseline lets a forged
    handoff flow straight into the receiving agent.
    """
    if not get_settings().enable_a2a_guard:
        return  # LAB-VULN(V11): inter-agent messages trusted blindly
    low = text.lower()
    for pat in _A2A_ACTION_PATTERNS:
        if re.search(pat, low):
            raise SafetyViolation(
                f"Forged action in inter-agent message ({from_agent} -> {to_agent}).",
                "a2a_poisoning",
            )


def redact_pii(text: str) -> PiiResult:
    """Redact PII from ``text``. No-op (passthrough) when the toggle is off.

    Uses Azure AI Language PII recognition. Missing configuration or service
    errors fail closed instead of using local regexes as a security control.
    """
    if not get_settings().enable_pii_redaction:
        return PiiResult(text=text)  # LAB-VULN(V3): PII flows unredacted
    creds = _language_creds()
    if creds is None:
        raise SecurityConfigurationError(
            "PII redaction is enabled but LANGUAGE_ENDPOINT is not configured."
        )
    try:
        return _azure_redact_pii(text, creds)
    except Exception as exc:  # noqa: BLE001 - SDK/transport errors fail closed
        raise SecurityConfigurationError(f"Azure Language PII check failed closed: {exc}") from exc


def scan_tool_output(result: dict[str, object], source: str = "tool") -> PiiResult:
    """Re-scan untrusted tool / MCP output before the model trusts it (V9).

    MCP/tool responses are *data from outside the trust boundary*: a poisoned
    result can carry an indirect prompt-injection payload (T12 / LLM01) or leak
    PII. When the result is flagged ``untrusted`` (secure MCP transport) this
    runs the same Prompt Shields + PII guards used on retrieved documents and
    returns the redacted text. When the output is not flagged untrusted
    (vulnerable transport), behaviour is governed by the individual guards,
    which are themselves no-ops in the vulnerable baseline.
    """
    text = str(result.get("data", result))
    if result.get("untrusted"):
        shield_prompt(text, source=source)  # may raise SafetyViolation
    return redact_pii(text)


def check_groundedness(answer: str, sources: list[str]) -> bool:
    """Crude groundedness signal: is the answer supported by the sources?

    Returns True when grounded (or when the check is disabled). Uses Azure AI
    Content Safety Groundedness detection is required when this guard is enabled.
    """
    if not get_settings().enable_groundedness:
        return True  # LAB-VULN(V6): no groundedness verification
    if not answer.strip():
        return True
    creds = _content_safety_creds()
    if creds is None:
        raise SecurityConfigurationError(
            "Groundedness is enabled but CONTENT_SAFETY_ENDPOINT is not configured."
        )
    if not sources:
        raise SecurityConfigurationError("Groundedness is enabled but no grounding sources were supplied.")
    try:
        return _azure_check_groundedness(answer, sources, creds)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise SecurityConfigurationError(f"Groundedness check failed closed: {exc}") from exc


def _azure_check_groundedness(answer: str, sources: list[str], creds: tuple[str, str]) -> bool:
    """Genuine Azure AI Content Safety ``text:detectGroundedness``."""
    endpoint, key = creds
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:detectGroundedness"
        f"?api-version={_CS_GROUNDEDNESS_API_VERSION}",
        headers=_ai_service_headers(key),
        json={"domain": "Generic", "task": "Summarization", "text": answer,
              "groundingSources": sources},
        timeout=15.0,
    )
    resp.raise_for_status()
    return not bool(resp.json().get("ungroundedDetected"))
