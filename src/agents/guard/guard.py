"""Safety guard used as Agent Framework middleware.

Centralizes the input/output protections that the lab toggles on:

* **Content Safety** (V1/V2) — harmful categories (sexual, hate, violence,
  self-harm) + off-topic/política blocklist, mirroring Azure AI Content Safety.
* **Prompt Shields** (V2) — detect direct jailbreaks in user input *and*
  indirect prompt-injection payloads embedded in retrieved documents.
* **PII redaction** (V3) — detect + redact PII before it reaches the model,
  the logs, or the response, mirroring Azure AI Language PII.
* **Groundedness** (V6) — flag answers not supported by retrieved sources.

When the matching toggle is **off**, each guard is a no-op so the vulnerable
baseline behaves unsafely on purpose.

Each guard has **two real implementations** and dispatches between them at call
time:

* **Azure-backed** — used when the corresponding Azure endpoint/key is
  configured (``CONTENT_SAFETY_ENDPOINT``, ``LANGUAGE_ENDPOINT``). These call
  the genuine services: Azure AI Content Safety ``analyze_text`` + Prompt
  Shields (``text:shieldPrompt``) + Groundedness detection, and Azure AI
  Language ``recognize_pii_entities``.
* **Offline heuristic** — used in the dependency-free local lab (Part 1) and in
  CI, so the before/after behaviour is demonstrable without any Azure resources.

The Azure path also falls back to the heuristic on any transport error, so the
app never hard-fails because a service is briefly unreachable.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

from src.config import get_settings

logger = logging.getLogger("zava.guard")

# Content Safety severity (0-7) at/above which a category counts as a block.
# The default lives in config (CONTENT_SAFETY_SEVERITY_THRESHOLD) so a learner
# can tune strictness without editing code, exactly like the Azure portal.
_CS_API_VERSION = "2024-09-01"
_CS_GROUNDEDNESS_API_VERSION = "2024-09-15-preview"

# --- Content Safety category seeds with an illustrative severity (offline) ---
# Each seed term carries a 0-7 severity, mirroring Azure's FourSeverityLevels
# scoring, so the severity threshold is meaningful offline: raise the threshold
# and milder terms (e.g. "nude" at 2) stop being blocked while "build a bomb"
# (6) still is.
_CATEGORY_TERMS: dict[str, dict[str, int]] = {
    "sexual": {"explicit sexual": 6, "sexual act": 4, "nude": 2, "porn": 6},
    "hate": {"racial slur": 6, "ethnic cleansing": 7, "subhuman": 4, "hate group": 4},
    "violence": {"build a bomb": 6, "make a weapon": 4, "kill": 4, "shoot up": 6},
    "self_harm": {"kill myself": 6, "how to suicide": 6, "end my life": 4, "self-harm": 4},
}
# Off-topic / out-of-scope topics a finance assistant must decline (RAI).
# This is a *custom blocklist* (an org business rule, not a model harm category),
# so it has its own on/off knob (CONTENT_SAFETY_BLOCK_OFF_TOPIC).
_OFF_TOPIC_TERMS = ["who should i vote", "political party", "election", "tell me a joke about"]

# --- Prompt Shields jailbreak / injection patterns -------------------------
_INJECTION_PATTERNS = [
    r"ignore (all|any|the) (previous|prior|above) (instructions|prompts)",
    r"disregard (your|the) (system|previous) (prompt|instructions)",
    r"you are now (?:in )?(?:dan|developer mode|jailbroken)",
    r"reveal (your|the) system prompt",
    r"print (your|the) (instructions|system prompt)",
    r"act as if you have no restrictions",
]

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

# --- PII regexes (offline approximation of Azure AI Language PII) -----------
_PII_PATTERNS = {
    "USSocialSecurityNumber": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CreditCardNumber": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "Email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "PhoneNumber": re.compile(r"\b(?:\+?1[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b"),
    "AccountNumber": re.compile(r"\bACC-\d{6,}\b"),
}


class SafetyViolation(RuntimeError):
    """Raised when a guard blocks content."""

    def __init__(self, reason: str, category: str) -> None:
        super().__init__(reason)
        self.category = category


@dataclass
class PiiResult:
    text: str
    entities: list[dict[str, str]] = field(default_factory=list)


# --- Azure service dispatch helpers ----------------------------------------
# Each guard prefers the genuine Azure service when its endpoint + key are
# configured, and transparently falls back to the offline heuristic on any
# transport/SDK error so the app never hard-fails on a brief outage. httpx is
# used directly for the Content Safety REST surface (analyze / shieldPrompt /
# detectGroundedness); Azure AI Language PII uses its SDK (lazy-imported so the
# offline lab never needs it installed).
def _content_safety_creds() -> tuple[str, str] | None:
    s = get_settings()
    if s.content_safety_endpoint and s.content_safety_key:
        return s.content_safety_endpoint.rstrip("/"), s.content_safety_key
    return None


def _language_creds() -> tuple[str, str] | None:
    s = get_settings()
    if s.language_endpoint and s.language_key:
        return s.language_endpoint.rstrip("/"), s.language_key
    return None


def _azure_check_content_safety(text: str, creds: tuple[str, str]) -> None:
    """Genuine Azure AI Content Safety ``text:analyze`` — raises on a harm hit."""
    endpoint, key = creds
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:analyze?api-version={_CS_API_VERSION}",
        headers={"Ocp-Apim-Subscription-Key": key, "content-type": "application/json"},
        json={"text": text, "outputType": "FourSeverityLevels"},
        timeout=10.0,
    )
    resp.raise_for_status()
    threshold = get_settings().content_safety_severity_threshold
    for item in resp.json().get("categoriesAnalysis", []):
        if int(item.get("severity", 0)) >= threshold:
            category = str(item.get("category", "harmful")).lower()
            raise SafetyViolation(f"Blocked harmful content ({category}).", category)


def _azure_shield_prompt(text: str, source: str) -> None:
    """Genuine Azure AI Content Safety ``text:shieldPrompt`` — raises on attack."""
    creds = _content_safety_creds()
    if creds is None:
        raise _NoAzure
    endpoint, key = creds
    body = {"userPrompt": text} if source == "user" else {"documents": [text]}
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:shieldPrompt?api-version={_CS_API_VERSION}",
        headers={"Ocp-Apim-Subscription-Key": key, "content-type": "application/json"},
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


def _azure_redact_pii(text: str, creds: tuple[str, str]) -> PiiResult:
    """Genuine Azure AI Language ``recognize_pii_entities`` redaction."""
    from azure.ai.textanalytics import TextAnalyticsClient
    from azure.core.credentials import AzureKeyCredential

    endpoint, key = creds
    client = TextAnalyticsClient(endpoint=endpoint, credential=AzureKeyCredential(key))
    result = client.recognize_pii_entities([text])[0]
    if result.is_error:  # pragma: no cover - service-side error
        raise RuntimeError(getattr(result, "error", "PII recognition failed"))
    found = [{"category": e.category, "text": e.text} for e in result.entities]
    return PiiResult(text=result.redacted_text, entities=found)


class _NoAzureError(RuntimeError):
    """Sentinel: no Azure endpoint configured -> use the offline heuristic."""


_NoAzure = _NoAzureError()


# ---------------------------------------------------------------------------
def check_content_safety(text: str) -> None:
    """Raise ``SafetyViolation`` if ``text`` hits a harmful/off-topic category.

    Uses Azure AI Content Safety when ``CONTENT_SAFETY_ENDPOINT`` is configured,
    otherwise the offline keyword heuristic. The off-topic blocklist (a *custom*
    business rule, not a model harm category) is always applied on top.
    """
    if not get_settings().enable_content_safety:
        return  # LAB-VULN(V1/V2): no content filtering
    creds = _content_safety_creds()
    if creds is not None:
        try:
            _azure_check_content_safety(text, creds)
        except SafetyViolation:
            raise
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            logger.warning("Content Safety call failed, using heuristic: %s", exc)
            _heuristic_content_safety(text)
    else:
        _heuristic_content_safety(text)
    # Custom off-topic blocklist (org rule) — independently toggleable so a
    # learner can see the difference between a model harm category and a
    # business "no politics / no jokes" rule.
    if get_settings().content_safety_block_off_topic:
        low = text.lower()
        for term in _OFF_TOPIC_TERMS:
            if term in low:
                raise SafetyViolation("Request is outside Zava's financial scope.", "off_topic")


def _heuristic_content_safety(text: str) -> None:
    low = text.lower()
    threshold = get_settings().content_safety_severity_threshold
    for category, terms in _CATEGORY_TERMS.items():
        if any(sev >= threshold and term in low for term, sev in terms.items()):
            raise SafetyViolation(f"Blocked harmful content ({category}).", category)


def shield_prompt(text: str, source: str = "user") -> None:
    """Detect jailbreak (user) / indirect injection (document) payloads.

    Defense-in-depth layer that complements the server-side Prompt Shields RAI
    policy on the model deployment: this is the only place each retrieved RAG
    chunk / tool output is shielded *before* the prompt is assembled. Uses Azure
    Content Safety ``text:shieldPrompt`` when configured, else the regex heuristic.
    """
    if not get_settings().enable_prompt_shields:
        return  # LAB-VULN(V2): prompt shields disabled
    try:
        _azure_shield_prompt(text, source)
        return
    except SafetyViolation:
        raise
    except _NoAzureError:
        pass
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning("Prompt Shields call failed, using heuristic: %s", exc)
    low = text.lower()
    for pat in _INJECTION_PATTERNS:
        if re.search(pat, low):
            raise SafetyViolation(
                f"Prompt-injection attempt detected in {source} content.",
                "jailbreak" if source == "user" else "indirect_injection",
            )


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

    Uses Azure AI Language PII recognition when ``LANGUAGE_ENDPOINT`` is
    configured, otherwise the offline regex set.
    """
    if not get_settings().enable_pii_redaction:
        return PiiResult(text=text)  # LAB-VULN(V3): PII flows unredacted
    creds = _language_creds()
    if creds is not None:
        try:
            return _azure_redact_pii(text, creds)
        except Exception as exc:  # noqa: BLE001 - any SDK/transport error -> heuristic
            logger.warning("Azure Language PII call failed, using heuristic: %s", exc)
    redacted = text
    found: list[dict[str, str]] = []
    for label, pattern in _PII_PATTERNS.items():
        for match in pattern.finditer(text):
            found.append({"category": label, "text": match.group()})
        redacted = pattern.sub(f"[{label}]", redacted)
    return PiiResult(text=redacted, entities=found)


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
    Content Safety Groundedness detection when configured, else a token-overlap
    heuristic.
    """
    if not get_settings().enable_groundedness:
        return True  # LAB-VULN(V6): no groundedness verification
    if not answer.strip():
        return True
    creds = _content_safety_creds()
    if creds is not None and sources:
        try:
            return _azure_check_groundedness(answer, sources, creds)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            logger.warning("Groundedness call failed, using heuristic: %s", exc)
    corpus = " ".join(sources).lower()
    sentences = [s for s in re.split(r"[.!?]\s+", answer) if len(s.split()) > 4]
    if not sentences:
        return True
    supported = sum(
        1 for s in sentences
        if any(tok in corpus for tok in s.lower().split() if len(tok) > 5)
    )
    return supported / len(sentences) >= 0.5


def _azure_check_groundedness(answer: str, sources: list[str], creds: tuple[str, str]) -> bool:
    """Genuine Azure AI Content Safety ``text:detectGroundedness``."""
    endpoint, key = creds
    resp = httpx.post(
        f"{endpoint}/contentsafety/text:detectGroundedness"
        f"?api-version={_CS_GROUNDEDNESS_API_VERSION}",
        headers={"Ocp-Apim-Subscription-Key": key, "content-type": "application/json"},
        json={"domain": "Generic", "task": "Summarization", "text": answer,
              "groundingSources": sources},
        timeout=15.0,
    )
    resp.raise_for_status()
    return not bool(resp.json().get("ungroundedDetected"))
