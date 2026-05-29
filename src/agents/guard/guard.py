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
baseline behaves unsafely on purpose. Offline implementations use heuristics so
the controls are demonstrable + testable without Azure; the Azure-backed
implementations call the corresponding services (see docs/workshop.md).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.config import get_settings

# --- Content Safety category keyword seeds (offline heuristic) --------------
_CATEGORY_TERMS = {
    "sexual": ["explicit sexual", "sexual act", "nude", "porn"],
    "hate": ["racial slur", "ethnic cleansing", "subhuman", "hate group"],
    "violence": ["build a bomb", "make a weapon", "kill", "shoot up"],
    "self_harm": ["kill myself", "how to suicide", "end my life", "self-harm"],
}
# Off-topic / out-of-scope topics a finance assistant must decline (RAI).
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


# ---------------------------------------------------------------------------
def check_content_safety(text: str) -> None:
    """Raise ``SafetyViolation`` if ``text`` hits a harmful/off-topic category."""
    if not get_settings().enable_content_safety:
        return  # LAB-VULN(V1/V2): no content filtering
    low = text.lower()
    for category, terms in _CATEGORY_TERMS.items():
        if any(t in low for t in terms):
            raise SafetyViolation(f"Blocked harmful content ({category}).", category)
    for term in _OFF_TOPIC_TERMS:
        if term in low:
            raise SafetyViolation("Request is outside Zava's financial scope.", "off_topic")


def shield_prompt(text: str, source: str = "user") -> None:
    """Detect jailbreak (user) / indirect injection (document) payloads."""
    if not get_settings().enable_prompt_shields:
        return  # LAB-VULN(V2): prompt shields disabled
    low = text.lower()
    for pat in _INJECTION_PATTERNS:
        if re.search(pat, low):
            raise SafetyViolation(
                f"Prompt-injection attempt detected in {source} content.",
                "jailbreak" if source == "user" else "indirect_injection",
            )


def redact_pii(text: str) -> PiiResult:
    """Redact PII from ``text``. No-op (passthrough) when the toggle is off."""
    if not get_settings().enable_pii_redaction:
        return PiiResult(text=text)  # LAB-VULN(V3): PII flows unredacted
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

    Returns True when grounded (or when the check is disabled). Azure AI Content
    Safety Groundedness detection replaces this heuristic in the deployed lab.
    """
    if not get_settings().enable_groundedness:
        return True  # LAB-VULN(V6): no groundedness verification
    if not answer.strip():
        return True
    corpus = " ".join(sources).lower()
    sentences = [s for s in re.split(r"[.!?]\s+", answer) if len(s.split()) > 4]
    if not sentences:
        return True
    supported = sum(
        1 for s in sentences
        if any(tok in corpus for tok in s.lower().split() if len(tok) > 5)
    )
    return supported / len(sentences) >= 0.5
