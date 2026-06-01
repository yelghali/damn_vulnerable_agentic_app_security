"""Agent governance posture check (Module 11).

A dependency-free, **offline** approximation of what Microsoft's
agent-governance-toolkit (AGT, `agt verify --strict`) does for you in
production: build an inventory of the app's agents and tools, evaluate each
governance control against the live ``ENABLE_*`` configuration, map every gap
to an OWASP Agentic threat (`Tn`), print a posture scorecard, and exit non-zero
when the posture is weak — so it can run as a CI gate.

Run it:

    # vulnerable baseline -> FAILs the gate (that's the point)
    python -m src.scripts.governance_check

    # answer key -> every control passes
    SECURE_MODE=true python -m src.scripts.governance_check

This is the local fallback. With the real toolkit installed
(``pip install agent-governance-toolkit``) the canonical command is:

    agt verify --policy src/agents/governance/policy.yaml --strict

which evaluates the same intent encoded in ``src/agents/governance/policy.yaml``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from src.config import get_settings


@dataclass(frozen=True)
class Control:
    """One governance control the posture check evaluates."""

    name: str
    toggle: str          # the Settings attribute that enables it
    threat: str          # OWASP Agentic threat code(s) it mitigates
    vuln: str            # the lab Vn it closes
    critical: bool       # critical controls must pass for a non-zero gate
    rationale: str


# The lab's agent + tool inventory (what AGT would discover by introspecting the
# Agent Framework graph). Kept explicit here so the check runs with no Azure.
INVENTORY = {
    "orchestrator": ["route", "input-guards", "output-guards"],
    "accounts": ["get_accounts", "get_transactions", "get_credit_score", "get_customer_profile"],
    "transactions": ["transfer_funds", "send_statement_email"],
    "knowledge": ["search_documents"],
    "reporting": ["generate_report (code interpreter)"],
}

# The controls the policy expects to be in force, highest-risk first.
CONTROLS = [
    Control("Human-in-the-loop on money movement", "enable_hitl",
            "T10", "V4", True,
            "transfer_funds / send_statement_email must pause for human approval."),
    Control("Tool least-privilege (object authZ + parameterized SQL)", "enable_tool_least_priv",
            "T2/T3", "V4", True,
            "Read tools enforce caller-owns-data; no string-interpolated SQL (IDOR/SQLi)."),
    Control("Sandboxed code execution", "enable_code_sandbox",
            "T11", "V8", True,
            "Model-generated report code blocks imports / file & network IO (RCE)."),
    Control("MCP tool allow-list + output re-scan", "enable_mcp_tool_security",
            "T2/T12", "V9", True,
            "MCP calls hit a pinned server, allow-listed tools only, output re-scanned."),
    Control("PII detection & redaction", "enable_pii_redaction",
            "T15", "V3", True,
            "SSN / account numbers redacted before logs, model and client."),
    Control("Identity propagation (Entra OBO)", "enable_obo",
            "T9", "V5", True,
            "Caller identity is verified server-side, not trusted from the client."),
    Control("Content Safety guardrails", "enable_content_safety",
            "T6", "V1/V2", False,
            "Harmful / off-topic input and output are filtered."),
    Control("Prompt Shields (direct + indirect injection)", "enable_prompt_shields",
            "T6/T12", "V2/V6", False,
            "Jailbreaks and poisoned-document instructions are detected."),
    Control("Groundedness verification", "enable_groundedness",
            "T1", "V6", False,
            "Answers must be supported by trusted sources."),
    Control("Document-level security trimming", "enable_doc_security",
            "T3", "V5", False,
            "AI Search results are trimmed to the caller's entitlements."),
    Control("Secure runtime (private endpoints, monitoring)", "enable_secure_runtime",
            "T8", "V7", False,
            "No public model/tool surface; requests are audited."),
    Control("AI gateway (token limits, key custody)", "enable_ai_gateway",
            "T4", "V10", False,
            "Model keys live in APIM; spend is bounded; calls are logged."),
]


def evaluate() -> list[tuple[Control, bool]]:
    settings = get_settings()
    return [(c, bool(getattr(settings, c.toggle))) for c in CONTROLS]


def render(results: list[tuple[Control, bool]]) -> int:
    """Print the scorecard. Return a process exit code (0 = posture acceptable)."""
    print("\nZava Wealth Advisor — agent governance posture")
    print("=" * 66)
    print("Inventory: orchestrator + "
          f"{len(INVENTORY) - 1} specialist agents, "
          f"{sum(len(v) for k, v in INVENTORY.items() if k != 'orchestrator')} tools\n")

    width = max(len(c.name) for c, _ in results)
    print(f"{'CONTROL':<{width}}  {'STATUS':<8} {'THREAT':<8} VULN")
    print("-" * (width + 26))
    failed_critical = 0
    passed = 0
    for control, ok in results:
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        elif control.critical:
            failed_critical += 1
        flag = "" if ok or not control.critical else "  <- critical"
        print(f"{control.name:<{width}}  {status:<8} {control.threat:<8} {control.vuln}{flag}")

    total = len(results)
    print("-" * (width + 26))
    print(f"\nPosture: {passed}/{total} controls enabled · "
          f"{failed_critical} critical gap(s).")

    if failed_critical:
        print("\nRESULT: FAIL — critical governance controls are off. "
              "Flip the matching ENABLE_* toggle (or SECURE_MODE=true) and re-run.")
        print("Equivalent toolkit gate: agt verify "
              "--policy src/agents/governance/policy.yaml --strict")
        return 1
    if passed < total:
        print("\nRESULT: PASS (with warnings) — all critical controls on; "
              "some defense-in-depth layers are still off.")
        return 0
    print("\nRESULT: PASS — full governance posture. This is the secure answer key.")
    return 0


def main() -> int:
    return render(evaluate())


if __name__ == "__main__":
    sys.exit(main())
