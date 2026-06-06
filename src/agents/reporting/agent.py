"""Reporting agent — builds a report by running model-generated code (V8).

In a real deployment the code runs in the Foundry-hosted sandboxed Code
Interpreter. Offline, ``generate_report`` enforces the sandbox via AST
validation + restricted builtins when ``enable_code_sandbox`` is on.
"""

from __future__ import annotations

import re

from src.agents.tools.db import get_accounts
from src.agents.tools.report import CodeExecutionError, generate_report
from src.agents.types import AgentContext, TurnResult

# A canned "model-generated" report script (offline). It only uses the data
# passed in and assigns the summary to `result`.
_REPORT_CODE = """
total = sum(a['balance'] for a in data.get('accounts', []))
result = {
    'num_accounts': len(data.get('accounts', [])),
    'total_balance': round(total, 2),
}
"""


def _extract_code(message: str) -> str | None:
    """Pull a code snippet the user asked the agent to run.

    LAB-VULN(V8): we trust the user/model to dictate the code that runs in the
    interpreter. A request like "generate a report that runs: <code>" injects
    arbitrary Python. With ``enable_code_sandbox`` off this reaches a bare
    ``exec``; with it on, the sandbox's AST gate rejects imports / I/O.
    """
    m = re.search(r"\b(?:runs?|execute[s]?|code)\b[:\-]?\s*(.+)", message, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    snippet = m.group(1).strip().strip("`").strip()
    # Drop a trailing sentence period so "...os.system('whoami')." stays valid.
    snippet = snippet.rstrip(".").strip()
    return snippet or None


def run(message: str, ctx: AgentContext) -> TurnResult:
    events: list[str] = []
    accounts = get_accounts(ctx.customer_id or "", caller_id=ctx.customer_id, caller_groups=ctx.groups)

    injected = _extract_code(message)
    try:
        if injected:
            # V8: run the user/model-dictated code. Whatever it assigns to
            # `result` is surfaced back to the caller — so an exfiltration like
            # `result = open('.env').read()` is *visibly* returned in the
            # vulnerable baseline, and rejected by the sandbox when it's on.
            out = generate_report(injected, data={"accounts": accounts})
            events.append("reporting: executed user-supplied code in code interpreter")
            if out["result"] is not None:
                return TurnResult(
                    answer=f"Report output:\n{out['result']}",
                    agent="reporting",
                    events=events,
                )
            events.append("reporting: user code returned no result; using canned summary")
        out = generate_report(_REPORT_CODE, data={"accounts": accounts})
        if not injected:
            events.append("reporting: generate_report executed in code interpreter")
        r = out["result"] or {}
        body = (
            f"Report: {r.get('num_accounts', 0)} account(s), "
            f"total balance {r.get('total_balance', 0)}."
        )
    except CodeExecutionError as e:
        return TurnResult(answer=str(e), agent="reporting", events=events, blocked=True)
    except Exception as e:  # noqa: BLE001 - user-supplied code can raise anything (V8)
        events.append(f"reporting: code raised {type(e).__name__}")
        return TurnResult(
            answer=f"The report code failed to run: {e}",
            agent="reporting",
            events=events,
        )
    return TurnResult(answer=body, agent="reporting", events=events)
