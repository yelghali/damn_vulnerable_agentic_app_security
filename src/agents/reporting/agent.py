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
    accounts = get_accounts(ctx.customer_id or "", caller_id=ctx.customer_id)

    # If the user dictated code, run *that* (V8). Otherwise the canned summary.
    injected = _extract_code(message)
    code = f"{injected}\n{_REPORT_CODE}" if injected else _REPORT_CODE
    try:
        out = generate_report(code, data={"accounts": accounts})
        if injected:
            events.append("reporting: executed user-supplied code in code interpreter")
        else:
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
