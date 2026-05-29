"""Reporting agent — builds a report by running model-generated code (V8).

In a real deployment the code runs in the Foundry-hosted sandboxed Code
Interpreter. Offline, ``generate_report`` enforces the sandbox via AST
validation + restricted builtins when ``enable_code_sandbox`` is on.
"""

from __future__ import annotations

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


def run(message: str, ctx: AgentContext) -> TurnResult:
    events: list[str] = []
    accounts = get_accounts(ctx.customer_id or "", caller_id=ctx.customer_id)
    try:
        out = generate_report(_REPORT_CODE, data={"accounts": accounts})
        events.append("reporting: generate_report executed in code interpreter")
        r = out["result"] or {}
        body = (
            f"Report: {r.get('num_accounts', 0)} account(s), "
            f"total balance {r.get('total_balance', 0)}."
        )
    except CodeExecutionError as e:
        return TurnResult(answer=str(e), agent="reporting", events=events, blocked=True)
    return TurnResult(answer=body, agent="reporting", events=events)
