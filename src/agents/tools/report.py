"""Report generation via a code interpreter (Reporting agent).

The agent writes Python to summarize a customer's finances into a small report.

* **Vulnerable baseline** (``enable_code_sandbox=False``)
    - executes model-generated code with a bare ``exec`` and full builtins:
      file system, ``os``/``subprocess``, network are all reachable
      (LAB-VULN V8 — remote code execution / improper output handling).
* **Secure path** (``enable_code_sandbox=True``)
    - in Azure: hand the code to the **Foundry-hosted sandboxed Code
      Interpreter** tool (no outbound network, ephemeral FS, CPU/time limits).
    - offline: a restricted executor that AST-validates the code, blocks
      imports / dunder access / known-dangerous names, and runs with a minimal
      builtin set so the control is demonstrable + testable without Azure.
"""

from __future__ import annotations

import ast
from typing import Any

from src.config import get_settings


class CodeExecutionError(RuntimeError):
    pass


_BLOCKED_NAMES = {
    "__import__", "eval", "exec", "compile", "open", "input",
    "globals", "locals", "vars", "getattr", "setattr", "delattr",
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "importlib",
}

_SAFE_BUILTINS = {
    "abs": abs, "min": min, "max": max, "sum": sum, "len": len,
    "round": round, "sorted": sorted, "range": range, "enumerate": enumerate,
    "list": list, "dict": dict, "set": set, "tuple": tuple, "float": float,
    "int": int, "str": str, "bool": bool, "print": print,
}


def _validate_ast(code: str) -> None:
    """Reject imports, attribute access to dunders, and dangerous names."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise CodeExecutionError("Imports are not permitted in the sandbox.")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise CodeExecutionError("Dunder attribute access is not permitted.")
        if isinstance(node, ast.Name) and node.id in _BLOCKED_NAMES:
            raise CodeExecutionError(f"Use of '{node.id}' is not permitted.")


def generate_report(code: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run model-generated report code over ``data`` and return ``result``.

    The code should assign its output to a variable named ``result``.
    """
    settings = get_settings()
    sandbox_globals: dict[str, Any] = {"data": data or {}, "result": None}

    if settings.enable_code_sandbox:
        # SECURE (offline approximation of the Foundry Code Interpreter).
        _validate_ast(code)
        sandbox_globals["__builtins__"] = _SAFE_BUILTINS
        try:
            exec(code, sandbox_globals)  # noqa: S102 - constrained builtins + AST gate
        except Exception as exc:  # noqa: BLE001
            raise CodeExecutionError(f"Sandboxed execution failed: {exc}") from exc
    else:
        # LAB-VULN(V8): unrestricted execution — full builtins, imports, I/O.
        exec(code, sandbox_globals)  # noqa: S102 - intentionally unsafe baseline

    return {"result": sandbox_globals.get("result")}
