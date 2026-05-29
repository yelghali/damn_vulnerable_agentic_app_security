"""Load the active system prompt.

The hardened system prompt (scope limits + no-leak + HITL) is the Module 1/3
remediation for V1 (weak prompt) and V3 (system-prompt leakage). It activates
once Content Safety is enabled (the point at which participants harden the
prompt) or whenever SECURE_MODE is on.
"""

from __future__ import annotations

from pathlib import Path

from src.config import get_settings

_PROMPTS = Path(__file__).resolve().parent


def load_system_prompt(name: str = "orchestrator") -> str:
    settings = get_settings()
    variant = "secure" if (settings.secure_mode or settings.enable_content_safety) else "vulnerable"
    path = _PROMPTS / variant / f"{name}.md"
    return path.read_text(encoding="utf-8")
