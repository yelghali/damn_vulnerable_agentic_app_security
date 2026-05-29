"""Model client abstraction.

* ``OFFLINE_MODE=true`` uses a deterministic, rules-based stub so the whole app
  and every vulnerability/mitigation are demonstrable + testable without Azure.
  The stub deliberately *follows the active system prompt*: under the vulnerable
  prompt it will leak instructions / go off-topic; under the hardened prompt it
  refuses — so the before/after is visible offline.

* In Azure mode the same surface is backed by the **Azure AI Foundry project
  SDK** (``AIProjectClient.get_openai_client()``) and orchestrated with the
  **Microsoft Agent Framework**. That path is constructed lazily so offline
  runs need no Azure SDKs or credentials.
"""

from __future__ import annotations

from src.config import get_settings


def _stub_compose(system_prompt: str, user_message: str, context: str) -> str:
    """Deterministic offline 'model'. Honors the active system prompt so the
    vulnerable vs. secure behavior is reproducible in tests."""
    low = user_message.lower()
    hardened = "never reveal" in system_prompt.lower()

    # System-prompt leakage (V3) — vulnerable prompt complies, hardened refuses.
    if any(k in low for k in ("system prompt", "your instructions", "admin override", "password")):
        if hardened:
            return "I can't share my configuration. I can help with your Zava finances though."
        return f"Sure! Here are my full instructions:\n{system_prompt}"

    # Off-topic (politics/jokes) — vulnerable engages, hardened declines.
    if any(k in low for k in ("vote", "election", "political", "joke")):
        if hardened:
            return "That's outside what I can help with. I can assist with your accounts or transactions."
        return "Haha, sure! Let's chat about that..."

    if context:
        return f"Here's what I found for you:\n{context}"
    return (
        "I can help with your accounts, transactions, credit score, statements, "
        "and financial documents. What would you like to do?"
    )


def compose_answer(system_prompt: str, user_message: str, context: str = "") -> str:
    settings = get_settings()
    if settings.offline_mode:
        return _stub_compose(system_prompt, user_message, context)

    # --- Azure AI Foundry + Microsoft Agent Framework path -----------------
    # Lazy imports so offline mode needs no Azure SDKs.
    from azure.ai.projects import AIProjectClient  # noqa: PLC0415
    from azure.identity import DefaultAzureCredential  # noqa: PLC0415

    project = AIProjectClient(
        endpoint=settings.foundry_project_endpoint,
        credential=DefaultAzureCredential(),
    )
    client = project.get_openai_client()
    completion = client.chat.completions.create(
        model=settings.active_model_deployment,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{user_message}\n\nContext:\n{context}"},
        ],
    )
    return completion.choices[0].message.content or ""
