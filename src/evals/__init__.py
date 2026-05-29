"""Safety + quality evaluations (Module 9).

In Azure this is backed by ``azure-ai-evaluation`` + Foundry cloud evaluations
(groundedness, relevance, content-harm, indirect-attack evaluators). Offline we
run a small, deterministic harness over the real orchestrator so the *gate* —
"do the safety controls hold?" — is demonstrable and CI-friendly without Azure.

Run with: ``python -m src.evals.run``
"""
