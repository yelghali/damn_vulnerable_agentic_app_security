"""Automated AI red-team scan (Module 10).

In Azure this is the **Azure AI Red Teaming Agent** (PyRIT-backed, via
``azure-ai-evaluation``), which probes the deployed app at scale across risk
categories and attack strategies and emits a coverage scorecard.

Offline we run a representative attack battery against the real orchestrator so
the scan — and its scorecard — work as a dependency-free regression gate.

Run with: ``python -m src.redteam.run``
"""
