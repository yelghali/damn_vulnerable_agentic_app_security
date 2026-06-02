# Damn Vulnerable Agentic App — Zava Wealth Advisor

A hands-on security lab that takes a **deliberately insecure, multi-agent Azure AI
application** and hardens it, module by module, into a secure app aligned with
**Microsoft AI app + data security best practices**.

**Zava Wealth Advisor** is a fictional personal-finance assistant: end users chat
with an AI agent that helps them understand their finances. It intentionally
handles **PII and financial data** (names, SSNs, account numbers, balances, credit
scores) so security genuinely matters. For each topic you first **observe / exploit**
a vulnerability, then **remediate** it with concrete Azure config, code, and prompt
changes — ending every module with a verifiable "before vs. after".

> ⚠️ **This app is intentionally vulnerable.** It exists to teach AI security.
> Never deploy the `vulnerable` baseline to a production or shared environment, and
> only ever point it at throwaway sample data.

## What it covers

| # | Vulnerability (baseline) | Remediation |
|---|--------------------------|-------------|
| V1 | Ungoverned/unsafe model | Governed Foundry deployment + content filters |
| V2 | No guardrails (Prompt Shields off) | Content Safety + Prompt Shields + Groundedness |
| V3 | PII in prompts / logs / responses | PII detection + redaction (Azure AI Language) |
| V4 | Overpermissioned tools, no HITL | Scoped DB role + RLS, human-in-the-loop, allow-listing |
| V5 | Weak OAuth / overpermissive RBAC | Entra OBO + managed identity + Key Vault + least-priv RBAC |
| V6 | Data leakage / poisoning | Trusted ingestion, indirect-injection defense, Purview/DSPM, groundedness |
| V7 | Insecure infrastructure | Private endpoints, Defender for Cloud AI, Monitor, safe errors |
| V8 | Unsafe code execution | Sandboxed Foundry Code Interpreter |
| V9 | Insecure MCP tool integration | Pinned servers, scoped OBO, tool allow-list, guarded output |
| V10 | No AI gateway | Azure API Management (token limits, auth, logging, caching) |

Each vulnerability maps to the **OWASP Top 10 for LLM Apps (2025)**, the **OWASP
Agentic AI threat taxonomy**, and a **Microsoft control baseline** — see
[docs/workshop.md](docs/workshop.md) for the full mapping.

## Architecture

```
User ──> Chat Web UI ──> FastAPI backend
                              │  Microsoft Agent Framework (multi-agent orchestration)
        ┌─ Orchestrator ─┬─ Knowledge(RAG) ─┬─ Accounts ─┬─ Transactions ─┬─ Reporting
        │   guardrails enforced on Foundry (model filters + agent guardrails)
        └─ [later/optional: in-app guard middleware or API-layer guard]
                                       │
                Azure API Management (AI Gateway)
                                       │
   Azure AI Foundry · Azure AI Search · PostgreSQL Flex (local or MCP) · Code Interpreter
        │
   Entra ID (OBO/RBAC) · Key Vault · Purview/DSPM · Defender for Cloud · Monitor
```

- **Orchestration:** Microsoft Agent Framework (`agent-framework`).
- **Models / agents / evals:** Azure AI Foundry project SDK (`azure-ai-projects>=2.0.0`).
- **Data tools:** local Python functions **or** the **Microsoft Azure MCP Server**
  (`postgres` namespace) — hosted on Azure Container Apps and attached to the
  Foundry agents as a remote MCP tool.
- **IaC:** Terraform ([src/infra/](src/infra/)).

## Two variants, one diff

The same app ships in two modes, selected by the `SECURE_MODE` master switch plus
per-vulnerability `ENABLE_*` toggles in [src/config.py](src/config.py):

- **`vulnerable`** — the insecure baseline (default; `SECURE_MODE=false`).
- **`secure`** — the hardened reference / answer key (`SECURE_MODE=true`).

Every intentional weakness is marked with a `# LAB-VULN(Vn): ...` comment, and each
mitigation is gated behind a single, obvious toggle. **The toggle is a teaching aid
for instant before/after offline** — the real deliverable of each module is
understanding the secure implementation it gates and the Azure control that enforces
it in production.

## Quick start (local — no Azure required)

`OFFLINE_MODE=true` runs the whole app locally against a **real small language model**
(via [Microsoft Foundry Local](https://learn.microsoft.com/azure/ai-foundry/foundry-local/))
and a local SQLite database, so you can explore and validate the agent without
provisioning anything. (No model running? It falls back to a deterministic stub.)

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env        # OFFLINE_MODE=true, SECURE_MODE=false by default
winget install Microsoft.FoundryLocal
foundry model run phi-3.5-mini     # real SLM, auto-discovered by the app
python -m src.scripts.seed         # seed the local SQLite DB
uvicorn src.app.main:app --reload  # browse http://localhost:8000
```

```bash
# macOS / Linux
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
brew tap microsoft/foundrylocal && brew install foundrylocal
foundry model run phi-3.5-mini
python -m src.scripts.seed
uvicorn src.app.main:app --reload
```

Flip a single module's mitigation by setting its toggle in `.env`
(e.g. `ENABLE_PII_REDACTION=true`) and restarting, or flip everything at once with
`SECURE_MODE=true`.

### Run the tests

```powershell
python -m pytest src/tests/ -q
```

The suite in [src/tests/test_vulnerabilities.py](src/tests/test_vulnerabilities.py)
asserts each vulnerability is present when its toggle is off and mitigated when on.

## Deploy to Azure

Modules 1+ run against real Azure services. Provision with Terraform:

```powershell
cd src/infra
terraform init
terraform apply
```

This stands up the Foundry project + model deployments, Azure AI Search, PostgreSQL
Flexible Server, Blob Storage, Key Vault, APIM (AI gateway), the **Microsoft Azure
MCP Server** on Azure Container Apps (the agents' PostgreSQL tool), and monitoring.
Copy the emitted outputs into `.env` (including `pg_mcp_server_url` ->
`PG_MCP_SERVER_URL`) and set `OFFLINE_MODE=false`. See
[docs/workshop.md](docs/workshop.md) for region/quota prerequisites and the
tenant-admin prep steps (Entra app registration, Purview) with fallbacks.

### Make the agents appear in the Foundry portal

The app calls Foundry models directly; to also create **persistent agents** that
show up in the portal **Agents** tab — the Knowledge agent wired to Azure AI Search
and the Accounts/Transactions agents wired to the Microsoft Azure MCP Server
(`postgres`) — run:

```powershell
python -m src.scripts.provision_foundry_agents          # create / update
python -m src.scripts.provision_foundry_agents --delete  # remove them
```

The MCP `allowed_tools` allow-list and `require_approval` (HITL) are driven by the
same `ENABLE_MCP_TOOL_SECURITY` (V9) and `ENABLE_HITL` (V4) toggles, so the
vulnerable vs. secure posture of the agents matches the app.

## The workshop

The full guided lab lives in **[docs/workshop.md](docs/workshop.md)** (MOAW format):

The full guided lab lives in **[docs/workshop.md](docs/workshop.md)** (MOAW format), told in **two parts**:

- **Part 1 · Understand the vulnerabilities (run locally):** break the app on your
  laptop and exploit all ten weaknesses (V1–V10) through the chat UI — **no Azure required**.
- **Part 2 · Add the Azure security layers:** harden the same app one Azure control at a
  time — Foundry guardrails, Azure AI Language PII, secure MCP, Entra ID + AI Search
  document security, APIM AI gateway + Defender, and Purview DLP.
  - *Core (Modules 1–6, ~4 h):* runs in your own subscription with **no tenant-admin rights**.
  - *Extended (Modules 7–11 + capstone, +2–3 h):* Purview governance, evaluations, AI red teaming, agent governance.

Part 2 loop: *Recall the exploit → Why it's dangerous → Add the Azure layer (design · secure code · Azure wiring) → Verify → Learn more.*

### Preview the workshop locally

The workshop is authored in [MOAW](https://github.com/microsoft/moaw) format. To render
and live-preview it on your machine, install the MOAW CLI (Node.js required) and serve
the file:

```powershell
# Windows (PowerShell)
$env:Path = "C:\Program Files\nodejs;$env:APPDATA\npm;$env:Path"
npm install -g @moaw/cli
& "$env:APPDATA\npm\moaw.cmd" serve docs/workshop.md
# Preview at http://localhost:4444/workshop/workshop.md (auto-reloads on save)
```

```bash
# macOS / Linux
npm install -g @moaw/cli
moaw serve docs/workshop.md
# Preview at http://localhost:4444/workshop/workshop.md (auto-reloads on save)
```

## Repository layout

```
src/
  app/        FastAPI backend + minimal chat web UI (entry point)
  agents/     Microsoft Agent Framework: orchestrator + specialist agents
    orchestrator/ knowledge/ accounts/ transactions/ reporting/   specialist agents
    guard/        in-app safety middleware (content safety, prompt shields, PII)
    tools/        tool implementations (db, search, email, report, mcp)
    gateway/      AI gateway client shim (APIM routing, V10)
    prompts/      vulnerable/ + secure/ system prompts
  config.py   SECURE_MODE + per-vulnerability feature toggles
  evals/      azure-ai-evaluation suites (Module 9)
  redteam/    AI Red Teaming Agent scans (Module 10)
  data/       seed SQL + sample financial docs (incl. one poisoned doc)
  infra/      Terraform (Foundry, Search, PostgreSQL, Blob, Entra, Key Vault, APIM, monitoring)
  scripts/    seed / deploy helpers
docs/
  workshop.md MOAW lab tutorial
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
