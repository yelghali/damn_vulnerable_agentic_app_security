---
name: "Agentic App Security Lab — Spec"
description: "Use when building, editing, or extending this repo's security lab: the Damn Vulnerable Agentic App (Zava Wealth Advisor), its Azure/Terraform infra, the multi-agent app code (Microsoft Agent Framework + Azure AI Foundry project SDK), the MOAW workshop.md tutorial, vulnerable vs. secure variants, or any security module (responsible/safe AI + content safety, prompt shields, PII redaction, Purview/DSPM + DLP, OAuth/OBO + RBAC least privilege, tool scoping + human-in-the-loop, secure code execution / code interpreter, data poisoning + groundedness, AI Search document-level security, secure runtime, evaluations, AI red teaming, agent governance). Authoritative scope, architecture, and conventions for the lab."
applyTo: ["src/**", "docs/**", "infra/**", "README.md"]
---

# Damn Vulnerable Agentic App — Security Lab Spec

> Authoritative design + conventions. Read this before generating any lab code, infra, or workshop content. Keep this file in sync when the lab design changes.

## 1. Goal

A hands-on **MOAW lab** that takes a deliberately insecure ("damn vulnerable") Azure-based **agentic AI app** and hardens it, step by step, into a secure app aligned with **Microsoft AI app + data security best practices**.

For each topic the participant: (1) **observes / exploits** the vulnerability, then (2) **remediates** it with a concrete Azure config, code, and/or prompt change. Every module ends with a verifiable "before vs. after".

- Audience: pro devs / cloud + AI engineers / security engineers. Level: **intermediate → advanced**.
- Everything (app + infra-as-code) is deployable by participants in **their own Azure subscription**.
- **Format:** iterative + self-paced, in two tracks:
  - **Core track (half-day, ~4 h):** Modules 0–6. Runs end-to-end in a guided session; everything is code/Terraform-deployable in the participant's own subscription with no tenant-admin rights.
  - **Extended track (self-paced, +2–3 h → full day):** Modules 7–11 + capstone. Covers tenant-scoped governance (Purview), assurance (evaluations, AI red teaming), and Microsoft's agent governance toolkit. Participants continue on their own.
  Each module is independently runnable and builds on the previous; a participant can stop/resume between modules. Tenant-admin or slow-provisioning steps (Purview, Entra app reg / RBAC, Defender) are called out as **prep** with ready-to-run code or click-through **and a fallback** so they never block the timed flow.

## 2. Functional use case — "Zava Wealth Advisor"

Zava is the fictional company. A personal-finance assistant: end users chat with an AI agent that helps them understand their finances. It deliberately handles **PII + financial data** so security matters.

Capabilities:
- **RAG** over financial documents (account statements, product disclosures, policy PDFs) in an **Azure AI Search** vector index sourced from **Azure Blob Storage**.
- **Tools (function calling)** backed by **Azure Database for PostgreSQL Flexible Server**:
  - `get_accounts(customer_id)` — list accounts/balances
  - `get_transactions(account_id, range)` — transaction history
  - `get_credit_score(customer_id)` — sensitive score
  - `transfer_funds(from, to, amount)` — **high-risk / state-changing**
  - `send_statement_email(customer_id)` — outbound action
  - `generate_report(spec)` — builds charts/summaries by running model-generated code in a **code interpreter** (secure-code-execution scenario)
- Sensitive data in scope: names, national ID / SSN, account numbers, balances, credit scores, addresses.

#### Tool transport: local function tools vs. remote MCP tools

A tool's *implementation* is independent of how the agent *reaches* it. The lab presents both, so participants learn the security trade-offs of each:

- **Local function tools** — Python functions registered directly with the agent (in-process). Fast, fully controlled, but every backing credential lives in the app.
- **Remote MCP server tools** — the same capability exposed by a **Model Context Protocol (MCP) server** that the agent connects to over HTTP. The Postgres data tools (`get_accounts`, `get_transactions`, …) can be served by the **Azure Database for PostgreSQL MCP server** and attached to a Foundry agent as a hosted MCP tool, instead of being implemented locally.

MCP shifts the trust boundary: the agent now executes whatever tools a *remote* server advertises. The lab deliberately makes this surface insecure first (**V9**) — an unpinned/untrusted MCP server, the admin connection string handed straight to it, no MCP-tool allow-list, and MCP responses trusted as clean text — then hardens it (pinned/approved server, scoped read-only identity via OBO, explicit tool allow-list, MCP output treated as untrusted content subject to the guard middleware).

### Multi-agent design (Microsoft Agent Framework + Foundry)

The app is a **multi-agent** system orchestrated with **Microsoft Agent Framework** (`agent-framework`), with agents + models running on **Azure AI Foundry** created via the **Foundry project SDK** (`azure-ai-projects>=2.0.0`, `AIProjectClient` → `get_openai_client()` / Foundry Agent Service):

- **Orchestrator / Planner** — receives the user turn and routes to specialist agents via an Agent Framework workflow.
- **Knowledge (RAG) agent** — retrieves from Azure AI Search; subject to indirect-injection + document-level security.
- **Accounts agent** — read tools (`get_accounts`, `get_transactions`, `get_credit_score`).
- **Transactions agent** — state-changing tools (`transfer_funds`, `send_statement_email`); human-in-the-loop gate.
- **Reporting agent** — `generate_report` via a **sandboxed Code Interpreter** (secure code execution).
- **Foundry guardrails (model + agent)** — the **canonical** safety layer: Azure AI **Content Safety content filters bound to the model deployment** plus **agent-level guardrails** (Prompt Shields, Groundedness, Protected Material) configured on the Foundry agent — *not* a separate guard agent in the workflow.

Per-agent tool allow-listing + the agent-to-agent boundary make **tool misuse (T2)**, **excessive agency (LLM06)**, **agent-communication poisoning (T12)**, and **unsafe code execution (T11)** concretely teachable.

#### Where guardrails live — Foundry-first; in-app guard is a later layer

Safety is **not** modeled as an extra LLM agent in the workflow. An agent is a non-deterministic, latency- and cost-adding model call that is *itself* susceptible to the prompt injection it would be meant to stop — a poor enforcement point. The lab's **default** is to enforce guardrails on **Foundry** at the model **and** agent level:

- **Model deployment.** Azure AI **Content Safety content filters** (harmful categories, **Prompt Shields** for direct + indirect/document injection, **Protected Material**) attached to the deployment, enforced on *every* model call regardless of app code.
- **Foundry agent.** Agent-level guardrails + **Groundedness detection** configured on the Foundry agent, so each specialist agent inherits them.

An **in-app guard layer** (`src/agents/guard/` — deterministic Prompt Shields/PII re-scan on **agent-to-agent messages**, **tool / MCP output** (V9), and **pre-log PII redaction** (V3)) is treated as a **later, optional** hardening step introduced with the **agent governance toolkit** (extended track), or pushed into the **API layer**. It exists in the repo (toggle-gated, used for offline before/after demos) but is **not** the primary control — Foundry is. Rule of thumb: enforce on the **platform** first (unavoidable); add in-app/API guards only for boundaries Foundry can't see, and only once governance is in scope.

## 3. Architecture

```
User ──> Chat Web UI ──> Backend API (FastAPI)
                              │  Microsoft Agent Framework (multi-agent orchestration)
        ┌─ Orchestrator ─┬─ Knowledge(RAG) ─┬─ Accounts ─┬─ Transactions ─┬─ Reporting
        │   guardrails enforced on Foundry (model filters + agent guardrails)        │
        │   [later/optional: in-app guard middleware or API-layer guard]             │
        └───────────────────────────────────────────────────────┘
               │                  │                 │               │
     ┌─────────────────── Azure API Management (AI Gateway) ───────────────────┐
     │  central authN/Z · token-based throttling · key vaulting · logging · cache │
     └──────────┬───────────────────┬───────────────┬───────────────┬──────────┘
               │                  │                 │               │
     Azure AI Foundry      Azure AI Search    PostgreSQL Flex   Code Interpreter
     (project SDK:         (RAG index +       (local tools OR   (sandboxed report
      models, agents,      doc-level ACL) ←   Postgres MCP      generation)
      Content Safety,      Blob (docs)        server)
      evals)
       │
  Microsoft Entra ID (OBO/RBAC) · Key Vault · Purview/DSPM+DLP · Defender for Cloud · Monitor/Log Analytics
```

- **SDKs:** Foundry project SDK (`azure-ai-projects`) creates the project, model deployments, agents, and runs evaluations; **Microsoft Agent Framework** does local multi-agent orchestration, middleware, and human-in-the-loop against those Foundry-hosted models/agents. Data tools may be **local functions** or attached as **MCP server tools** (e.g. the Azure Database for PostgreSQL MCP server).
- **AI Gateway:** **Azure API Management** sits in front of the Foundry model endpoints and the MCP/tool endpoints, giving one governed choke point for authentication, OBO token validation, **token-based rate limiting**, key/secret protection (no model keys in the app), request/response logging, and semantic caching. The vulnerable baseline calls models and tools directly; the secure end-state routes everything through the gateway.
- **Two deployable variants** of the same app, selected by config/flag or folder:
  - `vulnerable` — insecure baseline (default for Module 0).
  - `secure` — hardened reference (the lab's end state).
- Participants progressively turn the vulnerable app into the secure one; `secure` is the answer key.

## 4. The vulnerabilities (baseline) → what the lab adds

| # | Vulnerability (baseline) | Remediation added in lab (Azure + code + prompt) |
|---|--------------------------|---------------------------------------------------|
| V1 | **Ungoverned/unsafe model** (e.g. self-hosted Grok / open model, no safety system) | Governed Azure AI Foundry deployment; default + custom **content filters**; model selection guidance |
| V2 | **No guardrails** — Content Safety / **Prompt Shields** off | Enable Content Safety: Prompt Shields (user-prompt jailbreak + **indirect/document** attacks), harmful-content categories, **Groundedness detection**, Protected Material |
| V3 | **PII/data safety** — PII flows into prompts, logs, responses; system prompt leaks | **PII detection + redaction** (Azure AI Language / Content Safety) pre-model and pre-log; output filtering; system-prompt hardening |
| V4 | **Overpermissioned tools** — DB tool uses admin conn string (read/write/DDL); `transfer_funds` runs with no confirmation; no per-tool authZ | Least-privilege scoped DB role (read-only + **row-level security**), parameterized queries, **human-in-the-loop** confirmation for state-changing tools, per-agent tool allow-listing |
| V5 | **No/bad OAuth + overpermissive RBAC** — shared SP / static API key, no user identity propagation, Owner/Contributor everywhere, secrets in code | **Entra ID** OAuth 2.0 auth-code + **On-Behalf-Of** flow, **managed identities** for service-to-service, **Key Vault** for secrets, **least-privilege RBAC** + API scopes |
| V6 | **Data leakage / poisoning** — untrusted RAG ingestion, indirect prompt injection in docs, no governance | Trusted ingestion + content validation, **indirect prompt injection** defense, **Microsoft Purview / DSPM for AI**, sensitivity labels, DLP, groundedness checks |
| V7 | **Insecure infrastructure** — public endpoints, no network isolation, no monitoring, verbose errors (the hosting environment, not V8's code interpreter) | **Private endpoints / VNet**, **Defender for Cloud** AI threat protection, **Monitor/Log Analytics** auditing, rate limiting, safe error handling |
| V8 | **Unsafe code execution** — reporting agent runs model-generated code with no sandbox, full network/file access | **Sandboxed Code Interpreter** (Foundry-hosted), no outbound network, ephemeral FS, output validation, CPU/time limits |
| V9 | **Insecure MCP tool integration** — agent connects to an unpinned/untrusted **MCP server**, the DB admin credential is passed straight through, all advertised MCP tools are callable (no allow-list), and MCP responses are trusted as clean text (tool/output poisoning) | Pin/approve trusted MCP servers only, pass a **scoped read-only identity (OBO)** to the server, **allow-list** the specific MCP tools each agent may call, and run MCP outputs through the **guard middleware** (Prompt Shields + PII) as untrusted content |
| V10 | **No AI gateway** — models and tool endpoints are exposed directly: model keys in the app, no central authN/Z, no token throttling, no audit | Front models + tools with **Azure API Management (AI Gateway)**: managed-identity/OBO auth, **token-based rate limiting**, key vaulting, centralized logging + semantic caching |

### 4a. Standards mapping (OWASP + Microsoft)

Each vulnerability maps to **OWASP Top 10 for LLM Apps (2025)**, the **OWASP Agentic AI threat taxonomy** (Agentic Security Initiative), and a **Microsoft control baseline** (Microsoft Cloud Security Benchmark / Azure Well-Architected Security pillar / MITRE ATLAS). The workshop teaches each remediation against these references.

| # | OWASP LLM (2025) | OWASP Agentic threat | Microsoft baseline / control |
|---|------------------|----------------------|------------------------------|
| V1 | LLM03 Supply Chain · LLM09 Misinformation | T5 Cascading Hallucination | MCSB **GS/DevOps & model governance**; Azure AI Foundry Responsible AI; WAF Security |
| V2 | LLM01 Prompt Injection · LLM05 Improper Output Handling | T6 Intent Breaking & Goal Manipulation | Azure AI **Content Safety / Prompt Shields**; MITRE ATLAS *Prompt Injection*; Defender for Cloud AI |
| V3 | LLM02 Sensitive Info Disclosure · LLM07 System Prompt Leakage | T15 Human Manipulation | MCSB **DP (Data Protection)**; Microsoft **Purview** sensitivity + PII |
| V4 | LLM06 Excessive Agency | T2 Tool Misuse · T10 Overwhelming Human-in-the-Loop | MCSB **PA (Privileged Access)** least privilege; WAF Security |
| V5 | LLM06 Excessive Agency | T3 Privilege Compromise · T9 Identity Spoofing & Impersonation | MCSB **IM (Identity Mgmt)** + **PA**; Microsoft **Entra** OBO + managed identity + RBAC |
| V6 | LLM04 Data & Model Poisoning · LLM08 Vector & Embedding Weaknesses · LLM01 (indirect) | T1 Memory Poisoning · T12 Agent Communication Poisoning | MCSB **DP**; Microsoft **Purview / DSPM for AI**; groundedness |
| V7 | LLM10 Unbounded Consumption | T4 Resource Overload · T8 Repudiation & Untraceability | MCSB **NS (Network Security)** + **LT (Logging & Threat Detection)**; Defender for Cloud; Azure Monitor |
| V8 | LLM05 Improper Output Handling · LLM06 Excessive Agency | T11 Unexpected RCE / Code Attacks | MCSB **PA** + workload isolation; Foundry sandboxed Code Interpreter; WAF Security |
| V9 | LLM06 Excessive Agency · LLM01 Prompt Injection (via tool output) · LLM03 Supply Chain | T2 Tool Misuse · T12 Agent Communication Poisoning | MCSB **PA** + **SC (Supply Chain)**; MCP tool allow-listing + scoped OBO; guard on tool output |
| V10 | LLM10 Unbounded Consumption · LLM02 Sensitive Info Disclosure (keys) | T4 Resource Overload · T8 Repudiation & Untraceability | MCSB **NS** + **IM** + **LT**; **Azure API Management** AI Gateway (token limit, auth, logging) |

## 5. Lab modules (workshop.md sections)

The lab is told as **two coherent parts**:

- **Part 1 · Understand the vulnerabilities (run locally).** Replaces the old "Module 0". A single local-only walkthrough where the participant runs the app on their laptop (seeded SQLite + local SLM, **no Azure**) and **exploits all of V1–V10 through the chat UI**. Ends with a "what you'll fix in Part 2" map. This is the consolidated "exploit" track.
- **Part 2 · Add the Azure security layers.** Modules 1–11 + capstone. Each module adds **one named Azure security layer** over the baseline and re-runs a Part 1 exploit to prove it's dead. Module headers are named after the Azure layer they add (e.g. "Module 1 — Foundry guardrails", "Module 5 — Entra ID identity & AI Search document security", "Module 6 — APIM AI gateway, observability, rate limiting & Defender"). Part 2 = the old Core track (Modules 1–6, no tenant admin) + Extended track (Modules 7–11 + capstone).

Per-module loop in **Part 2**: *Scenario → Recall the exploit → Why it's dangerous (OWASP/MS mapping) → **Add the Azure layer** (design · secure code · Azure wiring) → Verify → MS Learn references.* The **Add the Azure layer** section is wrapped in a `<details>` and structured as **(a) secure design & code**, **(b) Azure wiring**, **(c) design notes / trade-offs**, then the `ENABLE_*` toggle (offline before/after switch only).

### Core track (half-day, ~4 h) — fully code/Terraform-deployable, no tenant admin

| M | Title | Vulns | OWASP / Agentic | ~Time |
|---|-------|-------|-----------------|-------|
| 0 | **Deploy the vulnerable multi-agent app** — Terraform + Foundry project + seed data + baseline tour | — | — | 35m |
| 1 | **Responsible & Safe AI** — harmful categories (sexual, hate, violence, self-harm), off-topic/politics, "bad jokes", weak system prompt; enable Content Safety filters + blocklists + system-prompt hardening **on the Foundry model deployment + agent** | V1, V2 | LLM05/09, T6 | 35m |
| 2 | **Prompt injection & jailbreak** — direct jailbreak + **indirect** injection via a poisoned RAG doc; enable **Prompt Shields** (user-prompt + document) **as a Foundry model/agent guardrail** | V2, V6 | LLM01, T6 | 35m |
| 3 | **PII & sensitive-data protection (in-app / API guard)** — detect + redact PII before model / logs / output (Azure AI Language PII at the API layer; Foundry can't redact prompt PII for you); system-prompt leakage. *This is the first in-app guard layer beyond Foundry.* | V3 | LLM02/07, T15 | 30m |
| 4 | **Tool least privilege, MCP tool scoping, human-in-the-loop & secure code execution** — scope DB role + RLS, attach data tools as **local *or* Postgres MCP server** tools, allow-list + scope the MCP surface, HITL gate on `transfer_funds`, sandbox the reporting **code interpreter** | V4, V8, V9 | LLM06, T2/T10/T11/T12 | 45m |
| 5 | **Identity & access** — Entra **OBO** + managed identity + least-priv RBAC + Key Vault; **RAG document-level security trimming** by user identity in AI Search (`group_ids` + `search.in()`) | V5 | LLM06, T3/T9 | 40m |
| 6 | **Secure infrastructure, AI gateway & monitoring** — front models + MCP/tool endpoints with **Azure API Management (AI Gateway)** (central auth, token-based throttling, key vaulting, logging, caching), private endpoints, Defender for Cloud AI, Monitor/Log Analytics, safe errors | V7, V10 | LLM10, T4/T8 | 35m |

### Extended track (self-paced, +2–3 h → full day)

| M | Title | Focus | Notes |
|---|-------|-------|-------|
| 7 | **Data governance with Microsoft Purview** — DSPM for AI, sensitivity labels, **DLP for AI**, classification + audit; register the Foundry app as an Entra-registered AI app | V3, V6 | **tenant admin + licensing**; guided + fallback (§5b) |
| 8 | **Data poisoning deep-dive & groundedness** — trusted ingestion pipeline, content validation, Groundedness detection | V6 | code-deployable |
| 9 | **Evaluations** — safety + quality evals (groundedness, relevance, content-harm, indirect-attack) with `azure-ai-evaluation` / Foundry evaluations; gate changes | assurance | code-deployable |
| 10 | **AI Red Teaming (automated)** — run the **Azure AI Red Teaming Agent** (PyRIT) to *automatically* scan the secured app at scale across risk categories + attack strategies; produces a coverage scorecard you can re-run as a regression gate | assurance | code-deployable |
| 11 | **Agent governance toolkit (Microsoft)** — agent inventory, policy, governance posture | governance | uses [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit); optional/self-paced |
| C | **Capstone red-team challenge (manual)** — *you* attack the hardened app by hand using everything you learned (jailbreaks, IDOR, indirect injection, code-exec, tool abuse), then fill in a scorecard confirming each V1–V8 mitigation holds. Where M10 is automated/tooling coverage, the capstone is the human, integrative "can you still break it?" exercise that proves understanding | all | builds on M0–10 |

Each module: *Scenario → Exploit it → Why it's dangerous (OWASP/MS mapping) → **Remediate** → Verify → MS Learn references.* The **Remediate** step must genuinely *explore the solution*, not just flip a toggle. Structure it as: **(a) the secure design & code** — quote the real secure path from the implementation file and explain how it works; **(b) the Azure wiring** — the concrete service config (Terraform/CLI/SDK/policy) that enforces the control in production; **(c) design notes / trade-offs** — why this design, alternatives, and how it layers with other controls; then the `ENABLE_*` toggle, framed explicitly as *only* the offline before/after switch. Per-module times are annotated in `workshop.md`; the Core track fits a **half day (~4 h)** and the Extended track makes it a **full day**.

### 5a. Prerequisites & prep (do before the timed flow)

Some steps need **tenant-admin rights or slow provisioning** and must not block the in-session clock. Provide each as ready-to-run code or click-through with a clear fallback:

- **Entra ID (Module 5):** app registration(s) for API + client, expose-an-API scopes, OBO grant, and the least-privilege app roles/RBAC role assignments. Provide `az ad` / Terraform `azuread` snippets. Fallback if participant lacks tenant admin: use a pre-created app reg or run the module in "read-only walkthrough" mode.
- **Microsoft Purview / DSPM for AI (Module 3 & 6):** enabling DSPM for AI, sensitivity labels, and DLP requires Purview + licensing and can take time to populate. Provide setup steps + screenshots and a code-only fallback (Azure AI Language PII + classification) so the security control is still demonstrated end-to-end without waiting on Purview ingestion.
- **Defender for Cloud AI threat protection (Module 6):** enabling the AI workload plan is subscription-level; provide `az` enablement command and note propagation delay.
- **Quotas/regions:** model + PostgreSQL capacity vary by region; document a known-good region and how to check quota before Module 0.

### 5b. Implementability matrix (be honest about what's code-deployable)

| Capability | Deployable in lab? | How / fallback |
|---|---|---|
| Foundry project + models + content filters | ✅ Terraform + Foundry SDK | `azure-ai-projects` |
| Prompt Shields, Groundedness, blocklists | ✅ code | Content Safety API |
| PII detection + redaction | ✅ code | Azure AI Language PII |
| DB least-privilege + RLS, human-in-the-loop | ✅ code | Postgres roles + app logic |
| Sandboxed code interpreter | ✅ | Foundry-hosted Code Interpreter tool |
| Local vs. **MCP** tool transport (Postgres MCP server) | ✅ code | Azure Database for PostgreSQL MCP server attached as a Foundry hosted MCP tool; offline mode models the MCP transport boundary locally |
| **Azure API Management — AI Gateway** (token limit, auth, logging, cache) | ✅ Terraform/`az` | APIM in front of Foundry model + MCP/tool endpoints; offline fallback simulates gateway policies (throttle, auth check, key hiding) |
| Entra OBO + RBAC + Key Vault | ⚠️ needs tenant rights | Terraform `azuread` + `az ad`; fallback: pre-created app reg / read-only walkthrough |
| AI Search document-level security trimming | ✅ code | `group_ids` + `search.in()` (Entra object IDs) |
| Private endpoints, Defender for Cloud AI, Monitor | ✅ Terraform/`az` | note propagation delay |
| **Purview DSPM for AI / sensitivity labels / DLP for AI** | ⚠️ tenant admin + M365/Purview licensing | guided click-through + screenshots; **fallback: in-app Azure AI Language PII + classification + audit logging** so the control is demonstrated without Purview |
| Evaluations (`azure-ai-evaluation`) | ✅ code | local + Foundry cloud eval |
| AI Red Teaming Agent (PyRIT) | ✅ code | `azure-ai-evaluation` red team |
| **Agent governance toolkit** | ❓ optional/self-paced | [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) — apply its governance guidance to the lab's agents; deep-deploy steps are optional |

> Rule: if a section isn't fully implementable in a self-service subscription, the workshop **must say so explicitly** and provide either a working fallback or a clearly-marked "further discussion" note. The **Core track must stay runnable end-to-end without tenant-admin rights**.

## 6. Repository layout

```
src/
  app/            # FastAPI backend + minimal chat web UI (entry point)
  agents/         # Microsoft Agent Framework: orchestrator + specialist agents
    orchestrator/ # planner/router workflow
    knowledge/    # RAG agent
    accounts/     # read tools agent
    transactions/ # state-changing tools agent (HITL)
    reporting/    # code-interpreter agent
    guard/        # safety middleware (content safety, prompt shields, PII)
    tools/        # tool/function implementations (Postgres, search, email)
      mcp.py      # MCP transport boundary: local-vs-MCP tool routing + V9 (insecure MCP) vs secure
    gateway/      # AI Gateway client shim: routes model/tool calls via APIM (V10) vs direct
    prompts/
      vulnerable/ # insecure system prompts (baseline)
      secure/     # hardened system prompts (answer key)
  config.py       # SECURE_MODE flag + feature toggles per vulnerability
  evals/          # azure-ai-evaluation suites (Module 9)
  redteam/        # AI Red Teaming Agent scans (Module 10)
  data/           # seed SQL, sample financial docs (incl. one poisoned doc for M2/M8)
  infra/          # Terraform: Foundry project + AI Search + PostgreSQL + Blob + Entra + Key Vault + APIM (AI Gateway) + monitoring
  scripts/        # deploy/seed/teardown helpers
docs/
  workshop.md     # MOAW lab tutorial (front matter + `---` separated sections)
  assets/         # diagrams, screenshots, banner (1280x640)
.github/instructions/  # this spec
```

## 7. Conventions

- **Stack:** Python backend (FastAPI) + minimal web chat UI. **Multi-agent orchestration via Microsoft Agent Framework (`agent-framework`)**; **Foundry project + models + agents + evaluations via the Foundry project SDK (`azure-ai-projects>=2.0.0`)**; auth via `azure-identity` `DefaultAzureCredential`. Evaluations: `azure-ai-evaluation`. Keep dependencies minimal and pinned.
- **Models:** prefer governed Foundry deployments. V1 "ungoverned model" is **simulated** by a Foundry deployment with content filters disabled (safe + reproducible), not a real unsafe model.
- **IaC:** **Terraform** as primary (azd optional wrapper). Idempotent, parameterized, `terraform destroy`-clean. No hardcoded secrets — outputs to Key Vault / `.env.example`.
- **Auth:** prefer **managed identity** + **Entra ID**; never commit secrets; provide `.env.example` only.
- **Vulnerable vs. secure:** isolate insecure behavior so the *diff* between `vulnerable/` and `secure/` is the teaching artifact. Clearly comment intentional vulnerabilities with `# LAB-VULN(Vn): ...`.
- **Learner-friendly code:** the app must be easy for an intermediate dev to read and *edit*. Keep each module's lever to a single, obvious place: one `ENABLE_*` toggle in `config.py`, one clearly-commented `# LAB-VULN(Vn)` branch in the relevant file. No deep inheritance, no metaprogramming, no clever indirection. Every file starts with a docstring saying what it does and which V# it relates to. The workshop includes a **code map** so participants know exactly which file to open per module.
- **Safety of the lab itself:** intentionally vulnerable code must be obviously labeled, scoped to throwaway sample data, and never reachable in the `secure` variant.
- **MOAW format:** `docs/workshop.md` uses the required front matter (`type: workshop`, `title`, `description`, `level`, `authors`, `contacts`, `duration_minutes`, `tags`) and `---`-separated sections; use admonition `<div class="warning|tip|task|info|important">` blocks.
- **Grounding:** cite official **Microsoft Learn** docs for every remediation — Content Safety / Prompt Shields, Azure AI Language PII, Purview / DSPM for AI + DLP, Microsoft Agent Framework, Foundry project SDK, AI Search document-level security (`search.in()`), Entra OBO, Defender for Cloud, PostgreSQL Flexible Server (roles/RLS), **Azure Database for PostgreSQL MCP server** + **Model Context Protocol** tool support in Foundry/Agent Framework, **Azure API Management as an AI gateway** (token-based rate limiting / GenAI policies), `azure-ai-evaluation` (evals + AI Red Teaming Agent).

## 8. Definition of done

- `terraform apply` + seed script stands up the full app in a fresh subscription.
- Vulnerable variant demonstrably exhibits each V1–V10.
- Secure variant passes the capstone red-team and demonstrably mitigates each.
- `workshop.md` walks a participant end-to-end with copy-pasteable commands; the **Core track** runs without tenant-admin rights and any non-implementable step has a stated fallback or "further discussion" note.
