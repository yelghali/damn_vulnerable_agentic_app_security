"""Central configuration for the Zava Wealth Advisor lab app.

Every security control is gated behind a feature toggle so the *diff* between
the vulnerable baseline and the secure end-state is the teaching artifact.

Precedence for each `ENABLE_*` flag:
  1. An explicit env override (e.g. ``ENABLE_PII_REDACTION=true``)
  2. Otherwise inherit from ``SECURE_MODE`` (the master switch)

So the baseline (``SECURE_MODE=false``) is fully vulnerable, flipping
``SECURE_MODE=true`` turns on every mitigation (the answer key), and during the
lab participants flip one toggle per module.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SECURITY_CONTROLS = {
    "content_safety": "enable_content_safety",
    "prompt_shields": "enable_prompt_shields",
    "pii_redaction": "enable_pii_redaction",
    "tool_least_priv": "enable_tool_least_priv",
    "hitl": "enable_hitl",
    "code_sandbox": "enable_code_sandbox",
    "obo": "enable_obo",
    "doc_security": "enable_doc_security",
    "groundedness": "enable_groundedness",
    "secure_runtime": "enable_secure_runtime",
    "mcp_tool_security": "enable_mcp_tool_security",
    "ai_gateway": "enable_ai_gateway",
    "a2a_guard": "enable_a2a_guard",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Lab mode ----------------------------------------------------------
    offline_mode: bool = Field(default=True, alias="OFFLINE_MODE")
    local_data_mode: bool = Field(default=False, alias="LOCAL_DATA_MODE")
    secure_mode: bool = Field(default=False, alias="SECURE_MODE")
    enable_runtime_toggles: bool = Field(default=False, alias="ENABLE_RUNTIME_TOGGLES")

    # --- Local SLM (offline backend) ---------------------------------------
    # In offline mode the app talks to a REAL small language model over an
    # OpenAI-compatible endpoint. Default runtime is Microsoft Foundry Local
    # (auto-discovered via foundry-local-sdk). Set LOCAL_MODEL_ENDPOINT to point
    # at any OpenAI-compatible server instead (e.g. Ollama: http://localhost:11434/v1).
    # If nothing is reachable, the app fails loudly. The lab should always use
    # an actual model, either local or Azure-hosted.
    local_model_name: str = Field(default="phi-3.5-mini", alias="LOCAL_MODEL_NAME")
    local_model_endpoint: str = Field(default="", alias="LOCAL_MODEL_ENDPOINT")
    local_model_key: str = Field(default="", alias="LOCAL_MODEL_KEY")
    local_model_timeout_seconds: float = Field(default=45.0, alias="LOCAL_MODEL_TIMEOUT_SECONDS")

    # --- Per-vulnerability toggles (None => inherit from secure_mode) -------
    enable_content_safety: bool | None = Field(default=None, alias="ENABLE_CONTENT_SAFETY")  # V1/V2
    enable_prompt_shields: bool | None = Field(default=None, alias="ENABLE_PROMPT_SHIELDS")  # V2
    enable_pii_redaction: bool | None = Field(default=None, alias="ENABLE_PII_REDACTION")    # V3
    enable_tool_least_priv: bool | None = Field(default=None, alias="ENABLE_TOOL_LEAST_PRIV")  # V4
    enable_hitl: bool | None = Field(default=None, alias="ENABLE_HITL")                      # V4
    enable_code_sandbox: bool | None = Field(default=None, alias="ENABLE_CODE_SANDBOX")      # V8
    enable_obo: bool | None = Field(default=None, alias="ENABLE_OBO")                        # V5
    enable_doc_security: bool | None = Field(default=None, alias="ENABLE_DOC_SECURITY")      # V5
    enable_groundedness: bool | None = Field(default=None, alias="ENABLE_GROUNDEDNESS")      # V6
    enable_secure_runtime: bool | None = Field(default=None, alias="ENABLE_SECURE_RUNTIME")  # V7
    enable_mcp_tool_security: bool | None = Field(default=None, alias="ENABLE_MCP_TOOL_SECURITY")  # V9
    enable_ai_gateway: bool | None = Field(default=None, alias="ENABLE_AI_GATEWAY")          # V10
    enable_a2a_guard: bool | None = Field(default=None, alias="ENABLE_A2A_GUARD")            # V11

    # --- Tool transport ----------------------------------------------------
    # When true the data tools are reached via an MCP server (the Microsoft
    # Azure MCP Server, postgres namespace) instead of local function calls.
    use_mcp_tools: bool = Field(default=False, alias="USE_MCP_TOOLS")
    pg_mcp_server_url: str = Field(default="", alias="PG_MCP_SERVER_URL")
    # Comma-separated allow-list of MCP tools each agent may call (secure mode).
    mcp_tool_allowlist: str = Field(
        default="get_accounts,get_transactions,get_credit_score",
        alias="MCP_TOOL_ALLOWLIST",
    )
    # AI gateway (Azure API Management) base URL placed in front of models/tools.
    ai_gateway_url: str = Field(default="", alias="AI_GATEWAY_URL")
    ai_gateway_token_limit: int = Field(default=20000, alias="AI_GATEWAY_TOKEN_LIMIT")
    vulnerable_app_url: str = Field(default="", alias="VULNERABLE_APP_URL")
    secure_app_url: str = Field(default="", alias="SECURE_APP_URL")

    # --- Azure AI Foundry --------------------------------------------------
    foundry_project_endpoint: str = Field(default="", alias="FOUNDRY_PROJECT_ENDPOINT")
    foundry_model_name: str = Field(default="", alias="FOUNDRY_MODEL_NAME")
    foundry_model_deployment: str = Field(default="gpt-4.1-mini", alias="FOUNDRY_MODEL_DEPLOYMENT")
    foundry_ungoverned_deployment: str = Field(
        default="gpt-4.1-mini-nofilter", alias="FOUNDRY_UNGOVERNED_DEPLOYMENT"
    )
    # Provision persistent Foundry agents (so they appear in the portal Agents
    # tab) instead of only calling chat completions. Driven by
    # scripts/provision_foundry_agents.py.
    provision_foundry_agents: bool = Field(default=False, alias="PROVISION_FOUNDRY_AGENTS")
    # Foundry project connection names for the agent tools.
    search_connection_name: str = Field(default="zava-search", alias="SEARCH_CONNECTION_NAME")
    pg_mcp_connection_name: str = Field(default="zava-postgres-mcp", alias="PG_MCP_CONNECTION_NAME")

    # --- Content Safety / Language / Search --------------------------------
    content_safety_endpoint: str = Field(default="", alias="CONTENT_SAFETY_ENDPOINT")
    content_safety_key: str = Field(default="", alias="CONTENT_SAFETY_KEY")
    # Guardrail tuning (Module 1) — mirrors the Azure Content Safety portal,
    # where you don't just turn the filter on/off, you *tune* it per aspect:
    #   * a global severity threshold 1..7 (lower = stricter; a category blocks
    #     at/above it) — the default for every harm category
    #   * per-category overrides for the 4 Azure harm categories (Hate, Sexual,
    #     Violence, Self-Harm), each its own slider exactly like the portal.
    #     None -> inherit the global threshold.
    #   * an org "off-topic" custom category (e.g. politics) you can detach
    # These only take effect while enable_content_safety is on.
    content_safety_severity_threshold: int = Field(
        default=2, alias="CONTENT_SAFETY_SEVERITY_THRESHOLD"
    )
    content_safety_threshold_hate: int | None = Field(
        default=None, alias="CONTENT_SAFETY_THRESHOLD_HATE"
    )
    content_safety_threshold_sexual: int | None = Field(
        default=None, alias="CONTENT_SAFETY_THRESHOLD_SEXUAL"
    )
    content_safety_threshold_violence: int | None = Field(
        default=None, alias="CONTENT_SAFETY_THRESHOLD_VIOLENCE"
    )
    content_safety_threshold_self_harm: int | None = Field(
        default=None, alias="CONTENT_SAFETY_THRESHOLD_SELF_HARM"
    )
    content_safety_block_off_topic: bool = Field(
        default=True, alias="CONTENT_SAFETY_BLOCK_OFF_TOPIC"
    )
    language_endpoint: str = Field(default="", alias="LANGUAGE_ENDPOINT")
    language_key: str = Field(default="", alias="LANGUAGE_KEY")
    search_endpoint: str = Field(default="", alias="SEARCH_ENDPOINT")
    search_index_name: str = Field(default="zava-financial-docs", alias="SEARCH_INDEX_NAME")
    search_key: str = Field(default="", alias="SEARCH_KEY")

    # --- Data layer --------------------------------------------------------
    pg_admin_connection: str = Field(default="", alias="PG_ADMIN_CONNECTION")
    pg_app_connection: str = Field(default="", alias="PG_APP_CONNECTION")
    default_customer_id: str = Field(default="CUST-1001", alias="DEFAULT_CUSTOMER_ID")
    default_owner_user_id: str = Field(default="user_1", alias="DEFAULT_OWNER_USER_ID")
    admin_groups: str = Field(default="zava-managers", alias="ADMIN_GROUPS")

    # --- Entra / Key Vault / Monitor ---------------------------------------
    azure_tenant_id: str = Field(default="", alias="AZURE_TENANT_ID")
    entra_api_client_id: str = Field(default="", alias="ENTRA_API_CLIENT_ID")
    entra_api_client_secret: str = Field(default="", alias="ENTRA_API_CLIENT_SECRET")
    entra_api_scope: str = Field(default="", alias="ENTRA_API_SCOPE")
    entra_redirect_uri: str = Field(default="", alias="ENTRA_REDIRECT_URI")
    key_vault_uri: str = Field(default="", alias="KEY_VAULT_URI")
    appinsights_connection_string: str = Field(
        default="", alias="APPLICATIONINSIGHTS_CONNECTION_STRING"
    )

    # -----------------------------------------------------------------------
    @model_validator(mode="after")
    def _resolve_toggles(self) -> "Settings":
        """Any toggle left as None inherits the master ``secure_mode`` value."""
        for name in SECURITY_CONTROLS.values():
            if getattr(self, name) is None:
                object.__setattr__(self, name, self.secure_mode)
        return self

    # -----------------------------------------------------------------------
    @property
    def active_model_deployment(self) -> str:
        """V1: the vulnerable baseline points at the *ungoverned* deployment
        (content filters off); the secure path uses the governed one."""
        return (
            self.foundry_model_deployment
            if self.enable_content_safety
            else self.foundry_ungoverned_deployment
        )

    def category_threshold(self, category: str) -> int:
        """Severity threshold for one Azure harm category (hate / sexual /
        violence / self_harm). Returns the per-category override if set, else
        the global default — exactly like the per-category sliders in the
        Azure Content Safety portal."""
        override = getattr(self, f"content_safety_threshold_{category}", None)
        return override if override is not None else self.content_safety_severity_threshold

    def summary(self) -> dict[str, object]:
        """Toggle snapshot, surfaced in the UI banner so participants can see
        exactly which mitigations are active."""
        model_label = (
            f"local/{self.local_model_name}"
            if self.offline_mode
            else (
                f"foundry/{self.active_model_deployment} ({self.foundry_model_name})"
                if self.foundry_model_name
                else f"foundry/{self.active_model_deployment}"
            )
        )
        data_backend = "local-sqlite" if self.offline_mode or self.local_data_mode else "postgresql"
        return {
            "secure_mode": self.secure_mode,
            "offline_mode": self.offline_mode,
            "local_data_mode": self.local_data_mode,
            "runtime_toggles_enabled": self.enable_runtime_toggles,
            "model_backend": "foundry-local/openai-compatible" if self.offline_mode else "azure-ai-foundry",
            "model_label": model_label,
            "data_backend": data_backend,
            "ai_gateway_token_limit": self.ai_gateway_token_limit,
            "vulnerable_app_url": self.vulnerable_app_url,
            "secure_app_url": self.secure_app_url,
            "local_login": bool(self.azure_tenant_id and self.entra_api_client_id),
            **{key: bool(getattr(self, attr)) for key, attr in SECURITY_CONTROLS.items()},
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
