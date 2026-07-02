"""Central configuration for BulkAuditAI.

Secrets are loaded from the environment / `.env`. They are NEVER persisted to
the database and are only ever exposed through the API in masked form
(see ``masked_settings``).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (the directory that contains `backend/` and `frontend/`).
ROOT_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Chain access -------------------------------------------------------
    rpc_url: str = Field(default="", alias="RPC_URL")
    chain: str = Field(default="ethereum", alias="CHAIN")

    # --- Source/ABI fetching -----------------------------------------------
    etherscan_api_key: str = Field(default="", alias="ETHERSCAN_API_KEY")
    etherscan_base_url: str = Field(
        default="https://api.etherscan.io/v2/api", alias="ETHERSCAN_BASE_URL"
    )

    # --- DeepSeek -----------------------------------------------------------
    deepseek_api_key: str = Field(default="", alias="DEEPSEEK_API_KEY")
    deepseek_base_url: str = Field(
        default="https://api.deepseek.com", alias="DEEPSEEK_BASE_URL"
    )
    deepseek_model: str = Field(default="deepseek-chat", alias="DEEPSEEK_MODEL")
    ai_review_mode: str = Field(default="ultra", alias="AI_REVIEW_MODE")
    ai_timeout_seconds: int = Field(default=300, alias="AI_TIMEOUT_SECONDS")
    ai_min_interval_seconds: float = Field(default=1.0, alias="AI_MIN_INTERVAL_SECONDS")
    ai_max_retries: int = Field(default=3, alias="AI_MAX_RETRIES")
    ai_retry_backoff_seconds: float = Field(default=3.0, alias="AI_RETRY_BACKOFF_SECONDS")

    # --- Feature toggles ----------------------------------------------------
    enable_slither: bool = Field(default=True, alias="ENABLE_SLITHER")
    enable_mythril: bool = Field(default=True, alias="ENABLE_MYTHRIL")
    enable_semgrep: bool = Field(default=True, alias="ENABLE_SEMGREP")
    enable_aderyn: bool = Field(default=True, alias="ENABLE_ADERYN")
    enable_foundry: bool = Field(default=False, alias="ENABLE_FOUNDRY")
    enable_fuzzing: bool = Field(default=False, alias="ENABLE_FUZZING")
    enable_bytecode_intel: bool = Field(default=True, alias="ENABLE_BYTECODE_INTEL")
    enable_bytecode_probes: bool = Field(default=True, alias="ENABLE_BYTECODE_PROBES")
    enable_deepseek: bool = Field(default=True, alias="ENABLE_DEEPSEEK")
    # --- New reasoning layers (gaps #1/#3/#8) ------------------------------- #
    enable_invariant_reasoner: bool = Field(default=True, alias="ENABLE_INVARIANT_REASONER")
    enable_refutation: bool = Field(default=True, alias="ENABLE_REFUTATION")
    enable_sourcify: bool = Field(default=True, alias="ENABLE_SOURCIFY")
    enable_value_context: bool = Field(default=True, alias="ENABLE_VALUE_CONTEXT")
    enable_sanity_liveness: bool = Field(default=True, alias="ENABLE_SANITY_LIVENESS")
    enable_chain_liveness: bool = Field(default=True, alias="ENABLE_CHAIN_LIVENESS")
    enable_analyzer_findings: bool = Field(default=True, alias="ENABLE_ANALYZER_FINDINGS")
    enable_refuter_precision_rules: bool = Field(default=True, alias="ENABLE_REFUTER_PRECISION_RULES")
    enable_binding_hard_gate: bool = Field(default=True, alias="ENABLE_BINDING_HARD_GATE")
    enable_critical_value_gate: bool = Field(default=True, alias="ENABLE_CRITICAL_VALUE_GATE")
    enable_pattern_priors: bool = Field(default=True, alias="ENABLE_PATTERN_PRIORS")
    enable_companion_expansion: bool = Field(default=False, alias="ENABLE_COMPANION_EXPANSION")
    companion_expansion_max_targets: int = Field(default=8, alias="COMPANION_EXPANSION_MAX_TARGETS")
    companion_expansion_hard_cap: int = Field(default=25, alias="COMPANION_EXPANSION_HARD_CAP")
    max_hypotheses_per_target: int = Field(default=8, alias="MAX_HYPOTHESES_PER_TARGET")
    max_pocs_per_target: int = Field(default=3, alias="MAX_POCS_PER_TARGET")
    refutation_mode: str = Field(default="hard", alias="REFUTATION_MODE")
    # Fork oracle/flash-loan manipulation simulator (needs ENABLE_FOUNDRY + RPC).
    enable_flashloan_sim: bool = Field(default=True, alias="ENABLE_FLASHLOAN_SIM")
    max_sims_per_target: int = Field(default=2, alias="MAX_SIMS_PER_TARGET")

    # --- Monitoring ("before-drain") + alerting ----------------------------- #
    enable_monitor: bool = Field(default=False, alias="ENABLE_MONITOR")
    monitor_interval_seconds: int = Field(default=300, alias="MONITOR_INTERVAL_SECONDS")
    monitor_scan_profile: str = Field(default="ultra-deep-v2", alias="MONITOR_SCAN_PROFILE")
    # Cap auto-onboarded contracts per deployer-watch cycle (prolific factories).
    max_new_deploys_per_check: int = Field(default=25, alias="MAX_NEW_DEPLOYS_PER_CHECK")
    # Outbound webhook for alerts (Slack/Discord/Telegram-compatible or generic JSON).
    alert_webhook_url: str = Field(default="", alias="ALERT_WEBHOOK_URL")

    # --- Limits / timeouts --------------------------------------------------
    max_parallel_scans: int = Field(default=2, alias="MAX_PARALLEL_SCANS")
    max_parallel_targets: int = Field(default=3, alias="MAX_PARALLEL_TARGETS")
    mythril_timeout: int = Field(default=90, alias="MYTHRIL_TIMEOUT")
    slither_timeout: int = Field(default=180, alias="SLITHER_TIMEOUT")
    semgrep_timeout: int = Field(default=120, alias="SEMGREP_TIMEOUT")
    aderyn_timeout: int = Field(default=240, alias="ADERYN_TIMEOUT")
    foundry_timeout: int = Field(default=300, alias="FOUNDRY_TIMEOUT")
    fuzz_timeout: int = Field(default=180, alias="FUZZ_TIMEOUT")

    # --- Server -------------------------------------------------------------
    host: str = Field(default="0.0.0.0", alias="HOST")
    # Fresh, uncommon port so it does not collide with services already on 8000.
    port: int = Field(default=8791, alias="PORT")
    cors_origins: str = Field(
        default="http://localhost:5891,http://127.0.0.1:5891", alias="CORS_ORIGINS"
    )

    # --- Storage ------------------------------------------------------------
    database_url: str = Field(default="sqlite:///./bulkauditai.db", alias="DATABASE_URL")
    output_dir: str = Field(default="./backend/outputs/scans", alias="OUTPUT_DIR")

    # ----------------------------------------------------------------------- #
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def output_path(self) -> Path:
        p = Path(self.output_dir)
        if not p.is_absolute():
            p = ROOT_DIR / p
        return p

    def etherscan_chain_id(self, chain: str | None = None) -> int:
        """Map a chain name to its Etherscan v2 chainid."""
        chain = (chain or self.chain or "ethereum").lower()
        return {
            "ethereum": 1, "mainnet": 1, "sepolia": 11155111,
            "arbitrum": 42161, "optimism": 10, "base": 8453, "polygon": 137,
            "bsc": 56, "avalanche": 43114, "avax": 43114, "scroll": 534352,
            "linea": 59144, "zksync": 324, "zksync-era": 324, "blast": 81457,
            "gnosis": 100, "fantom": 250, "celo": 42220, "mantle": 5000,
            "mode": 34443, "polygonzkevm": 1101, "arbitrum-nova": 42170,
        }.get(chain, 1)

    def rpc_url_for(self, chain: str | None = None) -> str:
        """Per-chain RPC: env ``RPC_URL_<CHAIN>`` (e.g. RPC_URL_BASE) or the default."""
        import os

        chain = (chain or self.chain or "ethereum").lower()
        return os.environ.get(f"RPC_URL_{chain.upper().replace('-', '_')}", "") or self.rpc_url


@lru_cache
def get_settings() -> Settings:
    return Settings()


def _mask(value: str, keep_head: int = 12, keep_tail: int = 4) -> str:
    """Mask a secret, showing only a small head and tail."""
    if not value:
        return ""
    if len(value) <= keep_head + keep_tail:
        return "***"
    return f"{value[:keep_head]}...{value[-keep_tail:]}"


def masked_settings() -> dict:
    """Return a UI-safe view of settings: secrets are masked, flags are plain."""
    s = get_settings()
    return {
        "rpc_url": _mask(s.rpc_url, keep_head=18, keep_tail=4),
        "rpc_url_configured": bool(s.rpc_url),
        "chain": s.chain,
        "etherscan_api_key": _mask(s.etherscan_api_key, keep_head=4, keep_tail=4),
        "etherscan_configured": bool(s.etherscan_api_key),
        "deepseek_api_key": _mask(s.deepseek_api_key, keep_head=5, keep_tail=4),
        "deepseek_configured": bool(s.deepseek_api_key),
        "deepseek_base_url": s.deepseek_base_url,
        "deepseek_model": s.deepseek_model,
        "ai_review": {
            "mode": s.ai_review_mode,
            "timeout_seconds": s.ai_timeout_seconds,
            "min_interval_seconds": s.ai_min_interval_seconds,
            "max_retries": s.ai_max_retries,
            "retry_backoff_seconds": s.ai_retry_backoff_seconds,
            "refutation_mode": s.refutation_mode,
        },
        "toggles": {
            "slither": s.enable_slither,
            "mythril": s.enable_mythril,
            "semgrep": s.enable_semgrep,
            "aderyn": s.enable_aderyn,
            "foundry": s.enable_foundry,
            "fuzzing": s.enable_fuzzing,
            "bytecode_intel": s.enable_bytecode_intel,
            "bytecode_probes": s.enable_bytecode_probes,
            "deepseek": s.enable_deepseek,
            "invariant_reasoner": s.enable_invariant_reasoner,
            "refutation": s.enable_refutation,
            "sourcify": s.enable_sourcify,
            "flashloan_sim": s.enable_flashloan_sim,
            "value_context": s.enable_value_context,
            "sanity_liveness": s.enable_sanity_liveness,
            "chain_liveness": s.enable_chain_liveness,
            "analyzer_findings": s.enable_analyzer_findings,
            "refuter_precision_rules": s.enable_refuter_precision_rules,
            "binding_hard_gate": s.enable_binding_hard_gate,
            "critical_value_gate": s.enable_critical_value_gate,
            "pattern_priors": s.enable_pattern_priors,
            "companion_expansion": s.enable_companion_expansion,
        },
        "limits": {
            "max_parallel_scans": s.max_parallel_scans,
            "max_parallel_targets": s.max_parallel_targets,
            "max_hypotheses_per_target": s.max_hypotheses_per_target,
            "max_pocs_per_target": s.max_pocs_per_target,
            "max_sims_per_target": s.max_sims_per_target,
            "companion_expansion_max_targets": s.companion_expansion_max_targets,
            "companion_expansion_hard_cap": s.companion_expansion_hard_cap,
            "mythril_timeout": s.mythril_timeout,
            "slither_timeout": s.slither_timeout,
            "semgrep_timeout": s.semgrep_timeout,
            "foundry_timeout": s.foundry_timeout,
            "fuzz_timeout": s.fuzz_timeout,
        },
    }
