"""Runtime configuration for both the orchestrator and the worker."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCANGRID_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------ shared
    role: str = Field(default="orchestrator", description="orchestrator | worker")
    data_dir: Path = Field(default=Path("./var"))
    log_level: str = Field(default="INFO")
    api_token: str = Field(default="change-me-please", min_length=8)

    # THE safety rail. Comma/space/newline separated CIDRs, single IPs, or
    # "a.b.c.d-e" ranges. Nothing outside this set is ever scanned. Public
    # (non-RFC1918) entries are rejected unless allow_public_targets=true.
    allowlist: str = Field(default="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
    allow_public_targets: bool = Field(default=False)

    # ------------------------------------------------------------------ orchestrator
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8090)
    dashboard_user: str = Field(default="")
    dashboard_password: str = Field(default="")

    default_nmap_args: str = Field(
        default="-sS -sV -T3 --top-ports 1000 -Pn --version-light",
        description="Applied to a job when the target doesn't override it.",
    )
    job_timeout_seconds: int = Field(default=3600)
    job_max_attempts: int = Field(default=3)
    scan_history_keep: int = Field(default=20, description="Scans kept per target for diffing.")

    # CVE matching. provider: nvd_api | offline | none
    cve_provider: str = Field(default="nvd_api")
    nvd_api_key: str = Field(default="", description="Raises the NVD rate limit.")
    nvd_feed_dir: Path = Field(default=Path("./data/nvd"), description="offline provider feeds.")
    cve_min_cvss: float = Field(default=0.0, description="Drop findings below this base score.")
    cve_cache_days: int = Field(default=7)

    # notifications: none | log | ntfy | telegram | webhook
    notify_backend: str = Field(default="log")
    notify_min_severity: str = Field(default="medium", description="info|low|medium|high|critical")
    ntfy_url: str = Field(default="https://ntfy.sh")
    ntfy_topic: str = Field(default="")
    telegram_bot_token: str = Field(default="")
    telegram_chat_id: str = Field(default="")
    webhook_url: str = Field(default="")

    # ------------------------------------------------------------------ worker
    orchestrator_url: str = Field(default="http://127.0.0.1:8090")
    worker_id: str = Field(default="worker-1")
    worker_poll_seconds: int = Field(default=10)
    worker_concurrency: int = Field(default=1, description="Parallel nmap runs on this worker.")
    nmap_path: str = Field(default="nmap")

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"orchestrator", "worker"}:
            raise ValueError("role must be 'orchestrator' or 'worker'")
        return v

    @field_validator("cve_provider")
    @classmethod
    def _cve_provider(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"nvd_api", "offline", "none"}:
            raise ValueError("cve_provider must be nvd_api | offline | none")
        return v

    @field_validator("notify_backend")
    @classmethod
    def _notify(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"none", "log", "ntfy", "telegram", "webhook"}:
            raise ValueError("invalid notify_backend")
        return v

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scangrid.db"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
