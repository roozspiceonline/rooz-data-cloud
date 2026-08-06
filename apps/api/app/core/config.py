import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="RDC_",
        extra="ignore",
    )

    env: Literal["development", "test", "staging", "production"] = "development"
    database_url: str = "postgresql+asyncpg://rdc:rdc@localhost:5432/rdc"
    redis_url: str = "redis://localhost:6379/0"

    s3_endpoint: str = "http://localhost:9000"
    s3_bucket: str = "rdc-local"
    s3_access_key: str = "rdc_local"
    s3_secret_key: str = "rdc_local_only_change_me"

    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    session_cookie_name: str = "rdc_session"
    session_cookie_secure: bool = False
    session_idle_minutes: int = 30
    session_absolute_hours: int = 168

    session_token_pepper: str = "development-session-token-pepper-change-me"
    csrf_token_pepper: str = "development-csrf-token-pepper-change-me"
    api_key_pepper: str = "development-api-key-pepper-change-me"
    api_key_issuance_secret: str = "development-api-key-issuance-secret-change-me"
    rate_limit_key: str = "development-rate-limit-key-change-me"
    cursor_signing_key: str = "development-cursor-signing-key-change-me"
    project_secret_master_key_b64: str = (
        "ZGV2ZWxvcG1lbnQtcmRjLXNlY3JldC1rZXktMzJiISE="
    )
    project_secret_master_key_version: str = "local-v1"
    worker_bootstrap_token: str = (
        "development-worker-bootstrap-token-change-me-32"
    )
    worker_token_pepper: str = (
        "development-worker-token-pepper-change-me-32"
    )
    lease_token_pepper: str = (
        "development-lease-token-pepper-change-me-32"
    )
    worker_lease_seconds: int = 60
    worker_lease_max_seconds: int = 300
    worker_max_attempts: int = 5
    worker_secret_envelope_seconds: int = 60

    auth_rate_limit_requests: int = 20
    auth_rate_limit_window_seconds: int = 300

    run_sse_poll_interval_seconds: float = 1.0
    run_sse_heartbeat_seconds: float = 15.0
    run_sse_max_connections: int = 100
    run_sse_replay_limit: int = 500

    @model_validator(mode="after")
    def validate_security_secrets(self) -> "Settings":
        values = {
            "session_token_pepper": self.session_token_pepper,
            "csrf_token_pepper": self.csrf_token_pepper,
            "api_key_pepper": self.api_key_pepper,
            "api_key_issuance_secret": self.api_key_issuance_secret,
            "rate_limit_key": self.rate_limit_key,
            "cursor_signing_key": self.cursor_signing_key,
            "worker_bootstrap_token": self.worker_bootstrap_token,
            "worker_token_pepper": self.worker_token_pepper,
            "lease_token_pepper": self.lease_token_pepper,
        }
        too_short = [name for name, value in values.items() if len(value) < 32]
        if too_short:
            raise ValueError(
                "Security settings must be at least 32 characters: " + ", ".join(too_short)
            )
        try:
            master_key = base64.b64decode(
                self.project_secret_master_key_b64,
                validate=True,
            )
        except ValueError as exc:
            raise ValueError(
                "Project-secret master key must be valid base64."
            ) from exc
        if len(master_key) != 32:
            raise ValueError(
                "Project-secret master key must decode to exactly 32 bytes."
            )
        if not self.project_secret_master_key_version.strip():
            raise ValueError(
                "Project-secret master key version cannot be empty."
            )
        if self.worker_lease_seconds < 15:
            raise ValueError("Worker leases must last at least 15 seconds.")
        if self.worker_lease_max_seconds < self.worker_lease_seconds:
            raise ValueError("Worker lease maximum must exceed the default lease.")
        if not 1 <= self.worker_max_attempts <= 20:
            raise ValueError("Worker max attempts must be between 1 and 20.")
        if not 15 <= self.worker_secret_envelope_seconds <= 300:
            raise ValueError("Secret envelopes must expire between 15 and 300 seconds.")
        if self.env in {"staging", "production"}:
            defaults = [name for name, value in values.items() if "change-me" in value]
            if defaults:
                raise ValueError(
                    "Default security settings are prohibited outside local environments: "
                    + ", ".join(defaults)
                )
            if (
                self.project_secret_master_key_version == "local-v1"
                or self.project_secret_master_key_b64
                == "ZGV2ZWxvcG1lbnQtcmRjLXNlY3JldC1rZXktMzJiISE="
            ):
                raise ValueError(
                    "The local project-secret master key is prohibited "
                    "outside local environments."
                )
            if not self.session_cookie_secure:
                raise ValueError("Secure session cookies are mandatory outside local environments")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
