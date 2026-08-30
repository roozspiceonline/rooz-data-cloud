import base64
import ipaddress
import re
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="RDC_",
        extra="ignore",
    )

    env: Literal["development", "test", "staging", "production"] = "development"
    deployment_id: str = ""
    database_url: str = "postgresql+asyncpg://rdc:rdc@localhost:5432/rdc"
    redis_url: str = "redis://localhost:6379/0"

    s3_endpoint: str = "http://localhost:9000"
    s3_public_endpoint: str = "http://localhost:9000"
    s3_region: str = "us-east-1"
    s3_bucket: str = "rdc-local"
    s3_access_key: str = "rdc_local"
    s3_secret_key: str = "rdc_local_only_change_me"
    storage_upload_grant_seconds: int = 900
    storage_download_grant_seconds: int = 300
    source_archive_max_bytes: int = 33_554_432
    source_archive_max_expanded_bytes: int = 268_435_456
    source_archive_max_files: int = 10_000
    source_archive_max_single_file_bytes: int = 67_108_864
    source_archive_max_compression_ratio: float = 100.0

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
    project_secret_master_key_b64: str = "ZGV2ZWxvcG1lbnQtcmRjLXNlY3JldC1rZXktMzJiISE="
    project_secret_master_key_version: str = "local-v1"
    worker_bootstrap_token: str = "development-worker-bootstrap-token-change-me-32"
    worker_token_pepper: str = "development-worker-token-pepper-change-me-32"
    lease_token_pepper: str = "development-lease-token-pepper-change-me-32"
    worker_lease_seconds: int = 60
    worker_lease_max_seconds: int = 300
    worker_max_attempts: int = 5
    worker_retry_base_seconds: int = 2
    worker_retry_max_seconds: int = 300
    worker_cancel_convergence_seconds: int = 300
    worker_secret_envelope_seconds: int = 60
    worker_registration_max_concurrency: int = 16
    worker_lost_after_seconds: int = 45
    execution_project_default_max_active_leases: int = 20
    execution_recovery_sweep_enabled: bool = True
    execution_recovery_sweep_interval_seconds: int = 10
    execution_recovery_sweep_batch_size: int = 100
    execution_recovery_stale_after_seconds: int = 60
    schedule_dispatch_enabled: bool = True
    schedule_dispatch_interval_seconds: int = 10
    schedule_dispatch_batch_size: int = 100

    sandbox_execution_enabled: bool = False
    sandbox_required_profile: str = "rdc.sandbox/v1"
    sandbox_max_memory_mb: int = 4096
    sandbox_max_cpu_millis: int = 4000
    sandbox_max_pids: int = 512
    sandbox_max_ephemeral_disk_mb: int = 8192
    sandbox_max_build_seconds: int = 900
    sandbox_max_run_seconds: int = 600
    sandbox_max_output_bytes: int = 16_777_216
    sandbox_artifact_max_bytes: int = 8_589_934_592

    sandbox_activation_mode: Literal["disabled", "canary"] = "disabled"
    sandbox_canary_agent_version_id: str = ""
    sandbox_canary_worker_name: str = ""
    sandbox_canary_max_memory_mb: int = 256
    sandbox_canary_max_cpu_millis: int = 500
    sandbox_canary_max_pids: int = 64
    sandbox_canary_max_ephemeral_disk_mb: int = 256
    sandbox_canary_max_build_seconds: int = 300
    sandbox_canary_max_run_seconds: int = 120

    sandbox_canary_web_egress_enabled: bool = False
    sandbox_canary_web_egress_allowed_hosts: list[str] = Field(default_factory=list)
    sandbox_canary_web_egress_max_requests: int = 8
    sandbox_canary_web_egress_max_response_bytes: int = 1_048_576
    sandbox_canary_web_egress_max_total_bytes: int = 4_194_304
    sandbox_canary_web_egress_max_redirects: int = 3
    sandbox_canary_web_egress_connect_timeout_seconds: int = 5
    sandbox_canary_web_egress_request_timeout_seconds: int = 15
    egress_route_provider_key: str = "static-canary"
    egress_route_region_key: str = "local"
    egress_health_min_route_samples: int = 5
    egress_credential_canary_enabled: bool = False
    egress_credential_canary_target_url: str = ""
    egress_credential_canary_claim_seconds: int = 60
    egress_credential_canary_batch_size: int = 50
    egress_credential_canary_max_attempts: int = 3
    egress_credential_canary_live_executor_enabled: bool = False
    egress_credential_canary_poll_interval_seconds: float = 5.0
    egress_credential_canary_connect_timeout_seconds: float = 5.0
    egress_credential_canary_total_timeout_seconds: float = 15.0
    egress_credential_canary_max_response_bytes: int = 65_536
    egress_credential_canary_max_concurrency: int = 4
    egress_credential_canary_max_retries: int = 0
    webhook_delivery_canary_enabled: bool = False
    webhook_delivery_connect_timeout_seconds: float = 5.0
    webhook_delivery_total_timeout_seconds: float = 15.0
    webhook_delivery_max_response_bytes: int = 65_536
    webhook_delivery_max_concurrency: int = 2

    sandbox_canary_browser_enabled: bool = False
    sandbox_canary_browser_live_navigation_enabled: bool = False
    sandbox_canary_dataset_writes_enabled: bool = False
    sandbox_canary_key_value_store_enabled: bool = False
    sandbox_canary_request_queue_enabled: bool = False
    sandbox_canary_request_queue_http_enabled: bool = False
    sandbox_canary_request_queue_browser_enabled: bool = False
    sandbox_canary_request_queue_dataset_enabled: bool = False
    sandbox_canary_request_queue_key_value_store_enabled: bool = False
    sandbox_canary_browser_max_pages: int = 1
    sandbox_canary_browser_max_actions: int = 8
    sandbox_canary_browser_navigation_timeout_seconds: int = 15
    sandbox_canary_browser_max_dom_bytes: int = 2_097_152
    sandbox_canary_browser_max_screenshot_bytes: int = 2_097_152

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
            raise ValueError("Project-secret master key must be valid base64.") from exc
        if len(master_key) != 32:
            raise ValueError("Project-secret master key must decode to exactly 32 bytes.")
        if not self.project_secret_master_key_version.strip():
            raise ValueError("Project-secret master key version cannot be empty.")
        if self.worker_lease_seconds < 15:
            raise ValueError("Worker leases must last at least 15 seconds.")
        if self.worker_lease_max_seconds < self.worker_lease_seconds:
            raise ValueError("Worker lease maximum must exceed the default lease.")
        if not 1 <= self.worker_max_attempts <= 20:
            raise ValueError("Worker max attempts must be between 1 and 20.")
        if not 1 <= self.worker_retry_base_seconds <= 60:
            raise ValueError("Worker retry base must be between 1 and 60 seconds.")
        if not self.worker_retry_base_seconds <= self.worker_retry_max_seconds <= 3600:
            raise ValueError("Worker retry maximum must be between its base and one hour.")
        if not 30 <= self.worker_cancel_convergence_seconds <= 3600:
            raise ValueError(
                "Worker cancellation convergence must be between 30 seconds and one hour."
            )
        if not 15 <= self.worker_secret_envelope_seconds <= 300:
            raise ValueError("Secret envelopes must expire between 15 and 300 seconds.")
        if not 1 <= self.worker_registration_max_concurrency <= 16:
            raise ValueError("Worker registration concurrency must be between 1 and 16.")
        if not 15 <= self.worker_lost_after_seconds <= 300:
            raise ValueError("Worker loss detection must be between 15 and 300 seconds.")
        if not 1 <= self.execution_project_default_max_active_leases <= 1000:
            raise ValueError("Default project execution concurrency must be between 1 and 1000.")
        if not 1 <= self.execution_recovery_sweep_interval_seconds <= 300:
            raise ValueError("Execution recovery sweep interval must be between 1 and 300 seconds.")
        if not 1 <= self.execution_recovery_sweep_batch_size <= 500:
            raise ValueError("Execution recovery sweep batch size must be between 1 and 500.")
        if not (
            2 * self.execution_recovery_sweep_interval_seconds
            <= self.execution_recovery_stale_after_seconds
            <= 3600
        ):
            raise ValueError(
                "Execution recovery stale threshold must be at least two intervals "
                "and no more than one hour."
            )
        if not 1 <= self.schedule_dispatch_interval_seconds <= 300:
            raise ValueError("Schedule dispatch interval must be between 1 and 300 seconds.")
        if not 1 <= self.schedule_dispatch_batch_size <= 500:
            raise ValueError("Schedule dispatch batch size must be between 1 and 500.")
        route_key_pattern = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
        if not route_key_pattern.fullmatch(self.egress_route_provider_key):
            raise ValueError("Egress provider key must be a bounded lowercase slug.")
        if not route_key_pattern.fullmatch(self.egress_route_region_key):
            raise ValueError("Egress region key must be a bounded lowercase slug.")
        if not 5 <= self.egress_health_min_route_samples <= 1000:
            raise ValueError("Egress route health requires between 5 and 1000 samples.")
        if not 15 <= self.egress_credential_canary_claim_seconds <= 300:
            raise ValueError("Egress credential canary claims must last 15 to 300 seconds.")
        if not 1 <= self.egress_credential_canary_batch_size <= 100:
            raise ValueError("Egress credential canary batches must contain 1 to 100 items.")
        if not 1 <= self.egress_credential_canary_max_attempts <= 5:
            raise ValueError("Egress credential canaries allow 1 to 5 claim attempts.")
        if not 0.5 <= self.egress_credential_canary_poll_interval_seconds <= 300:
            raise ValueError(
                "Egress credential canary polling must be between 0.5 and 300 seconds."
            )
        if not 0.1 <= self.egress_credential_canary_connect_timeout_seconds <= 10:
            raise ValueError("Egress credential canary connect timeout is outside the safe bound.")
        if not (
            self.egress_credential_canary_connect_timeout_seconds
            <= self.egress_credential_canary_total_timeout_seconds
            <= 30
        ):
            raise ValueError("Egress credential canary total timeout is outside the safe bound.")
        if not 1 <= self.egress_credential_canary_max_response_bytes <= 1_048_576:
            raise ValueError("Egress credential canary response limit is outside the safe bound.")
        if not 1 <= self.egress_credential_canary_max_concurrency <= 32:
            raise ValueError("Egress credential canary concurrency must be between 1 and 32.")
        if self.egress_credential_canary_max_retries not in {0, 1}:
            raise ValueError("Egress credential canary retries must be zero or one.")
        if not 0.1 <= self.webhook_delivery_connect_timeout_seconds <= 10:
            raise ValueError("Webhook delivery connect timeout is outside the safe bound.")
        if (
            not self.webhook_delivery_connect_timeout_seconds
            <= self.webhook_delivery_total_timeout_seconds
            <= 30
        ):
            raise ValueError("Webhook delivery total timeout is outside the safe bound.")
        if not 1 <= self.webhook_delivery_max_response_bytes <= 65_536:
            raise ValueError("Webhook delivery response limit is outside the safe bound.")
        if not 1 <= self.webhook_delivery_max_concurrency <= 8:
            raise ValueError("Webhook delivery concurrency is outside the safe bound.")
        if self.egress_credential_canary_live_executor_enabled:
            if not self.egress_credential_canary_enabled:
                raise ValueError("The live credential canary executor requires canary scheduling.")
            if (
                self.egress_credential_canary_claim_seconds
                < self.egress_credential_canary_total_timeout_seconds + 5
            ):
                raise ValueError("Credential canary claims must outlive the live request timeout.")
        canary_target = self.egress_credential_canary_target_url.strip()
        if self.egress_credential_canary_enabled and not canary_target:
            raise ValueError("Enabled egress credential canaries require an HTTPS target.")
        if canary_target:
            parsed_target = urlsplit(canary_target)
            target_host = parsed_target.hostname
            if (
                parsed_target.scheme != "https"
                or target_host is None
                or parsed_target.username is not None
                or parsed_target.password is not None
                or parsed_target.query
                or parsed_target.fragment
                or parsed_target.port not in {None, 443}
            ):
                raise ValueError("Egress credential canary target must be credential-free HTTPS.")
            try:
                ipaddress.ip_address(target_host)
            except ValueError:
                pass
            else:
                raise ValueError("Egress credential canary target cannot use an IP literal.")
            normalized_target_host = target_host.rstrip(".").casefold()
            labels = normalized_target_host.split(".")
            if (
                len(normalized_target_host) > 253
                or len(labels) < 2
                or normalized_target_host.endswith(".local")
                or any(
                    not label
                    or len(label) > 63
                    or label[0] == "-"
                    or label[-1] == "-"
                    or not all(
                        character.isascii() and (character.isalnum() or character == "-")
                        for character in label
                    )
                    for label in labels
                )
            ):
                raise ValueError("Egress credential canary target hostname is unsafe.")
            self.egress_credential_canary_target_url = canary_target
        if self.sandbox_required_profile != "rdc.sandbox/v1":
            raise ValueError("The Phase 1H sandbox profile must be rdc.sandbox/v1.")
        if not 128 <= self.sandbox_max_memory_mb <= 32768:
            raise ValueError("Sandbox memory limit is outside the safe range.")
        if not 100 <= self.sandbox_max_cpu_millis <= 16000:
            raise ValueError("Sandbox CPU limit is outside the safe range.")
        if not 16 <= self.sandbox_max_pids <= 4096:
            raise ValueError("Sandbox PID limit is outside the safe range.")
        if not 64 <= self.sandbox_max_ephemeral_disk_mb <= 102400:
            raise ValueError("Sandbox disk limit is outside the safe range.")
        if not 30 <= self.sandbox_max_build_seconds <= 3600:
            raise ValueError("Sandbox Build timeout is outside the safe range.")
        if not 1 <= self.sandbox_max_run_seconds <= 86400:
            raise ValueError("Sandbox Run timeout is outside the safe range.")
        if not 1_048_576 <= self.sandbox_max_output_bytes <= 268_435_456:
            raise ValueError("Sandbox output limit is outside the safe range.")
        if not 1_048_576 <= self.sandbox_artifact_max_bytes <= 68_719_476_736:
            raise ValueError("Sandbox artifact limit is outside the safe range.")
        if self.sandbox_activation_mode == "canary":
            if not self.sandbox_execution_enabled:
                raise ValueError("Canary activation requires the sandbox execution master gate.")
            if not self.sandbox_canary_agent_version_id.strip():
                raise ValueError("Canary activation requires one immutable Agent version ID.")
            try:
                UUID(self.sandbox_canary_agent_version_id.strip())
            except ValueError as exc:
                raise ValueError("Canary Agent version ID must be a UUID.") from exc
            worker_name = self.sandbox_canary_worker_name.strip()
            if (
                len(worker_name) < 3
                or len(worker_name) > 160
                or re.fullmatch(r"[a-z0-9][a-z0-9._-]+", worker_name) is None
            ):
                raise ValueError("Canary worker name must match the worker-name contract.")
        canary_limits = {
            "memory": (
                self.sandbox_canary_max_memory_mb,
                self.sandbox_max_memory_mb,
            ),
            "cpu": (
                self.sandbox_canary_max_cpu_millis,
                self.sandbox_max_cpu_millis,
            ),
            "pids": (
                self.sandbox_canary_max_pids,
                self.sandbox_max_pids,
            ),
            "disk": (
                self.sandbox_canary_max_ephemeral_disk_mb,
                self.sandbox_max_ephemeral_disk_mb,
            ),
            "build_timeout": (
                self.sandbox_canary_max_build_seconds,
                self.sandbox_max_build_seconds,
            ),
            "run_timeout": (
                self.sandbox_canary_max_run_seconds,
                self.sandbox_max_run_seconds,
            ),
        }
        if any(value <= 0 or value > ceiling for value, ceiling in canary_limits.values()):
            raise ValueError("Canary limits must be positive and no broader than sandbox limits.")

        normalized_egress_hosts: list[str] = []
        for value in self.sandbox_canary_web_egress_allowed_hosts:
            candidate = value.strip().rstrip(".").casefold()
            if not candidate or "*" in candidate:
                raise ValueError("Canary web-egress hosts must be exact hostnames.")
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                pass
            else:
                raise ValueError("Canary web-egress hosts cannot be IP literals.")
            try:
                normalized = candidate.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Canary web-egress host is not valid IDNA.") from exc
            labels = normalized.split(".")
            if (
                len(normalized) > 253
                or len(labels) < 2
                or normalized.endswith(".local")
                or any(
                    not label
                    or len(label) > 63
                    or label[0] == "-"
                    or label[-1] == "-"
                    or not all(character.isalnum() or character == "-" for character in label)
                    for label in labels
                )
            ):
                raise ValueError("Canary web-egress host is outside the safe hostname contract.")
            normalized_egress_hosts.append(normalized)

        self.sandbox_canary_web_egress_allowed_hosts = sorted(set(normalized_egress_hosts))
        if len(self.sandbox_canary_web_egress_allowed_hosts) > 32:
            raise ValueError("Canary web-egress allowlist cannot exceed 32 hosts.")
        if self.sandbox_canary_web_egress_enabled:
            if not self.sandbox_execution_enabled or self.sandbox_activation_mode != "canary":
                raise ValueError("Web egress requires the sandbox master gate and canary mode.")
            if not self.sandbox_canary_web_egress_allowed_hosts:
                raise ValueError("Web egress requires at least one operator-allowlisted host.")

        if not 1 <= self.sandbox_canary_web_egress_max_requests <= 32:
            raise ValueError("Canary web-egress request limit is outside the safe range.")
        if not (1_024 <= self.sandbox_canary_web_egress_max_response_bytes <= 8_388_608):
            raise ValueError("Canary web-egress response limit is outside the safe range.")
        if not (
            self.sandbox_canary_web_egress_max_response_bytes
            <= self.sandbox_canary_web_egress_max_total_bytes
            <= 33_554_432
        ):
            raise ValueError("Canary web-egress total byte limit is outside the safe range.")
        if not 0 <= self.sandbox_canary_web_egress_max_redirects <= 5:
            raise ValueError("Canary web-egress redirect limit is outside the safe range.")
        if not (1 <= self.sandbox_canary_web_egress_connect_timeout_seconds <= 15):
            raise ValueError("Canary web-egress connect timeout is outside the safe range.")
        if not (1 <= self.sandbox_canary_web_egress_request_timeout_seconds <= 30):
            raise ValueError("Canary web-egress request timeout is outside the safe range.")

        if self.sandbox_canary_dataset_writes_enabled and (
            not self.sandbox_execution_enabled or self.sandbox_activation_mode != "canary"
        ):
            raise ValueError(
                "Dataset worker writes require the sandbox master gate and canary mode."
            )

        if self.sandbox_canary_key_value_store_enabled and (
            not self.sandbox_execution_enabled or self.sandbox_activation_mode != "canary"
        ):
            raise ValueError(
                "Key-Value Store worker access requires the sandbox master gate and canary mode."
            )

        if self.sandbox_canary_request_queue_enabled and (
            not self.sandbox_execution_enabled or self.sandbox_activation_mode != "canary"
        ):
            raise ValueError(
                "Request Queue worker access requires the sandbox master gate and canary mode."
            )

        if self.sandbox_canary_request_queue_http_enabled:
            if not self.sandbox_canary_request_queue_enabled:
                raise ValueError("Queue HTTP acquisition requires the Request Queue gate.")
            if not self.sandbox_canary_web_egress_enabled:
                raise ValueError("Queue HTTP acquisition requires the web-egress gate.")
            if not self.sandbox_canary_web_egress_allowed_hosts:
                raise ValueError("Queue HTTP acquisition requires an operator allowlist.")

        if self.sandbox_canary_request_queue_browser_enabled:
            if not self.sandbox_canary_request_queue_enabled:
                raise ValueError("Queue browser acquisition requires the Request Queue gate.")
            if (
                not self.sandbox_canary_browser_enabled
                or not self.sandbox_canary_browser_live_navigation_enabled
            ):
                raise ValueError("Queue browser acquisition requires live browser gates.")
            if (
                not self.sandbox_canary_web_egress_enabled
                or not self.sandbox_canary_web_egress_allowed_hosts
            ):
                raise ValueError("Queue browser acquisition requires allowlisted web egress.")

        if self.sandbox_canary_request_queue_dataset_enabled and (
            not self.sandbox_canary_request_queue_enabled
            or not self.sandbox_canary_dataset_writes_enabled
        ):
            raise ValueError("Queue Dataset composition requires Queue and Dataset gates.")

        if self.sandbox_canary_request_queue_key_value_store_enabled and (
            not self.sandbox_canary_request_queue_enabled
            or not self.sandbox_canary_key_value_store_enabled
        ):
            raise ValueError(
                "Queue Key-Value Store composition requires Queue and Key-Value Store gates."
            )

        if not 1 <= self.sandbox_canary_browser_max_pages <= 2:
            raise ValueError("Canary browser page limit is outside the safe range.")
        if not 1 <= self.sandbox_canary_browser_max_actions <= 16:
            raise ValueError("Canary browser action limit is outside the safe range.")
        if not 1 <= self.sandbox_canary_browser_navigation_timeout_seconds <= 30:
            raise ValueError("Canary browser navigation timeout is outside the safe range.")
        if not 65_536 <= self.sandbox_canary_browser_max_dom_bytes <= 4_194_304:
            raise ValueError("Canary browser DOM limit is outside the safe range.")
        if not (65_536 <= self.sandbox_canary_browser_max_screenshot_bytes <= 4_194_304):
            raise ValueError("Canary browser screenshot limit is outside the safe range.")
        if self.sandbox_canary_browser_live_navigation_enabled:
            if not self.sandbox_canary_browser_enabled:
                raise ValueError("Live browser navigation requires the browser canary gate.")
            if self.sandbox_canary_max_memory_mb > 256:
                raise ValueError("Live browser navigation memory cannot exceed 256 MiB.")
            if self.sandbox_canary_max_cpu_millis > 500:
                raise ValueError("Live browser navigation CPU cannot exceed 500m.")
            if self.sandbox_canary_max_pids > 64:
                raise ValueError("Live browser navigation PID limit cannot exceed 64.")
            if self.sandbox_canary_max_ephemeral_disk_mb > 256:
                raise ValueError("Live browser navigation disk cannot exceed 256 MiB.")
            if self.sandbox_canary_max_run_seconds > 120:
                raise ValueError("Live browser navigation timeout cannot exceed 120 seconds.")

        if self.sandbox_canary_browser_enabled:
            if not self.sandbox_execution_enabled or self.sandbox_activation_mode != "canary":
                raise ValueError(
                    "Browser execution requires the sandbox master gate and canary mode."
                )
            if not self.sandbox_canary_web_egress_enabled:
                raise ValueError("Browser execution requires the Phase 1J web-egress gate.")
            if not self.sandbox_canary_web_egress_allowed_hosts:
                raise ValueError("Browser execution requires an operator web-egress allowlist.")

        if not 60 <= self.storage_upload_grant_seconds <= 3600:
            raise ValueError("Storage upload grants must expire between 60 and 3600 seconds.")
        if not 30 <= self.storage_download_grant_seconds <= 900:
            raise ValueError("Storage download grants must expire between 30 and 900 seconds.")
        if not 1_048_576 <= self.source_archive_max_bytes <= 536_870_912:
            raise ValueError("Source archive compressed limit is outside the safe range.")
        if self.source_archive_max_expanded_bytes < self.source_archive_max_bytes:
            raise ValueError("Expanded source limit must be at least the compressed limit.")
        if not 1 <= self.source_archive_max_files <= 100_000:
            raise ValueError("Source archive file limit must be between 1 and 100000.")
        if not (
            1_048_576
            <= self.source_archive_max_single_file_bytes
            <= self.source_archive_max_expanded_bytes
        ):
            raise ValueError("Source archive per-file limit is outside the safe range.")
        if not 1.0 <= self.source_archive_max_compression_ratio <= 1000.0:
            raise ValueError("Source archive compression ratio limit is outside the safe range.")
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
                    "The local project-secret master key is prohibited outside local environments."
                )
            if not self.session_cookie_secure:
                raise ValueError("Secure session cookies are mandatory outside local environments")
            if (
                re.fullmatch(
                    rf"{self.env}-[a-z0-9][a-z0-9-]{{2,62}}",
                    self.deployment_id,
                )
                is None
            ):
                raise ValueError("Deployment ID must be environment-prefixed and stable.")
            if not self.project_secret_master_key_version.startswith(self.env + "-"):
                raise ValueError(
                    "Project-secret key version must match the deployment environment."
                )
            if not self.s3_bucket.startswith(f"rdc-{self.env}-"):
                raise ValueError("Object-storage bucket must be environment-prefixed.")
            parsed_origins = [urlsplit(origin) for origin in self.allowed_origins]
            if not parsed_origins or any(
                parsed.scheme != "https"
                or parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                for parsed in parsed_origins
            ):
                raise ValueError(
                    "Credential-free HTTPS origins are mandatory outside local environments."
                )
            parsed_storage_endpoints = [
                urlsplit(self.s3_endpoint),
                urlsplit(self.s3_public_endpoint),
            ]
            if any(
                parsed.scheme != "https"
                or parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                for parsed in parsed_storage_endpoints
            ):
                raise ValueError("Object-storage endpoints must be credential-free HTTPS.")
            local_defaults = {
                "database_url": self.database_url,
                "redis_url": self.redis_url,
                "s3_endpoint": self.s3_endpoint,
                "s3_access_key": self.s3_access_key,
                "s3_secret_key": self.s3_secret_key,
            }
            unsafe = [
                name
                for name, value in local_defaults.items()
                if "change-me" in value
                or value
                in {
                    "postgresql+asyncpg://rdc:rdc@localhost:5432/rdc",
                    "redis://localhost:6379/0",
                    "http://localhost:9000",
                    "rdc_local",
                    "rdc_local_only_change_me",
                }
            ]
            if unsafe:
                raise ValueError(
                    "Local infrastructure settings are prohibited outside "
                    "local environments: " + ", ".join(unsafe)
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
