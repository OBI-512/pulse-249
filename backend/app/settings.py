from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    redis_url: str = "redis://redis:6379/0"
    cors_origins: str = "http://localhost:3000"
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 900
    data_root: str = "/app/data"
    restore_points_enabled: bool = True
    restore_points_schedule_time: str = "00:00"
    restore_points_timezone: str = "UTC"
    restore_points_retention_days: int = 30
    enable_database_restore: bool = False
    restore_health_url: str = "http://backend:8000/api/health"
    integrations_enabled: bool = False
    integration_allow_insecure_http: bool = False
    integration_token_rate_limit_attempts: int = 10
    integration_token_rate_limit_window_seconds: int = 900
    integration_event_rate_limit_per_minute: int = 300
    remote_access_enabled: bool = False
    remote_access_ticket_ttl_seconds: int = 60
    remote_access_session_max_seconds: int = 1800
    remote_access_idle_timeout_seconds: int = 900
    remote_access_allowed_origins: str = "http://localhost:3000,http://localhost:8080"
    remote_access_web_allowed_ports: str = "80,443,8080,8443"
    remote_access_web_max_request_bytes: int = 33554432
    remote_access_web_rewrite_max_bytes: int = 8388608
    remote_access_gateway_tls_enabled: bool = False
    remote_access_gateway_tls_certificate_reference: str | None = None
    remote_access_gateway_tls_private_key_reference: str | None = None
    remote_access_gateway_external_tls_terminated: bool = False
    access_template_key_reference: str = "env://FTTW_ACCESS_TEMPLATE_KEY"
    telnet_access_enabled: bool = False
    configuration_artifact_key_reference: str = "env://FTTW_CONFIGURATION_ARTIFACT_KEY"
    configuration_artifact_max_bytes: int = 16777216
    configuration_artifact_public_base_url: str | None = None
    configuration_artifact_lease_ttl_seconds: int = 90
    configuration_artifact_lease_max_reads: int = 4
    configuration_artifact_edge_key_reference: str = "env://FTTW_CONFIGURATION_ARTIFACT_EDGE_HMAC_KEY"
    configuration_artifact_trusted_edge_peers: str = ""
    configuration_artifact_edge_attestation_max_age_seconds: int = 15
    configuration_command_timeout_seconds: int = 30
    configuration_session_max_output_bytes: int = 4194304
    configuration_queue_max_age_seconds: int = 1800
    configuration_batch_max_targets: int = Field(default=100, ge=1, le=100)
    configuration_batch_max_concurrency: int = Field(default=5, ge=1, le=25)
    fttw_env: str = "development"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
