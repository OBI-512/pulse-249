from dataclasses import dataclass, field


@dataclass
class DiscoveryContext:
    ip_address: str
    timeout_seconds: float = 2.0
    http_port: int | None = None
    https_port: int | None = None
    credential_reference: str | None = None
    snmp_version: str = "2c"
    snmp_port: int = 161
    snmp_community: str | None = None
    snmp_retries: int = 0
    snmp_v3_username: str | None = None
    snmp_v3_security_level: str = "noAuthNoPriv"
    snmp_v3_auth_protocol: str | None = None
    snmp_v3_auth_password: str | None = None
    snmp_v3_priv_protocol: str | None = None
    snmp_v3_priv_password: str | None = None
    snmp_v3_context_name: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class DiscoveryResult:
    success: bool
    method: str
    ip_address: str
    vendor: str | None = None
    model: str | None = None
    hostname: str | None = None
    serial_number: str | None = None
    management_protocol: str | None = None
    response_time_ms: float | None = None
    message: str | None = None
    raw_data: dict = field(default_factory=dict)
