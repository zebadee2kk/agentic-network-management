import ipaddress
import uuid
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

ASSET_TYPES = {
    "endpoint",
    "server",
    "network_device",
    "firewall",
    "router",
    "switch",
    "wireless_ap",
    "hypervisor",
    "virtual_machine",
    "iot",
    "printer",
    "service",
    "unknown",
}
PROTECTED_ROLES = {
    "identity",
    "backup",
    "core_network",
    "security_control",
    "platform_control",
    "hypervisor",
    "critical_application",
}
FORBIDDEN_CONNECTOR_HOSTS = {
    "localhost",
    "control-api",
    "ui",
    "nats",
    "opa",
    "openbao",
    "postgres",
}


class DependencyStatus(BaseModel):
    status: Literal["ok", "degraded", "down"]
    detail: str | None = None


class ReadinessResponse(BaseModel):
    ready: bool
    dependencies: dict[str, DependencyStatus]


class PrincipalResponse(BaseModel):
    subject: str
    roles: list[str]
    provider: str


class PolicyDecision(BaseModel):
    decision: Literal["deny", "require_approval", "allow"]
    reasons: list[str] = Field(default_factory=list)
    required_roles: list[str] = Field(default_factory=list)
    source: Literal["opa", "fail_closed"] = "opa"


class PolicyProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: dict[str, Any]
    target: dict[str, Any]
    incident: dict[str, Any]
    requester: dict[str, Any]
    environment: dict[str, Any]


class CredentialReferenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    secret_ref: str = Field(min_length=11, max_length=1024)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        if not value.startswith("openbao://"):
            raise ValueError("credential references must use the openbao:// scheme")
        return value


class CredentialReferenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    secret_ref: str
    created_at: datetime
    updated_at: datetime


class TestEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=128)
    aggregate_key: str = Field(min_length=1, max_length=128)


class TestEventResponse(BaseModel):
    accepted: bool
    duplicate: bool
    aggregate_key: str


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    occurred_at: datetime
    actor_type: str
    actor_id: str
    action: str
    outcome: str
    correlation_id: str | None
    details: dict[str, Any]


class ManagedScopeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    cidrs: list[str] = Field(default_factory=list, max_length=128)
    connector_cidrs: list[str] = Field(default_factory=list, max_length=64)
    allowed_connector_types: list[Literal["netbox", "librenms"]] = Field(default_factory=list)
    max_requests_per_minute: int = Field(default=30, ge=1, le=600)
    enabled: bool = True

    @field_validator("cidrs", "connector_cidrs")
    @classmethod
    def validate_cidrs(cls, values: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(value, strict=False)) for value in values]


class ManagedScopeResponse(ManagedScopeCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ConnectorInstanceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    connector_type: Literal["netbox", "librenms"]
    base_url: str = Field(min_length=8, max_length=1024)
    scope_id: uuid.UUID
    site_id: uuid.UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    secret_ref: str | None = Field(default=None, max_length=1024)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("openbao://"):
            raise ValueError("connector secret references must use openbao://")
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("connector base_url must use http:// or https:// with a host")
        if parsed.username or parsed.password:
            raise ValueError("connector base_url must not contain credentials")
        if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("connector base_url must be an origin without path, query, or fragment")
        hostname = parsed.hostname.lower().rstrip(".")
        if hostname in FORBIDDEN_CONNECTOR_HOSTS or hostname.endswith(".localhost"):
            raise ValueError("connector base_url targets a protected platform host")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address and (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("connector base_url targets a prohibited address class")
        return value.rstrip("/")


class ConnectorInstanceResponse(ConnectorInstanceCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    created_at: datetime
    updated_at: datetime


class ObservationIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=512)
    confidence: float = Field(default=1.0, ge=0, le=1)


class TopologyHint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship: Literal[
        "connected_to",
        "member_of_vlan",
        "routed_via",
        "hosted_on",
        "depends_on",
        "managed_by",
        "located_at",
    ]
    target_namespace: str = Field(min_length=1, max_length=128)
    target_value: str = Field(min_length=1, max_length=512)
    confidence: float = Field(default=1.0, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ObservationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector_instance_id: uuid.UUID
    discovery_run_id: uuid.UUID | None = None
    observed_at: datetime
    kind: Literal["device"] = "device"
    attributes: dict[str, Any] = Field(default_factory=dict)
    identifiers: list[ObservationIdentifier] = Field(default_factory=list, max_length=128)
    topology: list[TopologyHint] = Field(default_factory=list, max_length=128)


class ObservationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connector_instance_id: uuid.UUID
    discovery_run_id: uuid.UUID | None
    observed_at: datetime
    kind: str
    attributes: dict[str, Any]
    identifiers: list[dict[str, Any]]
    topology: list[dict[str, Any]]
    reconciliation_state: str
    reconciled_asset_id: uuid.UUID | None
    created_at: datetime


class AssetIdentifierResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    namespace: str
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime


class AssetAddressResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    address: str
    address_type: str
    source: str
    first_seen: datetime
    last_seen: datetime


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    schema_version: str
    display_name: str
    asset_type: str
    criticality: str
    status: str
    site_id: uuid.UUID | None
    network_zone: str | None
    protected_roles: list[str]
    created_at: datetime
    updated_at: datetime


class AssetDetailResponse(AssetResponse):
    identifiers: list[AssetIdentifierResponse]
    addresses: list[AssetAddressResponse]


class ReconciliationCandidateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    observation_id: uuid.UUID
    candidate_asset_id: uuid.UUID | None
    score: float
    reasons: list[str]
    status: str
    resolution: str | None
    created_at: datetime
    resolved_at: datetime | None


class ReconciliationResolutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["attach", "new_asset", "reject"]


class DiscoveryRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector_instance_id: uuid.UUID


class DiscoveryRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scope_id: uuid.UUID
    connector_instance_id: uuid.UUID
    status: str
    observations_count: int
    reconciled_count: int
    conflicts_count: int
    error_category: str | None
    error_detail: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class TopologyEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship: str
    source: str
    origin: str
    confidence: float
    observed_at: datetime
    expires_at: datetime | None
    edge_metadata: dict[str, Any]
