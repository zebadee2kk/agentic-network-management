import ipaddress
import uuid
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from anm.schemas import FORBIDDEN_CONNECTOR_HOSTS


class TelemetrySourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    source_type: Literal["wazuh", "suricata"]
    scope_id: uuid.UUID | None = None
    base_url: str | None = Field(default=None, max_length=1024)
    secret_ref: str | None = Field(default=None, max_length=1024)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("openbao://"):
            raise ValueError("telemetry secret references must use openbao://")
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("telemetry base_url must use http:// or https:// with a host")
        if parsed.username or parsed.password:
            raise ValueError("telemetry base_url must not contain credentials")
        if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("telemetry base_url must be an origin without path/query/fragment")
        hostname = parsed.hostname.lower().rstrip(".")
        if hostname in FORBIDDEN_CONNECTOR_HOSTS or hostname.endswith(".localhost"):
            raise ValueError("telemetry base_url targets a protected platform host")
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
            raise ValueError("telemetry base_url targets a prohibited address class")
        return value.rstrip("/")


class TelemetrySourceResponse(TelemetrySourceCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cursor: dict[str, Any]
    status: str
    created_at: datetime
    updated_at: datetime


class TelemetryBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_instance: str = Field(min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class TelemetryBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    event_ids: list[uuid.UUID]
    incident_ids: list[uuid.UUID]


class EventSource(BaseModel):
    connector: str
    instance: str
    source_event_id: str | None = None


class CanonicalEventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID
    schema_version: Literal["1.0.0"] = "1.0.0"
    occurred_at: datetime
    ingested_at: datetime
    source: EventSource
    type: str = Field(pattern=r"^[a-z0-9_.-]{1,128}$")
    severity: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    asset_id: uuid.UUID | None = None
    site_id: uuid.UUID | None = None
    classifications: list[str] = Field(default_factory=list, max_length=32)
    summary: str = Field(min_length=1, max_length=2048)
    raw_reference: str | None = Field(default=None, max_length=2048)
    attributes: dict[str, Any] = Field(default_factory=dict)
    trust: Literal["untrusted_evidence"] = "untrusted_evidence"
    correlation_id: uuid.UUID | None = None
    causation_id: uuid.UUID | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    state: str
    severity: int
    confidence: float
    summary: str
    opened_at: datetime
    last_activity_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None


class IncidentTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal[
        "NEW",
        "TRIAGE",
        "INVESTIGATING",
        "ACTION_PROPOSED",
        "AWAITING_APPROVAL",
        "REMEDIATING",
        "VERIFYING",
        "RESOLVED",
        "CLOSED",
        "FALSE_POSITIVE",
    ]
    reason: str = Field(min_length=1, max_length=512)


class IncidentEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    event_id: uuid.UUID
    correlation_reasons: list[str]
    added_at: datetime


class IncidentTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    occurred_at: datetime
    entry_type: str
    summary: str
    evidence_event_id: uuid.UUID | None
    details: dict[str, Any]


class BaselineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: uuid.UUID
    feature_key: str
    sample_count: int
    mean: float
    m2: float
    algorithm_version: str
    updated_at: datetime


class AnomalyFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    feature_key: str
    sample_id: uuid.UUID
    score: float
    threshold: float
    reasons: list[str]
    created_at: datetime
