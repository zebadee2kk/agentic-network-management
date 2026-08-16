import ipaddress
import uuid
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXECUTION_ADAPTER_NAMES = {
    "ansible_windows",
    "ansible_linux",
    "reference_endpoint",
    "reference_firewall",
}
PROTECTED_EXECUTION_HOSTS = {
    "localhost",
    "control-api",
    "ui",
    "nats",
    "opa",
    "openbao",
    "postgres",
    "ai-worker",
    "model-relay",
}


class ExecutionBindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    adapter: Literal[
        "ansible_windows",
        "ansible_linux",
        "reference_endpoint",
        "reference_firewall",
    ]
    endpoint: str = Field(min_length=1, max_length=1024)
    credential_reference_id: uuid.UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if any(character.isspace() for character in value):
            raise ValueError("execution endpoint must not contain whitespace")
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("HTTP execution endpoint must be an http(s) origin")
            if parsed.username or parsed.password:
                raise ValueError("execution endpoint must not contain credentials")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("HTTP execution endpoint must not contain a path or query")
            hostname = parsed.hostname.lower().rstrip(".")
        else:
            hostname = value.lower().rstrip(".")
        if hostname in PROTECTED_EXECUTION_HOSTS or hostname.endswith(".localhost"):
            raise ValueError("execution endpoint targets a protected platform host")
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
            raise ValueError("execution endpoint targets a prohibited address class")
        return value.rstrip("/")


class ExecutionBindingResponse(ExecutionBindingCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ExecutionControlResponse(BaseModel):
    enabled: bool
    reason: str
    updated_at: datetime | None = None


class ExecutionControlUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    reason: str = Field(min_length=1, max_length=512)


class ExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    proposal_id: uuid.UUID
    binding_id: uuid.UUID | None
    rollback_of_execution_id: uuid.UUID | None
    idempotency_key: str
    capability: str
    capability_version: str
    target_asset_id: uuid.UUID
    parameters: dict[str, Any]
    incident_id: uuid.UUID
    evidence_ids: list[str]
    confidence: float
    proposal_digest: str
    capability_digest: str
    implementation_digest: str
    policy_version: str
    target_criticality: str
    target_protected_roles: list[str]
    state: str
    pre_state: dict[str, Any]
    executor_result: dict[str, Any]
    verification_result: dict[str, Any]
    error_category: str | None
    error_detail: str | None
    queued_at: datetime
    started_at: datetime | None
    executor_completed_at: datetime | None
    verified_at: datetime | None
    completed_at: datetime | None


class DispatchResponse(BaseModel):
    execution: ExecutionResponse
    duplicate: bool


class RollbackProposalResponse(BaseModel):
    source_execution_id: uuid.UUID
    rollback_proposal_id: uuid.UUID
    capability: str
    state: str
