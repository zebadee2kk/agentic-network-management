import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
