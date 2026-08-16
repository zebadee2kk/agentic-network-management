import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CapabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    capability_id: str
    version: str
    description: str
    risk: int
    write: bool
    reversible: bool
    lifecycle: str
    parameter_schema: dict[str, Any]
    manifest_digest: str
    implementation_digest: str
    capability_digest: str
    created_at: datetime
    updated_at: datetime


class ActionProposalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability: str = Field(pattern=r"^[a-z0-9_.-]{1,128}$")
    capability_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    target_asset_id: uuid.UUID
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=64)
    reason: str = Field(min_length=1, max_length=4096)
    incident_id: uuid.UUID
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0, le=1)


class ActionProposalRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_asset_id: uuid.UUID | None = None
    parameters: dict[str, Any] | None = Field(default=None, max_length=64)
    reason: str | None = Field(default=None, min_length=1, max_length=4096)
    evidence_ids: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=128)
    confidence: float | None = Field(default=None, ge=0, le=1)


class ActionProposalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    schema_version: str
    revision: int
    capability: str
    capability_version: str
    capability_digest: str
    implementation_digest: str
    target_asset_id: uuid.UUID
    parameters: dict[str, Any]
    reason: str
    incident_id: uuid.UUID
    evidence_ids: list[str]
    confidence: float
    requester_type: str
    requester_id: str
    requester_roles: list[str]
    proposal_digest: str
    state: str
    policy_decision: str
    policy_reasons: list[str]
    required_roles: list[str]
    policy_source: str
    policy_version: str
    policy_input_digest: str
    policy_evaluated_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApprovalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    comment: str | None = Field(default=None, max_length=2048)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    proposal_id: uuid.UUID
    proposal_digest: str
    capability_digest: str
    implementation_digest: str
    policy_version: str
    approver_id: str
    approver_roles: list[str]
    decision: str
    comment: str | None
    valid: bool
    invalidated_reason: str | None
    invalidated_at: datetime | None
    created_at: datetime


class ReevaluateResponse(BaseModel):
    proposal: ActionProposalResponse
    approvals_invalidated: int


class ApprovalQueueItem(BaseModel):
    proposal: ActionProposalResponse
    approvals: list[ApprovalResponse]
