import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from anm.db import Base
from anm.models import utcnow


class CapabilityDefinition(Base):
    __tablename__ = "capability_definitions"
    __table_args__ = (
        UniqueConstraint("capability_id", "version", name="uq_capability_id_version"),
        CheckConstraint("risk >= 0 AND risk <= 5", name="ck_capability_risk_range"),
        CheckConstraint(
            "lifecycle IN ('DRAFT','REVIEWED','ENABLED','DEPRECATED','DISABLED')",
            name="ck_capability_lifecycle",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    capability_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    risk: Mapped[int] = mapped_column(Integer, nullable=False)
    write: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reversible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(32), default="ENABLED", nullable=False)
    parameter_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    capability_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class ActionProposal(Base):
    __tablename__ = "action_proposals"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_action_confidence_range"),
        CheckConstraint(
            "state IN ('PROPOSED','AWAITING_APPROVAL','AUTHORIZED','DENIED','REJECTED')",
            name="ck_action_proposal_state",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0.0", nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    capability_definition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("capability_definitions.id"), nullable=False
    )
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    capability_version: Mapped[str] = mapped_column(String(32), nullable=False)
    capability_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    reason: Mapped[str] = mapped_column(String(4096), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id"), nullable=False
    )
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    requester_type: Mapped[str] = mapped_column(String(32), nullable=False)
    requester_id: Mapped[str] = mapped_column(String(256), nullable=False)
    requester_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="PROPOSED", nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(32), default="deny", nullable=False)
    policy_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    required_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    policy_source: Mapped[str] = mapped_column(String(32), default="fail_closed", nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), default="unknown", nullable=False)
    policy_input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class ActionApproval(Base):
    __tablename__ = "action_approvals"
    __table_args__ = (
        UniqueConstraint(
            "proposal_id",
            "approver_id",
            "proposal_digest",
            name="uq_approval_proposal_approver_digest",
        ),
        CheckConstraint("decision IN ('approve','reject')", name="ck_action_approval_decision"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    proposal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    capability_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    approver_id: Mapped[str] = mapped_column(String(256), nullable=False)
    approver_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    invalidated_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
