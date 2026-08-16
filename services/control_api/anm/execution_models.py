import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Uuid,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from anm.db import Base
from anm.models import utcnow

EXECUTION_STATES = (
    "QUEUED",
    "RUNNING",
    "EXECUTOR_SUCCEEDED",
    "VERIFYING",
    "SUCCEEDED",
    "FAILED",
    "AMBIGUOUS",
    "VERIFICATION_FAILED",
    "CANCELLED",
)

EXECUTION_ADAPTERS = (
    "ansible_windows",
    "ansible_linux",
    "reference_endpoint",
    "reference_firewall",
)


class ExecutionBinding(Base):
    __tablename__ = "execution_bindings"
    __table_args__ = (
        UniqueConstraint("asset_id", "adapter", name="uq_execution_binding_asset_adapter"),
        CheckConstraint(
            "adapter IN ('ansible_windows','ansible_linux',"
            "'reference_endpoint','reference_firewall')",
            name="ck_execution_binding_adapter",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)
    credential_reference_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("credential_references.id"), nullable=True
    )
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class ActionExecution(Base):
    __tablename__ = "action_executions"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_action_execution_idempotency_key"),
        CheckConstraint(
            "state IN ('QUEUED','RUNNING','EXECUTOR_SUCCEEDED','VERIFYING',"
            "'SUCCEEDED','FAILED','AMBIGUOUS','VERIFICATION_FAILED','CANCELLED')",
            name="ck_action_execution_state",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    proposal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    binding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("execution_bindings.id"), nullable=True
    )
    rollback_of_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("action_executions.id"), nullable=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    capability_version: Mapped[str] = mapped_column(String(32), nullable=False)
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id"), nullable=False
    )
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    capability_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    target_criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    target_protected_roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="QUEUED", nullable=False)
    pre_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    executor_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    verification_result: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executor_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExecutionRollbackLink(Base):
    __tablename__ = "execution_rollback_links"
    __table_args__ = (
        UniqueConstraint("source_execution_id", name="uq_rollback_link_source_execution"),
        UniqueConstraint("rollback_proposal_id", name="uq_rollback_link_proposal"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("action_executions.id"), nullable=False
    )
    rollback_proposal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
