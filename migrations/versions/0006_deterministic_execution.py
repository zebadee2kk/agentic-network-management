"""Deterministic execution bindings, executions and rollback links.

Revision ID: 0006_deterministic_execution
Revises: 0005_action_policy_approvals
Create Date: 2026-08-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_deterministic_execution"
down_revision: str | None = "0005_action_policy_approvals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "execution_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("adapter", sa.String(length=64), nullable=False),
        sa.Column("endpoint", sa.String(length=1024), nullable=False),
        sa.Column("credential_reference_id", sa.Uuid(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "adapter IN ('ansible_windows','ansible_linux',"
            "'reference_endpoint','reference_firewall')",
            name="ck_execution_binding_adapter",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(
            ["credential_reference_id"],
            ["credential_references.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id",
            "adapter",
            name="uq_execution_binding_asset_adapter",
        ),
    )

    op.create_table(
        "action_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("proposal_id", sa.Uuid(), nullable=False),
        sa.Column("binding_id", sa.Uuid(), nullable=True),
        sa.Column("rollback_of_execution_id", sa.Uuid(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=128), nullable=False),
        sa.Column("capability_version", sa.String(length=32), nullable=False),
        sa.Column("target_asset_id", sa.Uuid(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("proposal_digest", sa.String(length=64), nullable=False),
        sa.Column("capability_digest", sa.String(length=64), nullable=False),
        sa.Column("implementation_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=128), nullable=False),
        sa.Column("target_criticality", sa.String(length=32), nullable=False),
        sa.Column("target_protected_roles", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("pre_state", sa.JSON(), nullable=False),
        sa.Column("executor_result", sa.JSON(), nullable=False),
        sa.Column("verification_result", sa.JSON(), nullable=False),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("error_detail", sa.String(length=512), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executor_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('QUEUED','RUNNING','EXECUTOR_SUCCEEDED','VERIFYING',"
            "'SUCCEEDED','FAILED','AMBIGUOUS','VERIFICATION_FAILED','CANCELLED')",
            name="ck_action_execution_state",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_action_execution_confidence_range",
        ),
        sa.ForeignKeyConstraint(["binding_id"], ["execution_bindings.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["proposal_id"], ["action_proposals.id"]),
        sa.ForeignKeyConstraint(
            ["rollback_of_execution_id"],
            ["action_executions.id"],
        ),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_action_execution_idempotency_key",
        ),
    )
    op.create_index(
        "ix_action_executions_state_queued",
        "action_executions",
        ["state", "queued_at"],
        unique=False,
    )
    op.create_index(
        "ix_action_executions_proposal",
        "action_executions",
        ["proposal_id", "queued_at"],
        unique=False,
    )

    op.create_table(
        "execution_rollback_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_execution_id", sa.Uuid(), nullable=False),
        sa.Column("rollback_proposal_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["rollback_proposal_id"],
            ["action_proposals.id"],
        ),
        sa.ForeignKeyConstraint(
            ["source_execution_id"],
            ["action_executions.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "rollback_proposal_id",
            name="uq_rollback_link_proposal",
        ),
        sa.UniqueConstraint(
            "source_execution_id",
            name="uq_rollback_link_source_execution",
        ),
    )


def downgrade() -> None:
    op.drop_table("execution_rollback_links")
    op.drop_index("ix_action_executions_proposal", table_name="action_executions")
    op.drop_index("ix_action_executions_state_queued", table_name="action_executions")
    op.drop_table("action_executions")
    op.drop_table("execution_bindings")
