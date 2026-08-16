"""Capability registry, action proposals and durable approvals.

Revision ID: 0005_action_policy_approvals
Revises: 0004_ai_investigation
Create Date: 2026-08-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_action_policy_approvals"
down_revision: str | None = "0004_ai_investigation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capability_definitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("capability_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("write", sa.Boolean(), nullable=False),
        sa.Column("reversible", sa.Boolean(), nullable=False),
        sa.Column("lifecycle", sa.String(length=32), nullable=False),
        sa.Column("parameter_schema", sa.JSON(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("implementation_digest", sa.String(length=64), nullable=False),
        sa.Column("capability_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("risk >= 0 AND risk <= 5", name="ck_capability_risk_range"),
        sa.CheckConstraint(
            "lifecycle IN ('DRAFT','REVIEWED','ENABLED','DEPRECATED','DISABLED')",
            name="ck_capability_lifecycle",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("capability_id", "version", name="uq_capability_id_version"),
    )
    op.create_index(
        "ix_capability_lifecycle_risk",
        "capability_definitions",
        ["lifecycle", "risk"],
        unique=False,
    )

    op.create_table(
        "action_proposals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("capability_definition_id", sa.Uuid(), nullable=False),
        sa.Column("capability", sa.String(length=128), nullable=False),
        sa.Column("capability_version", sa.String(length=32), nullable=False),
        sa.Column("capability_digest", sa.String(length=64), nullable=False),
        sa.Column("implementation_digest", sa.String(length=64), nullable=False),
        sa.Column("target_asset_id", sa.Uuid(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(length=4096), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("requester_type", sa.String(length=32), nullable=False),
        sa.Column("requester_id", sa.String(length=256), nullable=False),
        sa.Column("requester_roles", sa.JSON(), nullable=False),
        sa.Column("proposal_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("policy_decision", sa.String(length=32), nullable=False),
        sa.Column("policy_reasons", sa.JSON(), nullable=False),
        sa.Column("required_roles", sa.JSON(), nullable=False),
        sa.Column("policy_source", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=128), nullable=False),
        sa.Column("policy_input_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_action_confidence_range",
        ),
        sa.CheckConstraint(
            "state IN ('PROPOSED','AWAITING_APPROVAL','AUTHORIZED','DENIED','REJECTED')",
            name="ck_action_proposal_state",
        ),
        sa.ForeignKeyConstraint(["capability_definition_id"], ["capability_definitions.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_action_proposals_state_created",
        "action_proposals",
        ["state", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_action_proposals_incident",
        "action_proposals",
        ["incident_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "action_approvals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("proposal_id", sa.Uuid(), nullable=False),
        sa.Column("proposal_digest", sa.String(length=64), nullable=False),
        sa.Column("capability_digest", sa.String(length=64), nullable=False),
        sa.Column("implementation_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=128), nullable=False),
        sa.Column("approver_id", sa.String(length=256), nullable=False),
        sa.Column("approver_roles", sa.JSON(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.String(length=2048), nullable=True),
        sa.Column("valid", sa.Boolean(), nullable=False),
        sa.Column("invalidated_reason", sa.String(length=256), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("decision IN ('approve','reject')", name="ck_action_approval_decision"),
        sa.ForeignKeyConstraint(["proposal_id"], ["action_proposals.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "proposal_id",
            "approver_id",
            "proposal_digest",
            name="uq_approval_proposal_approver_digest",
        ),
    )
    op.create_index(
        "ix_action_approvals_proposal_valid",
        "action_approvals",
        ["proposal_id", "valid"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_action_approvals_proposal_valid", table_name="action_approvals")
    op.drop_table("action_approvals")
    op.drop_index("ix_action_proposals_incident", table_name="action_proposals")
    op.drop_index("ix_action_proposals_state_created", table_name="action_proposals")
    op.drop_table("action_proposals")
    op.drop_index("ix_capability_lifecycle_risk", table_name="capability_definitions")
    op.drop_table("capability_definitions")
