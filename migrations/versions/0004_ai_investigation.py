"""Read-only AI investigation layer tables.

Revision ID: 0004_ai_investigation
Revises: 0003_security_telemetry
Create Date: 2026-08-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_ai_investigation"
down_revision: str | None = "0003_security_telemetry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_providers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider_type", sa.String(length=32), nullable=False),
        sa.Column("locality", sa.String(length=32), nullable=False),
        sa.Column("base_url", sa.String(length=1024), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("secret_ref", sa.String(length=1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_model_provider_name"),
    )
    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("objective", sa.String(length=2048), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.String(length=4096), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("total_input_tokens", sa.Integer(), nullable=False),
        sa.Column("total_output_tokens", sa.Integer(), nullable=False),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=False),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("error_detail", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["provider_id"], ["model_providers.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "agent_steps",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_run_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("tool_allowlist", sa.JSON(), nullable=False),
        sa.Column("evidence_digest", sa.String(length=64), nullable=True),
        sa.Column("output", sa.JSON(), nullable=False),
        sa.Column("error_detail", sa.String(length=512), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["investigation_run_id"], ["investigation_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "investigation_run_id",
            "role",
            name="uq_investigation_role",
        ),
    )
    op.create_table(
        "model_invocations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("investigation_run_id", sa.Uuid(), nullable=False),
        sa.Column("agent_step_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_sha256", sa.String(length=64), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_step_id"], ["agent_steps.id"]),
        sa.ForeignKeyConstraint(["investigation_run_id"], ["investigation_runs.id"]),
        sa.ForeignKeyConstraint(["provider_id"], ["model_providers.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "incident_hypotheses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_run_id", sa.Uuid(), nullable=False),
        sa.Column("agent_role", sa.String(length=64), nullable=False),
        sa.Column("statement", sa.String(length=2048), nullable=False),
        sa.Column("rationale", sa.String(length=4096), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["investigation_run_id"], ["investigation_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("incident_hypotheses")
    op.drop_table("model_invocations")
    op.drop_table("agent_steps")
    op.drop_table("investigation_runs")
    op.drop_table("model_providers")
