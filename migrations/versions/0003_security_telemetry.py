"""Security telemetry, behaviour and incident engine tables.

Revision ID: 0003_security_telemetry
Revises: 0002_discovery_assets
Create Date: 2026-08-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_security_telemetry"
down_revision: str | None = "0002_discovery_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telemetry_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("scope_id", sa.Uuid(), nullable=True),
        sa.Column("base_url", sa.String(length=1024), nullable=True),
        sa.Column("secret_ref", sa.String(length=1024), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("cursor", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scope_id"], ["managed_scopes.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_type", "name", name="uq_telemetry_source_type_name"),
    )
    op.create_table(
        "canonical_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_connector", sa.String(length=64), nullable=False),
        sa.Column("source_instance", sa.String(length=128), nullable=False),
        sa.Column("source_event_id", sa.String(length=256), nullable=True),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("site_id", sa.Uuid(), nullable=True),
        sa.Column("classifications", sa.JSON(), nullable=False),
        sa.Column("summary", sa.String(length=2048), nullable=False),
        sa.Column("raw_reference", sa.String(length=2048), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("trust", sa.String(length=32), nullable=False),
        sa.Column("correlation_id", sa.Uuid(), nullable=True),
        sa.Column("causation_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key", name="uq_canonical_event_dedupe_key"),
    )
    op.create_index(
        "ix_canonical_event_asset_time",
        "canonical_events",
        ["asset_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_canonical_event_source_time",
        "canonical_events",
        ["source_connector", "source_instance", "occurred_at"],
        unique=False,
    )
    op.create_table(
        "raw_event_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("canonical_event_id", sa.Uuid(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_pointer", sa.String(length=2048), nullable=True),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["canonical_event_id"], ["canonical_events.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "feature_definitions",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "feature_samples",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("feature_key", sa.String(length=128), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_event_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["source_event_id"], ["canonical_events.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "baselines",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("feature_key", sa.String(length=128), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("mean", sa.Float(), nullable=False),
        sa.Column("m2", sa.Float(), nullable=False),
        sa.Column("algorithm_version", sa.String(length=16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "feature_key", name="uq_baseline_asset_feature"),
    )
    op.create_table(
        "anomaly_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("feature_key", sa.String(length=128), nullable=False),
        sa.Column("sample_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["sample_id"], ["feature_samples.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.String(length=2048), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "incident_assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "asset_id", name="uq_incident_asset"),
    )
    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("correlation_reasons", sa.JSON(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["canonical_events.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "event_id", name="uq_incident_event"),
    )
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entry_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.String(length=2048), nullable=False),
        sa.Column("evidence_event_id", sa.Uuid(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_event_id"], ["canonical_events.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("incident_timeline")
    op.drop_table("incident_evidence")
    op.drop_table("incident_assets")
    op.drop_table("incidents")
    op.drop_table("anomaly_findings")
    op.drop_table("baselines")
    op.drop_table("feature_samples")
    op.drop_table("feature_definitions")
    op.drop_table("raw_event_references")
    op.drop_index("ix_canonical_event_source_time", table_name="canonical_events")
    op.drop_index("ix_canonical_event_asset_time", table_name="canonical_events")
    op.drop_table("canonical_events")
    op.drop_table("telemetry_sources")
