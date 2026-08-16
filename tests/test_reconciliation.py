from datetime import UTC, datetime

from anm.db import Base
from anm.models import (
    Asset,
    AssetAddress,
    AssetIdentifier,
    ConnectorInstance,
    ManagedScope,
    ReconciliationCandidate,
    TopologyEdge,
)
from anm.schemas import ObservationCreate, ObservationIdentifier, TopologyHint
from anm.services.discovery import persist_observation
from anm.services.reconciliation import rebuild_topology
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session


def make_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def add_connector(db: Session, connector_type: str, name: str) -> ConnectorInstance:
    scope = db.scalar(select(ManagedScope).limit(1))
    if scope is None:
        scope = ManagedScope(
            name="lab",
            cidrs=["10.0.0.0/24"],
            allowed_connector_types=["netbox", "librenms"],
            max_requests_per_minute=30,
        )
        db.add(scope)
        db.flush()
    connector = ConnectorInstance(
        name=name,
        connector_type=connector_type,
        base_url=f"https://{name}.example",
        scope_id=scope.id,
        secret_ref=f"openbao://connectors/{connector_type}/{name}",
    )
    db.add(connector)
    db.flush()
    return connector


def observation(
    connector: ConnectorInstance,
    *,
    identifiers: list[ObservationIdentifier],
    ip: str | None = None,
    name: str = "device",
    protected_roles: list[str] | None = None,
    topology: list[TopologyHint] | None = None,
) -> ObservationCreate:
    return ObservationCreate(
        connector_instance_id=connector.id,
        observed_at=datetime.now(UTC),
        attributes={
            "display_name": name,
            "management_ip": ip,
            "asset_type": "network_device",
            "protected_roles": protected_roles or [],
        },
        identifiers=identifiers,
        topology=topology or [],
    )


def test_netbox_and_librenms_same_serial_resolve_to_one_asset() -> None:
    db = make_db()
    netbox = add_connector(db, "netbox", "netbox")
    librenms = add_connector(db, "librenms", "librenms")

    first = persist_observation(
        db,
        observation(
            netbox,
            identifiers=[
                ObservationIdentifier(namespace="netbox", value="7"),
                ObservationIdentifier(namespace="serial", value="SERIAL-1"),
            ],
            ip="10.0.0.10",
            name="sw-01",
        ),
    )
    second = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[
                ObservationIdentifier(namespace="librenms", value="42"),
                ObservationIdentifier(namespace="serial", value="SERIAL-1"),
            ],
            ip="10.0.0.10",
            name="sw-01.example",
        ),
    )
    db.commit()

    assert first.reconciled_asset_id == second.reconciled_asset_id
    assert db.scalar(select(func.count()).select_from(Asset)) == 1
    identifiers = {
        (item.namespace, item.value)
        for item in db.scalars(select(AssetIdentifier)).all()
    }
    assert ("netbox", "7") in identifiers
    assert ("librenms", "42") in identifiers


def test_conflicting_immutable_identifiers_never_auto_merge() -> None:
    db = make_db()
    netbox = add_connector(db, "netbox", "netbox")
    librenms = add_connector(db, "librenms", "librenms")

    persist_observation(
        db,
        observation(
            netbox,
            identifiers=[
                ObservationIdentifier(namespace="netbox", value="1"),
                ObservationIdentifier(namespace="serial", value="SER-A"),
                ObservationIdentifier(namespace="device_uuid", value="UUID-A"),
            ],
            name="asset-a",
        ),
    )
    persist_observation(
        db,
        observation(
            librenms,
            identifiers=[
                ObservationIdentifier(namespace="librenms", value="2"),
                ObservationIdentifier(namespace="serial", value="SER-B"),
                ObservationIdentifier(namespace="device_uuid", value="UUID-B"),
            ],
            name="asset-b",
        ),
    )
    conflict = persist_observation(
        db,
        observation(
            netbox,
            identifiers=[
                ObservationIdentifier(namespace="netbox", value="3"),
                ObservationIdentifier(namespace="serial", value="SER-A"),
                ObservationIdentifier(namespace="device_uuid", value="UUID-B"),
            ],
            name="ambiguous",
        ),
    )
    db.commit()

    assert conflict.reconciliation_state == "conflict"
    assert conflict.reconciled_asset_id is None
    assert db.scalar(select(func.count()).select_from(Asset)) == 2
    candidates = db.scalars(
        select(ReconciliationCandidate).where(
            ReconciliationCandidate.observation_id == conflict.id
        )
    ).all()
    assert len(candidates) == 2
    assert all(candidate.status == "conflict" for candidate in candidates)


def test_source_mapping_keeps_asset_stable_when_ip_changes() -> None:
    db = make_db()
    librenms = add_connector(db, "librenms", "librenms")
    first = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[ObservationIdentifier(namespace="librenms", value="10")],
            ip="10.0.0.10",
            name="router-1",
        ),
    )
    second = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[ObservationIdentifier(namespace="librenms", value="10")],
            ip="10.0.0.20",
            name="router-1",
        ),
    )
    db.commit()

    assert first.reconciled_asset_id == second.reconciled_asset_id
    assert db.scalar(select(func.count()).select_from(Asset)) == 1
    addresses = {item.address for item in db.scalars(select(AssetAddress)).all()}
    assert addresses == {"10.0.0.10", "10.0.0.20"}


def test_ip_only_cross_source_match_requires_review() -> None:
    db = make_db()
    netbox = add_connector(db, "netbox", "netbox")
    librenms = add_connector(db, "librenms", "librenms")
    persist_observation(
        db,
        observation(
            netbox,
            identifiers=[ObservationIdentifier(namespace="netbox", value="1")],
            ip="10.0.0.50",
            name="device-a",
        ),
    )
    pending = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[ObservationIdentifier(namespace="librenms", value="99")],
            ip="10.0.0.50",
            name="different-name",
        ),
    )
    db.commit()

    assert pending.reconciliation_state == "pending_review"
    assert pending.reconciled_asset_id is None
    candidate = db.scalar(
        select(ReconciliationCandidate).where(
            ReconciliationCandidate.observation_id == pending.id
        )
    )
    assert candidate is not None
    assert candidate.score == 0.35
    assert "ip_match_weak_evidence" in candidate.reasons


def test_protected_roles_are_preserved_and_union_across_sources() -> None:
    db = make_db()
    netbox = add_connector(db, "netbox", "netbox")
    librenms = add_connector(db, "librenms", "librenms")
    first = persist_observation(
        db,
        observation(
            netbox,
            identifiers=[
                ObservationIdentifier(namespace="netbox", value="8"),
                ObservationIdentifier(namespace="serial", value="PROTECTED-1"),
            ],
            protected_roles=["identity"],
        ),
    )
    persist_observation(
        db,
        observation(
            librenms,
            identifiers=[
                ObservationIdentifier(namespace="librenms", value="8"),
                ObservationIdentifier(namespace="serial", value="PROTECTED-1"),
            ],
            protected_roles=["backup"],
        ),
    )
    db.commit()

    asset = db.get(Asset, first.reconciled_asset_id)
    assert asset is not None
    assert asset.protected_roles == ["backup", "identity"]


def test_topology_hints_materialize_after_both_assets_exist() -> None:
    db = make_db()
    librenms = add_connector(db, "librenms", "librenms")
    parent = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[ObservationIdentifier(namespace="librenms", value="1")],
            name="parent",
        ),
    )
    child = persist_observation(
        db,
        observation(
            librenms,
            identifiers=[ObservationIdentifier(namespace="librenms", value="2")],
            name="child",
            topology=[
                TopologyHint(
                    relationship="depends_on",
                    target_namespace="librenms",
                    target_value="1",
                    confidence=0.9,
                )
            ],
        ),
    )
    assert rebuild_topology(db) == 1
    db.commit()

    edge = db.scalar(select(TopologyEdge))
    assert edge is not None
    assert edge.source_asset_id == child.reconciled_asset_id
    assert edge.target_asset_id == parent.reconciled_asset_id
    assert edge.relationship == "depends_on"
