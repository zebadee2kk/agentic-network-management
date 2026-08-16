from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from anm.db import Base
from anm.models import Asset, ConnectorInstance, DiscoveryRun, ManagedScope
from anm.schemas import ObservationCreate, ObservationIdentifier
from anm.services import discovery
from anm.services.discovery import DiscoveryConfigurationError, execute_discovery_run


class FakeSecrets:
    def __init__(self) -> None:
        self.reads = 0

    async def read_kv_v2(self, reference: str) -> dict[str, str]:
        self.reads += 1
        assert reference.startswith("openbao://")
        return {"token": "fake-read-only-token"}


class FakeNetBoxConnector:
    def __init__(self, *, connector_instance_id, **kwargs) -> None:
        del kwargs
        self.connector_instance_id = connector_instance_id

    async def discover(self, cidrs: list[str]) -> list[ObservationCreate]:
        assert cidrs == ["10.20.0.0/24"]
        return [
            ObservationCreate(
                connector_instance_id=self.connector_instance_id,
                observed_at=datetime.now(UTC),
                attributes={
                    "display_name": "sw-01",
                    "management_ip": "10.20.0.10",
                    "asset_type": "switch",
                },
                identifiers=[
                    ObservationIdentifier(namespace="netbox", value="7"),
                    ObservationIdentifier(namespace="serial", value="SERIAL-7"),
                ],
            )
        ]


def make_run(connector_url: str, connector_cidrs: list[str]) -> tuple[Session, DiscoveryRun]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    scope = ManagedScope(
        name="lab",
        cidrs=["10.20.0.0/24"],
        connector_cidrs=connector_cidrs,
        allowed_connector_types=["netbox"],
        max_requests_per_minute=30,
    )
    db.add(scope)
    db.flush()
    connector = ConnectorInstance(
        name="lab-netbox",
        connector_type="netbox",
        base_url=connector_url,
        scope_id=scope.id,
        config={},
        secret_ref="openbao://secret/connectors/netbox/lab",
    )
    db.add(connector)
    db.flush()
    run = DiscoveryRun(
        scope_id=scope.id,
        connector_instance_id=connector.id,
        status="pending",
    )
    db.add(run)
    db.commit()
    return db, run


@pytest.mark.asyncio
async def test_allowed_endpoint_completes_read_only_discovery(monkeypatch) -> None:
    db, run = make_run("https://10.10.0.5", ["10.10.0.0/24"])
    secrets = FakeSecrets()
    monkeypatch.setattr(discovery, "NetBoxConnector", FakeNetBoxConnector)

    result = await execute_discovery_run(db, run, secrets)

    assert result.status == "succeeded"
    assert result.observations_count == 1
    assert result.reconciled_count == 1
    assert secrets.reads == 1
    assert db.scalar(select(func.count()).select_from(Asset)) == 1


@pytest.mark.asyncio
async def test_out_of_scope_endpoint_fails_before_secret_read() -> None:
    db, run = make_run("https://10.20.0.5", ["10.10.0.0/24"])
    secrets = FakeSecrets()

    with pytest.raises(DiscoveryConfigurationError):
        await execute_discovery_run(db, run, secrets)

    assert secrets.reads == 0
    assert db.scalar(select(func.count()).select_from(Asset)) == 0
