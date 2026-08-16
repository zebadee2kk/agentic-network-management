import uuid

import httpx
import pytest

from anm.connectors.base import ConnectorError
from anm.connectors.librenms import LibreNMSConnector
from anm.connectors.netbox import NetBoxConnector
from anm.services.discovery import DiscoveryConfigurationError, validate_connector_endpoint


@pytest.mark.asyncio
async def test_netbox_normalizes_and_filters_to_managed_cidr() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/dcim/devices/"
        return httpx.Response(
            200,
            json={
                "count": 2,
                "results": [
                    {
                        "id": 7,
                        "name": "sw-01",
                        "serial": "ABC123",
                        "primary_ip4": {"address": "10.0.0.10/24"},
                        "status": {"value": "active"},
                        "role": {"slug": "switch"},
                    },
                    {
                        "id": 8,
                        "name": "outside",
                        "serial": "OUTSIDE",
                        "primary_ip4": {"address": "192.168.1.10/24"},
                        "status": {"value": "active"},
                        "role": {"slug": "switch"},
                    },
                ],
            },
        )

    connector = NetBoxConnector(
        connector_instance_id=uuid.uuid4(),
        base_url="https://netbox.example",
        token="not-logged",
        config={},
        request_budget=10,
        transport=httpx.MockTransport(handler),
    )
    observations = await connector.discover(["10.0.0.0/24"])

    assert len(observations) == 1
    assert observations[0].attributes["display_name"] == "sw-01"
    assert {(item.namespace, item.value) for item in observations[0].identifiers} >= {
        ("netbox", "7"),
        ("serial", "ABC123"),
    }
    assert not hasattr(connector, "execute")


@pytest.mark.asyncio
async def test_librenms_normalizes_parent_topology_hint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.headers["X-Auth-Token"] == "secret-token"
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "devices": [
                    {
                        "device_id": "42",
                        "hostname": "10.0.0.42",
                        "sysName": "edge-42.example",
                        "serial": "SER42",
                        "dependency_parent_id": "1,2",
                        "status": 1,
                    }
                ],
            },
        )

    connector = LibreNMSConnector(
        connector_instance_id=uuid.uuid4(),
        base_url="https://librenms.example",
        token="secret-token",
        config={},
        request_budget=10,
        transport=httpx.MockTransport(handler),
    )
    observations = await connector.discover(["10.0.0.0/24"])

    assert len(observations) == 1
    observation = observations[0]
    assert observation.attributes["management_ip"] == "10.0.0.42"
    assert {(hint.target_namespace, hint.target_value) for hint in observation.topology} == {
        ("librenms", "1"),
        ("librenms", "2"),
    }
    assert connector.capabilities == ("assets.discover", "assets.read")


@pytest.mark.asyncio
async def test_connector_request_budget_stops_pagination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "count": 2,
                "results": [
                    {
                        "id": 1,
                        "name": "one",
                        "primary_ip4": {"address": "10.0.0.1/24"},
                    }
                ],
            },
        )

    connector = NetBoxConnector(
        connector_instance_id=uuid.uuid4(),
        base_url="https://netbox.example",
        token="secret-token",
        config={"page_size": 1},
        request_budget=1,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ConnectorError) as exc:
        await connector.discover(["10.0.0.0/24"])
    assert exc.value.category == "rate_limited"


@pytest.mark.asyncio
async def test_authentication_error_does_not_echo_token() -> None:
    token = "never-echo-this-token"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": f"bad token {token}"})

    connector = LibreNMSConnector(
        connector_instance_id=uuid.uuid4(),
        base_url="https://librenms.example",
        token=token,
        config={},
        request_budget=10,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ConnectorError) as exc:
        await connector.discover([])
    assert exc.value.category == "authentication_failed"
    assert token not in exc.value.detail


@pytest.mark.asyncio
async def test_connector_endpoint_must_be_inside_explicit_egress_cidr() -> None:
    addresses = await validate_connector_endpoint(
        "https://10.10.0.5",
        ["10.10.0.0/24"],
    )
    assert addresses == {"10.10.0.5"}

    with pytest.raises(DiscoveryConfigurationError):
        await validate_connector_endpoint("https://10.20.0.5", ["10.10.0.0/24"])
    with pytest.raises(DiscoveryConfigurationError):
        await validate_connector_endpoint("https://10.10.0.5", [])
