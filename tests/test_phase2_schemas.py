import uuid

import pytest
from pydantic import ValidationError

from anm.schemas import ConnectorInstanceCreate, ManagedScopeCreate


def test_scope_normalizes_cidrs_and_bounds_request_budget() -> None:
    scope = ManagedScopeCreate(
        name="lab",
        cidrs=["10.0.0.4/24", "2001:db8::1/64"],
        connector_cidrs=["10.10.0.5/24"],
        allowed_connector_types=["netbox", "librenms"],
        max_requests_per_minute=60,
    )
    assert scope.cidrs == ["10.0.0.0/24", "2001:db8::/64"]
    assert scope.connector_cidrs == ["10.10.0.0/24"]

    with pytest.raises(ValidationError):
        ManagedScopeCreate(name="bad", cidrs=["not-a-network"])
    with pytest.raises(ValidationError):
        ManagedScopeCreate(name="bad-egress", connector_cidrs=["not-a-network"])
    with pytest.raises(ValidationError):
        ManagedScopeCreate(name="too-fast", max_requests_per_minute=601)


def test_connector_rejects_plaintext_secret_and_non_http_base_url() -> None:
    scope_id = uuid.uuid4()
    with pytest.raises(ValidationError):
        ConnectorInstanceCreate(
            name="bad-secret",
            connector_type="netbox",
            base_url="https://netbox.example",
            scope_id=scope_id,
            secret_ref="plaintext-token",
        )
    with pytest.raises(ValidationError):
        ConnectorInstanceCreate(
            name="bad-url",
            connector_type="librenms",
            base_url="file:///etc/passwd",
            scope_id=scope_id,
            secret_ref="openbao://connectors/librenms/lab",
        )


def test_connector_origin_rejects_platform_hosts_and_url_smuggling() -> None:
    scope_id = uuid.uuid4()
    invalid_urls = [
        "http://openbao:8200",
        "http://127.0.0.1:8000",
        "http://169.254.169.254",
        "https://user:password@netbox.example",
        "https://netbox.example/api/dcim/devices/",
        "https://netbox.example?next=http://openbao:8200",
        "https://netbox.example/#fragment",
    ]
    for index, base_url in enumerate(invalid_urls):
        with pytest.raises(ValidationError):
            ConnectorInstanceCreate(
                name=f"bad-origin-{index}",
                connector_type="netbox",
                base_url=base_url,
                scope_id=scope_id,
                secret_ref="openbao://connectors/netbox/lab",
            )
