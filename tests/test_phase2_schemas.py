import uuid

import pytest
from pydantic import ValidationError

from anm.schemas import ConnectorInstanceCreate, ManagedScopeCreate


def test_scope_normalizes_cidrs_and_bounds_request_budget() -> None:
    scope = ManagedScopeCreate(
        name="lab",
        cidrs=["10.0.0.4/24", "2001:db8::1/64"],
        allowed_connector_types=["netbox", "librenms"],
        max_requests_per_minute=60,
    )
    assert scope.cidrs == ["10.0.0.0/24", "2001:db8::/64"]

    with pytest.raises(ValidationError):
        ManagedScopeCreate(name="bad", cidrs=["not-a-network"])
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
