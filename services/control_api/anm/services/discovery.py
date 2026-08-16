import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from anm.connectors import ConnectorError, LibreNMSConnector, NetBoxConnector
from anm.models import AssetObservation, ConnectorInstance, DiscoveryRun, ManagedScope, utcnow
from anm.schemas import ObservationCreate
from anm.services.reconciliation import rebuild_topology, reconcile_observation
from anm.services.secrets import OpenBaoClient


class DiscoveryConfigurationError(ValueError):
    pass


def persist_observation(db: Session, request: ObservationCreate) -> AssetObservation:
    connector = db.get(ConnectorInstance, request.connector_instance_id)
    if connector is None:
        raise DiscoveryConfigurationError("unknown connector instance")
    if (
        request.discovery_run_id is not None
        and db.get(DiscoveryRun, request.discovery_run_id) is None
    ):
        raise DiscoveryConfigurationError("unknown discovery run")
    observation = AssetObservation(
        connector_instance_id=request.connector_instance_id,
        discovery_run_id=request.discovery_run_id,
        observed_at=request.observed_at,
        kind=request.kind,
        attributes=request.attributes,
        identifiers=[item.model_dump() for item in request.identifiers],
        topology=[item.model_dump() for item in request.topology],
    )
    db.add(observation)
    db.flush()
    reconcile_observation(db, observation)
    return observation


def _connector_token(secret: dict[str, Any]) -> str:
    token = secret.get("token") or secret.get("api_token")
    if not isinstance(token, str) or not token.strip():
        raise DiscoveryConfigurationError("connector secret must contain token or api_token")
    return token.strip()


def _address_allowed(address: str, allowed_cidrs: list[str]) -> bool:
    candidate = ipaddress.ip_address(address)
    return any(candidate in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs)


async def validate_connector_endpoint(base_url: str, allowed_cidrs: list[str]) -> set[str]:
    """Resolve a configured connector origin and require every address to be explicitly allowed."""
    if not allowed_cidrs:
        raise DiscoveryConfigurationError(
            "managed scope must define connector_cidrs before discovery can use credentials"
        )
    hostname = urlsplit(base_url).hostname
    if not hostname:
        raise DiscoveryConfigurationError("connector base URL has no hostname")
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {str(literal)}
    except ValueError:
        try:
            results = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                None,
                0,
                socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise DiscoveryConfigurationError("connector hostname could not be resolved") from exc
        addresses = {str(item[4][0]) for item in results}
    if not addresses or not all(_address_allowed(address, allowed_cidrs) for address in addresses):
        raise DiscoveryConfigurationError(
            "connector endpoint resolved outside the managed connector_cidrs"
        )
    return addresses


async def execute_discovery_run(
    db: Session,
    run: DiscoveryRun,
    secrets: OpenBaoClient,
) -> DiscoveryRun:
    connector_instance = db.get(ConnectorInstance, run.connector_instance_id)
    scope = db.get(ManagedScope, run.scope_id)
    if connector_instance is None or scope is None:
        raise DiscoveryConfigurationError("discovery run references missing configuration")
    if connector_instance.scope_id != scope.id:
        raise DiscoveryConfigurationError("connector is not bound to the requested scope")
    if not scope.enabled:
        raise DiscoveryConfigurationError("managed scope is disabled")
    if (
        scope.allowed_connector_types
        and connector_instance.connector_type not in scope.allowed_connector_types
    ):
        raise DiscoveryConfigurationError("connector type is not allowed by managed scope")
    if not connector_instance.secret_ref:
        raise DiscoveryConfigurationError("connector requires an OpenBao secret reference")

    # Validate the endpoint before dereferencing any credential. This prevents a
    # configuration mistake from turning a secret reference into arbitrary egress.
    await validate_connector_endpoint(connector_instance.base_url, scope.connector_cidrs)

    run.status = "running"
    run.started_at = utcnow()
    connector_instance.status = "running"
    db.commit()

    try:
        secret = await secrets.read_kv_v2(connector_instance.secret_ref)
        token = _connector_token(secret)
        common = {
            "connector_instance_id": connector_instance.id,
            "base_url": connector_instance.base_url,
            "token": token,
            "config": connector_instance.config,
            "request_budget": scope.max_requests_per_minute,
        }
        if connector_instance.connector_type == "netbox":
            connector = NetBoxConnector(**common)
        elif connector_instance.connector_type == "librenms":
            connector = LibreNMSConnector(**common)
        else:
            raise DiscoveryConfigurationError("unsupported connector type")

        observations = await connector.discover(scope.cidrs)
        reconciled = 0
        conflicts = 0
        for request in observations:
            request.discovery_run_id = run.id
            observation = persist_observation(db, request)
            if observation.reconciled_asset_id is not None:
                reconciled += 1
            if observation.reconciliation_state == "conflict":
                conflicts += 1
        rebuild_topology(db)
        run.observations_count = len(observations)
        run.reconciled_count = reconciled
        run.conflicts_count = conflicts
        run.status = "succeeded"
        run.completed_at = utcnow()
        connector_instance.status = "healthy"
        db.commit()
        db.refresh(run)
        return run
    except ConnectorError as exc:
        db.rollback()
        current_run = db.get(DiscoveryRun, run.id)
        current_connector = db.get(ConnectorInstance, connector_instance.id)
        if current_run is None or current_connector is None:
            raise
        current_run.status = "failed"
        current_run.error_category = exc.category
        current_run.error_detail = exc.detail
        current_run.completed_at = utcnow()
        current_connector.status = "degraded"
        db.commit()
        return current_run
    except Exception:
        db.rollback()
        current_run = db.get(DiscoveryRun, run.id)
        current_connector = db.get(ConnectorInstance, connector_instance.id)
        if current_run is not None:
            current_run.status = "failed"
            current_run.error_category = "upstream_error"
            current_run.error_detail = "discovery failed; inspect redacted service logs"
            current_run.completed_at = utcnow()
        if current_connector is not None:
            current_connector.status = "degraded"
        db.commit()
        raise
