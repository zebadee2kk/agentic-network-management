import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.auth import Principal, get_principal
from anm.db import get_db
from anm.models import (
    Asset,
    AssetAddress,
    AssetIdentifier,
    AssetObservation,
    ConnectorInstance,
    DiscoveryRun,
    ManagedScope,
    ReconciliationCandidate,
    TopologyEdge,
)
from anm.schemas import (
    AssetAddressResponse,
    AssetDetailResponse,
    AssetIdentifierResponse,
    AssetResponse,
    ConnectorInstanceCreate,
    ConnectorInstanceResponse,
    DiscoveryRunCreate,
    DiscoveryRunResponse,
    ManagedScopeCreate,
    ManagedScopeResponse,
    ObservationResponse,
    ReconciliationCandidateResponse,
    ReconciliationResolutionRequest,
    TopologyEdgeResponse,
)
from anm.services.audit import AuditService
from anm.services.discovery import DiscoveryConfigurationError, execute_discovery_run
from anm.services.reconciliation import ImmutableIdentityConflict, rebuild_topology, resolve_candidate
from anm.services.secrets import OpenBaoClient
from anm.state import get_openbao_client

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
Secrets = Annotated[OpenBaoClient, Depends(get_openbao_client)]


@router.post(
    "/api/v1/scopes",
    response_model=ManagedScopeResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["discovery"],
)
def create_scope(
    request: ManagedScopeCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> ManagedScope:
    scope = ManagedScope(**request.model_dump())
    db.add(scope)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="scope name already exists") from exc
    AuditService.record(
        db,
        principal=principal,
        action="managed_scope.create",
        outcome="success",
        details={"scope_id": str(scope.id), "name": scope.name},
    )
    db.commit()
    db.refresh(scope)
    return scope


@router.get("/api/v1/scopes", response_model=list[ManagedScopeResponse], tags=["discovery"])
def list_scopes(db: Db, principal: CurrentPrincipal) -> list[ManagedScope]:
    del principal
    return list(db.scalars(select(ManagedScope).order_by(ManagedScope.name)))


@router.post(
    "/api/v1/connectors",
    response_model=ConnectorInstanceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["connectors"],
)
def create_connector(
    request: ConnectorInstanceCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> ConnectorInstance:
    scope = db.get(ManagedScope, request.scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="managed scope not found")
    if scope.allowed_connector_types and request.connector_type not in scope.allowed_connector_types:
        raise HTTPException(status_code=400, detail="connector type not allowed by scope")
    connector = ConnectorInstance(**request.model_dump(), status="unknown")
    db.add(connector)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="connector name already exists") from exc
    AuditService.record(
        db,
        principal=principal,
        action="connector.create",
        outcome="success",
        details={
            "connector_id": str(connector.id),
            "connector_type": connector.connector_type,
            "scope_id": str(connector.scope_id),
        },
    )
    db.commit()
    db.refresh(connector)
    return connector


@router.get(
    "/api/v1/connectors",
    response_model=list[ConnectorInstanceResponse],
    tags=["connectors"],
)
def list_connectors(db: Db, principal: CurrentPrincipal) -> list[ConnectorInstance]:
    del principal
    return list(db.scalars(select(ConnectorInstance).order_by(ConnectorInstance.name)))


@router.post(
    "/api/v1/discovery/runs",
    response_model=DiscoveryRunResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["discovery"],
)
async def run_discovery(
    request: DiscoveryRunCreate,
    db: Db,
    principal: CurrentPrincipal,
    secrets: Secrets,
) -> DiscoveryRun:
    connector = db.get(ConnectorInstance, request.connector_instance_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="connector not found")
    run = DiscoveryRun(
        scope_id=connector.scope_id,
        connector_instance_id=connector.id,
        status="pending",
    )
    db.add(run)
    db.flush()
    run_id = run.id
    AuditService.record(
        db,
        principal=principal,
        action="discovery.run",
        outcome="started",
        details={"run_id": str(run_id), "connector_id": str(connector.id)},
    )
    db.commit()
    try:
        result = await execute_discovery_run(db, run, secrets)
    except DiscoveryConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    AuditService.record(
        db,
        principal=principal,
        action="discovery.run",
        outcome=result.status,
        details={
            "run_id": str(run_id),
            "observations": result.observations_count,
            "reconciled": result.reconciled_count,
            "conflicts": result.conflicts_count,
            "error_category": result.error_category,
        },
    )
    db.commit()
    db.refresh(result)
    return result


@router.get(
    "/api/v1/discovery/runs/{run_id}",
    response_model=DiscoveryRunResponse,
    tags=["discovery"],
)
def get_discovery_run(
    run_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> DiscoveryRun:
    del principal
    run = db.get(DiscoveryRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="discovery run not found")
    return run


@router.get("/api/v1/assets", response_model=list[AssetResponse], tags=["assets"])
def list_assets(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = 250,
) -> list[Asset]:
    del principal
    safe_limit = max(1, min(limit, 1000))
    return list(db.scalars(select(Asset).order_by(Asset.display_name).limit(safe_limit)))


@router.get("/api/v1/assets/{asset_id}", response_model=AssetDetailResponse, tags=["assets"])
def get_asset(
    asset_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> AssetDetailResponse:
    del principal
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    identifiers = list(
        db.scalars(
            select(AssetIdentifier)
            .where(AssetIdentifier.asset_id == asset.id)
            .order_by(AssetIdentifier.namespace, AssetIdentifier.value)
        )
    )
    addresses = list(
        db.scalars(
            select(AssetAddress)
            .where(AssetAddress.asset_id == asset.id)
            .order_by(AssetAddress.address)
        )
    )
    return AssetDetailResponse(
        **AssetResponse.model_validate(asset).model_dump(),
        identifiers=[AssetIdentifierResponse.model_validate(item) for item in identifiers],
        addresses=[AssetAddressResponse.model_validate(item) for item in addresses],
    )


@router.get(
    "/api/v1/assets/{asset_id}/topology",
    response_model=list[TopologyEdgeResponse],
    tags=["topology"],
)
def get_asset_topology(
    asset_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[TopologyEdge]:
    del principal
    if db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return list(
        db.scalars(
            select(TopologyEdge).where(
                (TopologyEdge.source_asset_id == asset_id)
                | (TopologyEdge.target_asset_id == asset_id)
            )
        )
    )


@router.get(
    "/api/v1/observations/{observation_id}",
    response_model=ObservationResponse,
    tags=["discovery"],
)
def get_observation(
    observation_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> AssetObservation:
    del principal
    observation = db.get(AssetObservation, observation_id)
    if observation is None:
        raise HTTPException(status_code=404, detail="observation not found")
    return observation


@router.get(
    "/api/v1/reconciliation/candidates",
    response_model=list[ReconciliationCandidateResponse],
    tags=["reconciliation"],
)
def list_reconciliation_candidates(
    db: Db,
    principal: CurrentPrincipal,
    candidate_status: str | None = None,
) -> list[ReconciliationCandidate]:
    del principal
    statement = select(ReconciliationCandidate).order_by(ReconciliationCandidate.created_at.desc())
    if candidate_status:
        statement = statement.where(ReconciliationCandidate.status == candidate_status)
    return list(db.scalars(statement.limit(500)))


@router.post(
    "/api/v1/reconciliation/candidates/{candidate_id}/resolve",
    response_model=ReconciliationCandidateResponse,
    tags=["reconciliation"],
)
def resolve_reconciliation_candidate(
    candidate_id: uuid.UUID,
    request: ReconciliationResolutionRequest,
    db: Db,
    principal: CurrentPrincipal,
) -> ReconciliationCandidate:
    candidate = db.get(ReconciliationCandidate, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate not found")
    if candidate.status not in {"pending", "conflict"}:
        raise HTTPException(status_code=409, detail="candidate is already resolved")
    try:
        asset = resolve_candidate(db, candidate, request.decision)
        rebuild_topology(db)
    except ImmutableIdentityConflict as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="immutable identity conflict prevents attachment",
        ) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    AuditService.record(
        db,
        principal=principal,
        action="reconciliation.resolve",
        outcome=request.decision,
        details={
            "candidate_id": str(candidate.id),
            "observation_id": str(candidate.observation_id),
            "asset_id": str(asset.id) if asset else None,
        },
    )
    db.commit()
    db.refresh(candidate)
    return candidate
