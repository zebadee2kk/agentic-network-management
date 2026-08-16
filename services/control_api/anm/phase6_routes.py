import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.action_models import ActionProposal
from anm.auth import Principal, get_principal
from anm.config import Settings, get_settings
from anm.db import get_db
from anm.execution_models import ActionExecution, ExecutionBinding
from anm.execution_schemas import (
    DispatchResponse,
    ExecutionBindingCreate,
    ExecutionBindingResponse,
    ExecutionControlResponse,
    ExecutionControlUpdate,
    ExecutionResponse,
    RollbackProposalResponse,
)
from anm.models import Asset, CredentialReference
from anm.services.audit import AuditService
from anm.services.execution import (
    ExecutionPermissionError,
    ExecutionValidationError,
    create_execution,
    create_rollback_proposal,
    execution_enabled,
    set_execution_enabled,
)
from anm.services.policy import PolicyClient
from anm.state import get_policy_client

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]
Policy = Annotated[PolicyClient, Depends(get_policy_client)]


def _platform_admin(principal: Principal) -> None:
    if "platform_admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="platform_admin role required")


def _execution_or_404(db: Session, execution_id: uuid.UUID) -> ActionExecution:
    execution = db.get(ActionExecution, execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="execution not found")
    return execution


def _validate_binding_endpoint(request: ExecutionBindingCreate) -> None:
    is_http = request.endpoint.startswith(("http://", "https://"))
    if request.adapter in {"reference_endpoint", "reference_firewall"} and not is_http:
        raise HTTPException(
            status_code=422,
            detail="reference adapters require an http(s) origin endpoint",
        )
    if request.adapter in {"ansible_windows", "ansible_linux"} and is_http:
        raise HTTPException(
            status_code=422,
            detail="Ansible adapters require a host or IP endpoint, not a URL",
        )


@router.get(
    "/api/v1/execution-control",
    response_model=ExecutionControlResponse,
    tags=["execution"],
)
def get_execution_control(db: Db, principal: CurrentPrincipal) -> ExecutionControlResponse:
    del principal
    enabled, reason, updated_at = execution_enabled(db)
    return ExecutionControlResponse(enabled=enabled, reason=reason, updated_at=updated_at)


@router.put(
    "/api/v1/execution-control",
    response_model=ExecutionControlResponse,
    tags=["execution"],
)
def update_execution_control(
    request: ExecutionControlUpdate,
    db: Db,
    principal: CurrentPrincipal,
) -> ExecutionControlResponse:
    _platform_admin(principal)
    setting = set_execution_enabled(db, enabled=request.enabled, reason=request.reason)
    AuditService.record(
        db,
        principal=principal,
        action="execution.kill_switch.update",
        outcome="enabled" if request.enabled else "disabled",
        details={"reason": request.reason},
    )
    db.commit()
    db.refresh(setting)
    return ExecutionControlResponse(
        enabled=request.enabled,
        reason=request.reason,
        updated_at=setting.updated_at,
    )


@router.post(
    "/api/v1/execution-bindings",
    response_model=ExecutionBindingResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["execution"],
)
def create_execution_binding(
    request: ExecutionBindingCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> ExecutionBinding:
    _platform_admin(principal)
    _validate_binding_endpoint(request)
    if db.get(Asset, request.asset_id) is None:
        raise HTTPException(status_code=404, detail="asset not found")
    if (
        request.credential_reference_id is not None
        and db.get(CredentialReference, request.credential_reference_id) is None
    ):
        raise HTTPException(status_code=404, detail="credential reference not found")
    binding = ExecutionBinding(**request.model_dump())
    db.add(binding)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="an execution binding already exists for this asset and adapter",
        ) from exc
    AuditService.record(
        db,
        principal=principal,
        action="execution.binding.create",
        outcome="success",
        details={
            "binding_id": str(binding.id),
            "asset_id": str(binding.asset_id),
            "adapter": binding.adapter,
            "credential_reference_id": (
                None
                if binding.credential_reference_id is None
                else str(binding.credential_reference_id)
            ),
        },
    )
    db.commit()
    db.refresh(binding)
    return binding


@router.get(
    "/api/v1/execution-bindings",
    response_model=list[ExecutionBindingResponse],
    tags=["execution"],
)
def list_execution_bindings(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ExecutionBinding]:
    del principal
    return list(
        db.scalars(
            select(ExecutionBinding).order_by(ExecutionBinding.created_at.desc()).limit(limit)
        )
    )


@router.post(
    "/api/v1/action-proposals/{proposal_id}/dispatch",
    response_model=DispatchResponse,
    tags=["execution"],
)
async def dispatch_proposal(
    proposal_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> DispatchResponse:
    proposal = db.get(ActionProposal, proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="action proposal not found")
    try:
        execution, duplicate = await create_execution(
            db,
            proposal,
            principal=principal,
            settings=settings,
            policy=policy,
        )
    except ExecutionPermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ExecutionValidationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    AuditService.record(
        db,
        principal=principal,
        action="execution.dispatch",
        outcome="duplicate" if duplicate else "queued",
        details={
            "execution_id": str(execution.id),
            "proposal_id": str(proposal.id),
            "idempotency_key": execution.idempotency_key,
            "capability": execution.capability,
            "proposal_digest": execution.proposal_digest,
            "capability_digest": execution.capability_digest,
            "implementation_digest": execution.implementation_digest,
            "policy_version": execution.policy_version,
        },
    )
    db.commit()
    db.refresh(execution)
    return DispatchResponse(
        execution=ExecutionResponse.model_validate(execution),
        duplicate=duplicate,
    )


@router.get(
    "/api/v1/executions",
    response_model=list[ExecutionResponse],
    tags=["execution"],
)
def list_executions(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ActionExecution]:
    del principal
    return list(
        db.scalars(
            select(ActionExecution).order_by(ActionExecution.queued_at.desc()).limit(limit)
        )
    )


@router.get(
    "/api/v1/executions/{execution_id}",
    response_model=ExecutionResponse,
    tags=["execution"],
)
def get_execution(
    execution_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> ActionExecution:
    del principal
    return _execution_or_404(db, execution_id)


@router.post(
    "/api/v1/executions/{execution_id}/rollback-proposal",
    response_model=RollbackProposalResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["execution"],
)
async def plan_rollback(
    execution_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> RollbackProposalResponse:
    execution = _execution_or_404(db, execution_id)
    try:
        proposal = await create_rollback_proposal(
            db,
            execution,
            principal=principal,
            settings=settings,
            policy=policy,
        )
    except (ExecutionValidationError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    AuditService.record(
        db,
        principal=principal,
        action="execution.rollback.plan",
        outcome=proposal.state,
        details={
            "source_execution_id": str(execution.id),
            "rollback_proposal_id": str(proposal.id),
            "rollback_capability": proposal.capability,
            "proposal_digest": proposal.proposal_digest,
        },
    )
    db.commit()
    db.refresh(proposal)
    return RollbackProposalResponse(
        source_execution_id=execution.id,
        rollback_proposal_id=proposal.id,
        capability=proposal.capability,
        state=proposal.state,
    )
