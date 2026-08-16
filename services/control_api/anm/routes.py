from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.auth import Principal, get_principal
from anm.config import Settings, get_settings
from anm.db import get_db
from anm.models import AuditEvent, CredentialReference
from anm.schemas import (
    AuditEventResponse,
    CredentialReferenceCreate,
    CredentialReferenceResponse,
    DependencyStatus,
    PolicyDecision,
    PolicyProbeRequest,
    PrincipalResponse,
    ReadinessResponse,
    TestEventRequest,
    TestEventResponse,
)
from anm.services.audit import AuditService
from anm.services.events import EventBus, apply_test_event_once
from anm.services.policy import PolicyClient
from anm.services.secrets import OpenBaoClient
from anm.state import get_event_bus, get_openbao_client, get_policy_client

router = APIRouter()

Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]
Policy = Annotated[PolicyClient, Depends(get_policy_client)]
Secrets = Annotated[OpenBaoClient, Depends(get_openbao_client)]
Bus = Annotated[EventBus, Depends(get_event_bus)]


@router.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", response_model=ReadinessResponse, tags=["health"])
async def ready(
    response: Response,
    db: Db,
    policy: Policy,
    secrets: Secrets,
    bus: Bus,
) -> ReadinessResponse:
    dependencies: dict[str, DependencyStatus] = {}

    try:
        db.execute(text("SELECT 1"))
        dependencies["postgres"] = DependencyStatus(status="ok")
    except Exception:
        dependencies["postgres"] = DependencyStatus(status="down", detail="database unavailable")

    dependencies["nats"] = DependencyStatus(
        status="ok" if bus.connected else "down",
        detail=None if bus.connected else "event bus disconnected",
    )

    opa_ok = await policy.health()
    dependencies["opa"] = DependencyStatus(
        status="ok" if opa_ok else "down",
        detail=None if opa_ok else "policy engine unavailable",
    )

    openbao_ok = await secrets.health()
    dependencies["openbao"] = DependencyStatus(
        status="ok" if openbao_ok else "down",
        detail=None if openbao_ok else "secrets service unavailable or sealed",
    )

    is_ready = all(item.status == "ok" for item in dependencies.values())
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(ready=is_ready, dependencies=dependencies)


@router.get("/api/v1/whoami", response_model=PrincipalResponse, tags=["system"])
def whoami(principal: CurrentPrincipal) -> PrincipalResponse:
    return PrincipalResponse(
        subject=principal.subject,
        roles=list(principal.roles),
        provider=principal.provider,
    )


@router.post("/api/v1/system/policy-probe", response_model=PolicyDecision, tags=["system"])
async def policy_probe(
    request: PolicyProbeRequest,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> PolicyDecision:
    if settings.is_production:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    decision = await policy.evaluate_action(request.model_dump())
    AuditService.record(
        db,
        principal=principal,
        action="system.policy_probe",
        outcome=decision.decision,
        details={"source": decision.source, "reasons": decision.reasons},
    )
    db.commit()
    return decision


@router.post(
    "/api/v1/credential-references",
    response_model=CredentialReferenceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["credentials"],
)
def create_credential_reference(
    request: CredentialReferenceCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> CredentialReference:
    item = CredentialReference(name=request.name, secret_ref=request.secret_ref)
    db.add(item)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="name already exists",
        ) from exc

    AuditService.record(
        db,
        principal=principal,
        action="credential_reference.create",
        outcome="success",
        details={"credential_reference_id": str(item.id), "name": item.name},
    )
    db.commit()
    db.refresh(item)
    return item


@router.get(
    "/api/v1/credential-references",
    response_model=list[CredentialReferenceResponse],
    tags=["credentials"],
)
def list_credential_references(db: Db, principal: CurrentPrincipal) -> list[CredentialReference]:
    del principal
    return list(db.scalars(select(CredentialReference).order_by(CredentialReference.name)))


@router.post("/api/v1/system/test-events", response_model=TestEventResponse, tags=["system"])
def apply_test_event(
    request: TestEventRequest,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
) -> TestEventResponse:
    if settings.is_production:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    accepted = apply_test_event_once(
        db,
        message_id=request.message_id,
        aggregate_key=request.aggregate_key,
    )
    AuditService.record(
        db,
        principal=principal,
        action="system.test_event",
        outcome="accepted" if accepted else "duplicate",
        details={"message_id": request.message_id, "aggregate_key": request.aggregate_key},
    )
    db.commit()
    return TestEventResponse(
        accepted=accepted,
        duplicate=not accepted,
        aggregate_key=request.aggregate_key,
    )


@router.get("/api/v1/audit", response_model=list[AuditEventResponse], tags=["audit"])
def list_audit_events(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = 100,
) -> list[AuditEvent]:
    del principal
    safe_limit = max(1, min(limit, 500))
    return list(
        db.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(safe_limit))
    )
