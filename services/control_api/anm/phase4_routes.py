import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.ai_models import AgentStep, IncidentHypothesis, InvestigationRun, ModelProvider
from anm.ai_schemas import (
    AgentStepResponse,
    AIStatusResponse,
    IncidentHypothesisResponse,
    InvestigationCreate,
    InvestigationRunResponse,
    ModelProviderCreate,
    ModelProviderResponse,
)
from anm.auth import Principal, get_principal
from anm.config import Settings, get_settings
from anm.db import get_db
from anm.models import OutboxEvent
from anm.security_models import Incident
from anm.services.audit import AuditService

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


def _require_platform_admin(principal: Principal) -> None:
    if "platform_admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="platform_admin role required")


@router.get("/api/v1/ai/status", response_model=AIStatusResponse, tags=["ai"])
def ai_status(db: Db, principal: CurrentPrincipal, settings: RuntimeSettings) -> AIStatusResponse:
    del principal
    count = db.scalar(
        select(func.count()).select_from(ModelProvider).where(ModelProvider.enabled.is_(True))
    )
    return AIStatusResponse(enabled=settings.ai_enabled, configured_providers=int(count or 0))


@router.post(
    "/api/v1/ai/providers",
    response_model=ModelProviderResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["ai"],
)
def create_model_provider(
    request: ModelProviderCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> ModelProvider:
    _require_platform_admin(principal)
    provider = ModelProvider(**request.model_dump())
    db.add(provider)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="model provider already exists") from exc
    AuditService.record(
        db,
        principal=principal,
        action="ai.provider.create",
        outcome="success",
        details={
            "provider_id": str(provider.id),
            "provider_type": provider.provider_type,
            "locality": provider.locality,
            "model": provider.model,
        },
    )
    db.commit()
    db.refresh(provider)
    return provider


@router.get(
    "/api/v1/ai/providers",
    response_model=list[ModelProviderResponse],
    tags=["ai"],
)
def list_model_providers(db: Db, principal: CurrentPrincipal) -> list[ModelProvider]:
    _require_platform_admin(principal)
    return list(db.scalars(select(ModelProvider).order_by(ModelProvider.name)))


@router.post(
    "/api/v1/incidents/{incident_id}/investigations",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["investigations"],
)
def create_investigation(
    incident_id: uuid.UUID,
    request: InvestigationCreate,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
) -> InvestigationRun:
    if not settings.ai_enabled:
        raise HTTPException(status_code=409, detail="AI investigation is disabled")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    provider = db.get(ModelProvider, request.provider_id)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="model provider unavailable")

    run = InvestigationRun(
        incident_id=incident.id,
        provider_id=provider.id,
        status="PENDING",
        objective=request.objective,
        requested_by=principal.subject,
    )
    db.add(run)
    db.flush()
    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="incident.investigation.requested",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "incident_id": str(incident.id),
                "investigation_run_id": str(run.id),
            },
        )
    )
    AuditService.record(
        db,
        principal=principal,
        action="ai.investigation.requested",
        outcome="queued",
        details={
            "incident_id": str(incident.id),
            "investigation_run_id": str(run.id),
            "provider_id": str(provider.id),
        },
    )
    db.commit()
    db.refresh(run)
    return run


@router.get(
    "/api/v1/investigations",
    response_model=list[InvestigationRunResponse],
    tags=["investigations"],
)
def list_investigations(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[InvestigationRun]:
    del principal
    return list(
        db.scalars(
            select(InvestigationRun)
            .order_by(InvestigationRun.created_at.desc())
            .limit(limit)
        )
    )


@router.get(
    "/api/v1/investigations/{run_id}",
    response_model=InvestigationRunResponse,
    tags=["investigations"],
)
def get_investigation(
    run_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> InvestigationRun:
    del principal
    run = db.get(InvestigationRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return run


@router.get(
    "/api/v1/investigations/{run_id}/steps",
    response_model=list[AgentStepResponse],
    tags=["investigations"],
)
def list_investigation_steps(
    run_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[AgentStep]:
    del principal
    return list(
        db.scalars(
            select(AgentStep)
            .where(AgentStep.investigation_run_id == run_id)
            .order_by(AgentStep.started_at)
        )
    )


@router.get(
    "/api/v1/incidents/{incident_id}/hypotheses",
    response_model=list[IncidentHypothesisResponse],
    tags=["investigations"],
)
def list_incident_hypotheses(
    incident_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[IncidentHypothesis]:
    del principal
    return list(
        db.scalars(
            select(IncidentHypothesis)
            .where(IncidentHypothesis.incident_id == incident_id)
            .order_by(IncidentHypothesis.created_at)
        )
    )
