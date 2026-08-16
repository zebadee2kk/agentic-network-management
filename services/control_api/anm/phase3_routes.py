import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.auth import Principal, get_principal
from anm.db import get_db
from anm.models import ManagedScope, OutboxEvent
from anm.security_models import (
    AnomalyFinding,
    Baseline,
    CanonicalEvent,
    Incident,
    IncidentEvidence,
    IncidentTimeline,
    TelemetrySource,
)
from anm.security_schemas import (
    AnomalyFindingResponse,
    BaselineResponse,
    CanonicalEventEnvelope,
    IncidentEvidenceResponse,
    IncidentResponse,
    IncidentTimelineResponse,
    IncidentTransitionRequest,
    TelemetryBatchRequest,
    TelemetryBatchResponse,
    TelemetrySourceCreate,
    TelemetrySourceResponse,
)
from anm.services.audit import AuditService
from anm.services.security import (
    InvalidIncidentTransition,
    event_to_envelope,
    ingest_event,
    transition_incident,
)

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


@router.post(
    "/api/v1/telemetry/sources",
    response_model=TelemetrySourceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["telemetry"],
)
def create_telemetry_source(
    request: TelemetrySourceCreate,
    db: Db,
    principal: CurrentPrincipal,
) -> TelemetrySource:
    if request.source_type == "wazuh":
        if request.scope_id is None or not request.base_url or not request.secret_ref:
            raise HTTPException(
                status_code=400,
                detail="Wazuh telemetry source requires scope_id, base_url and secret_ref",
            )
        scope = db.get(ManagedScope, request.scope_id)
        if scope is None:
            raise HTTPException(status_code=404, detail="managed scope not found")
        if not scope.connector_cidrs:
            raise HTTPException(status_code=400, detail="managed scope has no connector_cidrs")
    elif request.base_url or request.secret_ref:
        raise HTTPException(
            status_code=400,
            detail="Suricata push source does not accept an outbound URL or credential",
        )

    source = TelemetrySource(**request.model_dump(), status="unknown")
    db.add(source)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="telemetry source already exists") from exc
    AuditService.record(
        db,
        principal=principal,
        action="telemetry_source.create",
        outcome="success",
        details={"source_id": str(source.id), "source_type": source.source_type},
    )
    db.commit()
    db.refresh(source)
    return source


@router.get(
    "/api/v1/telemetry/sources",
    response_model=list[TelemetrySourceResponse],
    tags=["telemetry"],
)
def list_telemetry_sources(db: Db, principal: CurrentPrincipal) -> list[TelemetrySource]:
    del principal
    return list(db.scalars(select(TelemetrySource).order_by(TelemetrySource.name)))


@router.post(
    "/api/v1/telemetry/sources/{source_id}/poll",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["telemetry"],
)
def request_wazuh_poll(
    source_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> dict[str, str]:
    source = db.get(TelemetrySource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="telemetry source not found")
    if source.source_type != "wazuh":
        raise HTTPException(status_code=400, detail="only Wazuh sources support polling")
    if source.scope_id is None:
        raise HTTPException(status_code=409, detail="Wazuh source has no managed scope")
    scope = db.get(ManagedScope, source.scope_id)
    if scope is None or not scope.enabled:
        raise HTTPException(status_code=409, detail="Wazuh managed scope is unavailable")
    if not scope.connector_cidrs:
        raise HTTPException(status_code=400, detail="managed scope has no connector_cidrs")
    if not source.base_url or not source.secret_ref:
        raise HTTPException(
            status_code=409,
            detail="Wazuh source is missing URL or secret reference",
        )

    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="telemetry.wazuh.poll_requested",
            message_id=message_id,
            payload={"message_id": message_id, "source_id": str(source.id)},
        )
    )
    AuditService.record(
        db,
        principal=principal,
        action="telemetry.wazuh.poll_requested",
        outcome="queued",
        details={"source_id": str(source.id), "message_id": message_id},
    )
    db.commit()
    return {"status": "queued", "message_id": message_id}


def _ingest_batch(
    db: Session,
    *,
    source_type: Literal["wazuh", "suricata"],
    request: TelemetryBatchRequest,
) -> TelemetryBatchResponse:
    configured = db.scalar(
        select(TelemetrySource).where(
            TelemetrySource.source_type == source_type,
            TelemetrySource.name == request.source_instance,
        )
    )
    if configured is None:
        raise HTTPException(status_code=404, detail="configured telemetry source not found")
    accepted = 0
    duplicates = 0
    event_ids: list[uuid.UUID] = []
    incident_ids: list[uuid.UUID] = []
    for payload in request.events:
        event, duplicate, incident = ingest_event(
            db,
            source=source_type,
            source_instance=request.source_instance,
            payload=payload,
        )
        event_ids.append(event.id)
        if duplicate:
            duplicates += 1
        else:
            accepted += 1
        if incident is not None and incident.id not in incident_ids:
            incident_ids.append(incident.id)
    configured.status = "healthy"
    db.flush()
    return TelemetryBatchResponse(
        accepted=accepted,
        duplicates=duplicates,
        event_ids=event_ids,
        incident_ids=incident_ids,
    )


@router.post(
    "/api/v1/telemetry/suricata/eve",
    response_model=TelemetryBatchResponse,
    tags=["telemetry"],
)
def ingest_suricata_eve(
    request: TelemetryBatchRequest,
    db: Db,
    principal: CurrentPrincipal,
) -> TelemetryBatchResponse:
    result = _ingest_batch(db, source_type="suricata", request=request)
    AuditService.record(
        db,
        principal=principal,
        action="telemetry.suricata.ingest",
        outcome="success",
        details={"accepted": result.accepted, "duplicates": result.duplicates},
    )
    db.commit()
    return result


@router.post(
    "/api/v1/telemetry/wazuh/events",
    response_model=TelemetryBatchResponse,
    tags=["telemetry"],
)
def ingest_wazuh_events(
    request: TelemetryBatchRequest,
    db: Db,
    principal: CurrentPrincipal,
) -> TelemetryBatchResponse:
    result = _ingest_batch(db, source_type="wazuh", request=request)
    AuditService.record(
        db,
        principal=principal,
        action="telemetry.wazuh.ingest",
        outcome="success",
        details={"accepted": result.accepted, "duplicates": result.duplicates},
    )
    db.commit()
    return result


@router.get(
    "/api/v1/events",
    response_model=list[CanonicalEventEnvelope],
    tags=["security-events"],
)
def list_events(
    db: Db,
    principal: CurrentPrincipal,
    asset_id: uuid.UUID | None = None,
    source: Literal["wazuh", "suricata"] | None = None,
    limit: int = Query(default=250, ge=1, le=1000),
) -> list[CanonicalEventEnvelope]:
    del principal
    statement = select(CanonicalEvent).order_by(CanonicalEvent.occurred_at.desc()).limit(limit)
    if asset_id is not None:
        statement = statement.where(CanonicalEvent.asset_id == asset_id)
    if source is not None:
        statement = statement.where(CanonicalEvent.source_connector == source)
    return [event_to_envelope(event) for event in db.scalars(statement)]


@router.get(
    "/api/v1/assets/{asset_id}/events",
    response_model=list[CanonicalEventEnvelope],
    tags=["security-events"],
)
def list_asset_events(
    asset_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=250, ge=1, le=1000),
) -> list[CanonicalEventEnvelope]:
    del principal
    events = db.scalars(
        select(CanonicalEvent)
        .where(CanonicalEvent.asset_id == asset_id)
        .order_by(CanonicalEvent.occurred_at.desc())
        .limit(limit)
    )
    return [event_to_envelope(event) for event in events]


@router.get(
    "/api/v1/incidents",
    response_model=list[IncidentResponse],
    tags=["incidents"],
)
def list_incidents(
    db: Db,
    principal: CurrentPrincipal,
    incident_state: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Incident]:
    del principal
    statement = select(Incident).order_by(Incident.last_activity_at.desc()).limit(limit)
    if incident_state:
        statement = statement.where(Incident.state == incident_state)
    return list(db.scalars(statement))


@router.get(
    "/api/v1/incidents/{incident_id}",
    response_model=IncidentResponse,
    tags=["incidents"],
)
def get_incident(
    incident_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> Incident:
    del principal
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.patch(
    "/api/v1/incidents/{incident_id}",
    response_model=IncidentResponse,
    tags=["incidents"],
)
def change_incident_state(
    incident_id: uuid.UUID,
    request: IncidentTransitionRequest,
    db: Db,
    principal: CurrentPrincipal,
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        transition_incident(
            db,
            incident=incident,
            new_state=request.state,
            reason=request.reason,
            actor_id=principal.subject,
        )
    except InvalidIncidentTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    AuditService.record(
        db,
        principal=principal,
        action="incident.transition",
        outcome=request.state,
        details={"incident_id": str(incident.id), "reason": request.reason},
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get(
    "/api/v1/incidents/{incident_id}/evidence",
    response_model=list[IncidentEvidenceResponse],
    tags=["incidents"],
)
def list_incident_evidence(
    incident_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[IncidentEvidence]:
    del principal
    return list(
        db.scalars(
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.added_at)
        )
    )


@router.get(
    "/api/v1/incidents/{incident_id}/timeline",
    response_model=list[IncidentTimelineResponse],
    tags=["incidents"],
)
def list_incident_timeline(
    incident_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[IncidentTimeline]:
    del principal
    return list(
        db.scalars(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident_id)
            .order_by(IncidentTimeline.occurred_at)
        )
    )


@router.get(
    "/api/v1/baselines",
    response_model=list[BaselineResponse],
    tags=["behaviour"],
)
def list_baselines(db: Db, principal: CurrentPrincipal) -> list[Baseline]:
    del principal
    return list(db.scalars(select(Baseline).order_by(Baseline.updated_at.desc()).limit(500)))


@router.get(
    "/api/v1/anomalies",
    response_model=list[AnomalyFindingResponse],
    tags=["behaviour"],
)
def list_anomalies(db: Db, principal: CurrentPrincipal) -> list[AnomalyFinding]:
    del principal
    return list(
        db.scalars(select(AnomalyFinding).order_by(AnomalyFinding.created_at.desc()).limit(500))
    )
