import hashlib
import json
import uuid
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from anm.agent_contracts import tools_for_role
from anm.ai_models import (
    AgentStep,
    IncidentHypothesis,
    InvestigationRun,
    ModelInvocation,
    ModelProvider,
)
from anm.ai_schemas import InvestigationOutput
from anm.config import Settings
from anm.models import OutboxEvent, utcnow
from anm.security_models import CanonicalEvent, Incident, IncidentEvidence, IncidentTimeline
from anm.services.ai_security import (
    build_evidence_bundle,
    evidence_digest,
    model_messages,
    supervisor_bundle,
)
from anm.services.model_gateway import ModelGateway, ModelRequest

TERMINAL_RUN_STATES = {"SUCCEEDED", "FAILED"}


class InvestigationError(RuntimeError):
    def __init__(self, category: str, detail: str) -> None:
        super().__init__(detail)
        self.category = category
        self.detail = detail


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _current_month_spend(db: Session, provider_id: uuid.UUID) -> float:
    now = datetime.now(UTC)
    month_start = datetime(now.year, now.month, 1, tzinfo=UTC)
    value = db.scalar(
        select(func.coalesce(func.sum(ModelInvocation.estimated_cost_usd), 0.0)).where(
            ModelInvocation.provider_id == provider_id,
            ModelInvocation.created_at >= month_start,
        )
    )
    return float(value or 0.0)


def _estimate_cost(provider: ModelProvider, input_tokens: int, output_tokens: int) -> float:
    input_rate = float(provider.config.get("input_cost_per_million", 0.0))
    output_rate = float(provider.config.get("output_cost_per_million", 0.0))
    return ((input_tokens * input_rate) + (output_tokens * output_rate)) / 1_000_000


def _validate_evidence_references(
    output: InvestigationOutput,
    allowed_ids: set[uuid.UUID],
) -> None:
    referenced = {
        evidence_id
        for item in [*output.findings, *output.hypotheses]
        for evidence_id in item.evidence_ids
    }
    if not referenced.issubset(allowed_ids):
        raise InvestigationError(
            "invalid_evidence_reference",
            "model output referenced evidence outside the supplied bundle",
        )


def _specialist_roles(db: Session, incident_id: uuid.UUID) -> list[str]:
    roles = ["soc_analyst"]
    network_count = db.scalar(
        select(func.count())
        .select_from(CanonicalEvent)
        .join(IncidentEvidence, IncidentEvidence.event_id == CanonicalEvent.id)
        .where(
            IncidentEvidence.incident_id == incident_id,
            CanonicalEvent.event_type.like("network.%"),
        )
    )
    if int(network_count or 0) > 0:
        roles.append("network_analyst")
    return roles


async def _run_agent(
    db: Session,
    *,
    run: InvestigationRun,
    provider: ModelProvider,
    role: str,
    bundle: dict,
    allowed_evidence_ids: set[uuid.UUID],
    gateway: ModelGateway,
) -> InvestigationOutput:
    existing = db.scalar(
        select(AgentStep).where(
            AgentStep.investigation_run_id == run.id,
            AgentStep.role == role,
        )
    )
    if existing is not None and existing.status == "SUCCEEDED":
        return InvestigationOutput.model_validate(existing.output)
    step = existing or AgentStep(
        investigation_run_id=run.id,
        role=role,
        tool_allowlist=list(tools_for_role(role)),
    )
    if existing is None:
        db.add(step)
    step.status = "RUNNING"
    step.started_at = utcnow()
    step.error_detail = None
    step.evidence_digest = evidence_digest(bundle)
    db.flush()

    messages = model_messages(role, run.objective, bundle)
    request_serialized = json.dumps(messages, sort_keys=True, separators=(",", ":"))
    request_hash = _hash_text(request_serialized)

    monthly_budget = float(provider.config.get("monthly_budget_usd", 0.0))
    if monthly_budget > 0 and _current_month_spend(db, provider.id) >= monthly_budget:
        step.status = "FAILED"
        step.error_detail = "provider monthly budget exhausted"
        step.completed_at = utcnow()
        raise InvestigationError("budget_exhausted", step.error_detail)

    response = await gateway.generate(
        ModelRequest(
            provider_id=provider.id,
            agent_role=role,
            messages=messages,
            response_schema=InvestigationOutput.model_json_schema(),
            max_output_tokens=int(provider.config.get("max_output_tokens", 1600)),
        )
    )
    response_hash = _hash_text(response.content)
    cost = _estimate_cost(provider, response.input_tokens, response.output_tokens)
    invocation = ModelInvocation(
        investigation_run_id=run.id,
        agent_step_id=step.id,
        provider_id=provider.id,
        model=response.model,
        status="SUCCEEDED",
        request_sha256=request_hash,
        response_sha256=response_hash,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        estimated_cost_usd=cost,
        latency_ms=response.latency_ms,
    )
    db.add(invocation)

    try:
        output = InvestigationOutput.model_validate_json(response.content)
    except ValidationError as exc:
        invocation.status = "INVALID_OUTPUT"
        step.status = "FAILED"
        step.error_detail = "model output failed schema validation"
        step.completed_at = utcnow()
        raise InvestigationError("invalid_model_output", step.error_detail) from exc
    if output.role != role:
        invocation.status = "INVALID_OUTPUT"
        step.status = "FAILED"
        step.error_detail = "model output role did not match requested agent"
        step.completed_at = utcnow()
        raise InvestigationError("invalid_model_output", step.error_detail)
    try:
        _validate_evidence_references(output, allowed_evidence_ids)
    except InvestigationError:
        invocation.status = "INVALID_OUTPUT"
        step.status = "FAILED"
        step.error_detail = "model output referenced unavailable evidence"
        step.completed_at = utcnow()
        raise

    step.status = "SUCCEEDED"
    step.output = output.model_dump(mode="json")
    step.completed_at = utcnow()
    run.total_input_tokens += response.input_tokens
    run.total_output_tokens += response.output_tokens
    run.estimated_cost_usd += cost

    for hypothesis in output.hypotheses:
        db.add(
            IncidentHypothesis(
                incident_id=run.incident_id,
                investigation_run_id=run.id,
                agent_role=role,
                statement=hypothesis.statement,
                rationale=hypothesis.rationale,
                confidence=hypothesis.confidence,
                evidence_ids=[str(item) for item in hypothesis.evidence_ids],
            )
        )
    db.flush()
    return output


async def execute_investigation(
    db: Session,
    *,
    run: InvestigationRun,
    settings: Settings,
    gateway: ModelGateway,
) -> InvestigationRun:
    if run.status in TERMINAL_RUN_STATES:
        return run
    if not settings.ai_enabled:
        run.status = "FAILED"
        run.error_category = "ai_disabled"
        run.error_detail = "AI investigation is disabled"
        run.completed_at = utcnow()
        db.commit()
        return run

    provider = db.get(ModelProvider, run.provider_id)
    incident = db.get(Incident, run.incident_id)
    if provider is None or not provider.enabled:
        run.status = "FAILED"
        run.error_category = "provider_unavailable"
        run.error_detail = "configured model provider unavailable"
        run.completed_at = utcnow()
        db.commit()
        return run
    if incident is None:
        run.status = "FAILED"
        run.error_category = "incident_missing"
        run.error_detail = "investigation incident no longer exists"
        run.completed_at = utcnow()
        db.commit()
        return run

    run.status = "RUNNING"
    run.started_at = run.started_at or utcnow()
    db.commit()

    specialist_outputs: list[dict] = []
    allowed_union: set[uuid.UUID] = set()
    try:
        for role in _specialist_roles(db, incident.id):
            bundle, allowed = build_evidence_bundle(
                db,
                incident=incident,
                role=role,
                max_events=settings.ai_max_evidence_events,
                max_chars=settings.ai_max_context_chars,
            )
            output = await _run_agent(
                db,
                run=run,
                provider=provider,
                role=role,
                bundle=bundle,
                allowed_evidence_ids=allowed,
                gateway=gateway,
            )
            specialist_outputs.append(output.model_dump(mode="json"))
            allowed_union.update(allowed)
            db.commit()

        supervisor_input = supervisor_bundle(
            incident=incident,
            objective=run.objective,
            specialist_outputs=specialist_outputs,
        )
        supervisor = await _run_agent(
            db,
            run=run,
            provider=provider,
            role="supervisor",
            bundle=supervisor_input,
            allowed_evidence_ids=allowed_union,
            gateway=gateway,
        )
        run.status = "SUCCEEDED"
        run.summary = supervisor.summary
        run.confidence = supervisor.confidence
        run.completed_at = utcnow()
        run.error_category = None
        run.error_detail = None
        db.add(
            IncidentTimeline(
                incident_id=incident.id,
                occurred_at=utcnow(),
                entry_type="ai_investigation_completed",
                summary=supervisor.summary[:2048],
                details={
                    "investigation_run_id": str(run.id),
                    "provider_id": str(provider.id),
                    "model": provider.model,
                    "confidence": supervisor.confidence,
                    "state_changed": False,
                },
            )
        )
        message_id = str(uuid.uuid4())
        db.add(
            OutboxEvent(
                subject="incident.investigation.completed",
                message_id=message_id,
                payload={
                    "message_id": message_id,
                    "incident_id": str(incident.id),
                    "investigation_run_id": str(run.id),
                    "status": run.status,
                },
            )
        )
        db.commit()
        db.refresh(run)
        return run
    except InvestigationError as exc:
        # Validation/policy-style failures do not invalidate the SQL transaction.
        # Commit the failed step/invocation metadata so the causal chain is auditable.
        current = db.get(InvestigationRun, run.id)
        if current is None:
            raise
        current.status = "FAILED"
        current.error_category = exc.category
        current.error_detail = exc.detail[:512]
        current.completed_at = utcnow()
        db.commit()
        db.refresh(current)
        return current
    except Exception:
        db.rollback()
        current = db.get(InvestigationRun, run.id)
        if current is not None:
            current.status = "FAILED"
            current.error_category = "investigation_failed"
            current.error_detail = "AI investigation failed; inspect redacted service logs"
            current.completed_at = utcnow()
            db.commit()
            return current
        raise
