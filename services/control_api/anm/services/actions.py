import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select
from sqlalchemy.orm import Session

from anm.action_models import ActionApproval, ActionProposal, CapabilityDefinition
from anm.action_schemas import ActionProposalCreate, ActionProposalRevision
from anm.auth import Principal
from anm.config import Settings
from anm.models import Asset, utcnow
from anm.policy_types import ActionPolicyDecision
from anm.security_models import Incident, IncidentEvidence
from anm.services.policy import PolicyClient

ROLE_COVERAGE = {
    "operator_approver": {"operator_approver", "security_approver", "platform_approver"},
    "security_approver": {"security_approver", "platform_approver"},
    "platform_approver": {"platform_approver"},
}


class ActionValidationError(ValueError):
    pass


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _capability(db: Session, capability_id: str, version: str) -> CapabilityDefinition:
    item = db.scalar(
        select(CapabilityDefinition).where(
            CapabilityDefinition.capability_id == capability_id,
            CapabilityDefinition.version == version,
        )
    )
    if item is None or item.lifecycle != "ENABLED":
        raise ActionValidationError("capability version is unavailable")
    return item


def _validate_parameters(capability: CapabilityDefinition, parameters: dict[str, Any]) -> None:
    validator = Draft202012Validator(
        capability.parameter_schema,
        format_checker=FormatChecker(),
    )
    if next(validator.iter_errors(parameters), None) is not None:
        raise ActionValidationError("parameters do not satisfy the capability schema")


def _validate_evidence(
    db: Session,
    incident_id: uuid.UUID,
    evidence_ids: list[uuid.UUID],
) -> None:
    supplied = {str(item) for item in evidence_ids}
    available = {
        str(item)
        for item in db.scalars(
            select(IncidentEvidence.event_id).where(IncidentEvidence.incident_id == incident_id)
        )
    }
    if not supplied.issubset(available):
        raise ActionValidationError("proposal references evidence outside the incident")


def _proposal_binding(proposal: ActionProposal) -> dict[str, Any]:
    return {
        "proposal_id": str(proposal.id),
        "schema_version": proposal.schema_version,
        "revision": proposal.revision,
        "capability": proposal.capability,
        "capability_version": proposal.capability_version,
        "capability_digest": proposal.capability_digest,
        "implementation_digest": proposal.implementation_digest,
        "target_asset_id": str(proposal.target_asset_id),
        "parameters": proposal.parameters,
        "reason": proposal.reason,
        "incident_id": str(proposal.incident_id),
        "evidence_ids": sorted(proposal.evidence_ids),
        "confidence": proposal.confidence,
        "requested_by": {
            "type": proposal.requester_type,
            "id": proposal.requester_id,
            "roles": sorted(proposal.requester_roles),
        },
    }


def _normative_payload(proposal: ActionProposal) -> dict[str, Any]:
    payload = _proposal_binding(proposal)
    payload["proposal_digest"] = proposal.proposal_digest
    payload["created_at"] = proposal.created_at.isoformat()
    return payload


def _validate_normative_schema(settings: Settings, proposal: ActionProposal) -> None:
    schema_path = Path(settings.schema_root) / "action-proposal.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    if next(validator.iter_errors(_normative_payload(proposal)), None) is not None:
        raise ActionValidationError("proposal failed normative schema validation")


def _policy_input(
    proposal: ActionProposal,
    capability: CapabilityDefinition,
    asset: Asset,
    incident: Incident,
    settings: Settings,
) -> dict[str, Any]:
    return {
        "action": {
            "capability": proposal.capability,
            "capability_version": proposal.capability_version,
            "risk": capability.risk,
            "write": capability.write,
            "reversible": capability.reversible,
            "capability_digest": proposal.capability_digest,
            "implementation_digest": proposal.implementation_digest,
            "proposal_digest": proposal.proposal_digest,
        },
        "target": {
            "asset_id": str(asset.id),
            "criticality": asset.criticality,
            "protected_roles": sorted(asset.protected_roles),
        },
        "incident": {
            "id": str(incident.id),
            "severity": incident.severity,
            "confidence": incident.confidence,
            "proposal_confidence": proposal.confidence,
        },
        "requester": {
            "type": proposal.requester_type,
            "id": proposal.requester_id,
            "roles": sorted(proposal.requester_roles),
        },
        "environment": {"autonomy_level": settings.autonomy_level},
    }


def _approval_matches(proposal: ActionProposal, approval: ActionApproval) -> bool:
    return (
        approval.valid
        and approval.proposal_digest == proposal.proposal_digest
        and approval.capability_digest == proposal.capability_digest
        and approval.implementation_digest == proposal.implementation_digest
        and approval.policy_version == proposal.policy_version
    )


def _role_is_covered(required_role: str, approver_roles: list[str]) -> bool:
    allowed = ROLE_COVERAGE.get(required_role, {required_role})
    return bool(allowed.intersection(approver_roles))


def _valid_approvals(db: Session, proposal: ActionProposal) -> list[ActionApproval]:
    return [
        item
        for item in db.scalars(
            select(ActionApproval).where(
                ActionApproval.proposal_id == proposal.id,
                ActionApproval.valid.is_(True),
            )
        )
        if _approval_matches(proposal, item)
    ]


def _approvals_satisfy(db: Session, proposal: ActionProposal) -> bool:
    approvals = [item for item in _valid_approvals(db, proposal) if item.decision == "approve"]
    if not proposal.required_roles:
        return True
    return all(
        any(_role_is_covered(role, approval.approver_roles) for approval in approvals)
        for role in proposal.required_roles
    )


def _has_valid_rejection(db: Session, proposal: ActionProposal) -> bool:
    return any(item.decision == "reject" for item in _valid_approvals(db, proposal))


def invalidate_approvals(db: Session, proposal: ActionProposal, reason: str) -> int:
    count = 0
    for approval in db.scalars(
        select(ActionApproval).where(
            ActionApproval.proposal_id == proposal.id,
            ActionApproval.valid.is_(True),
        )
    ):
        approval.valid = False
        approval.invalidated_reason = reason
        approval.invalidated_at = utcnow()
        count += 1
    return count


def _apply_policy_state(
    db: Session,
    proposal: ActionProposal,
    decision: ActionPolicyDecision,
) -> None:
    if decision.decision == "deny":
        proposal.state = "DENIED"
    elif decision.decision == "allow":
        proposal.state = "AUTHORIZED"
    elif _has_valid_rejection(db, proposal):
        proposal.state = "REJECTED"
    elif _approvals_satisfy(db, proposal):
        proposal.state = "AUTHORIZED"
    else:
        proposal.state = "AWAITING_APPROVAL"


async def evaluate_proposal(
    db: Session,
    proposal: ActionProposal,
    *,
    settings: Settings,
    policy: PolicyClient,
    invalidate_on_policy_change: bool = True,
) -> tuple[ActionPolicyDecision, int]:
    previous_binding = (
        proposal.policy_version,
        proposal.policy_decision,
        tuple(sorted(proposal.required_roles)),
        proposal.policy_input_digest if proposal.policy_evaluated_at is not None else None,
    )
    capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
    asset = db.get(Asset, proposal.target_asset_id)
    incident = db.get(Incident, proposal.incident_id)
    if capability is None or capability.lifecycle != "ENABLED":
        new_input_digest = _digest({"capability_unavailable": True})
        decision = ActionPolicyDecision(
            decision="deny",
            reasons=["capability_unavailable"],
            required_roles=[],
            source="fail_closed",
            policy_version="local-capability-gate",
        )
    elif asset is None or incident is None:
        new_input_digest = _digest({"context_unavailable": True})
        decision = ActionPolicyDecision(
            decision="deny",
            reasons=["proposal_context_unavailable"],
            required_roles=[],
            source="fail_closed",
            policy_version="local-context-gate",
        )
    else:
        input_document = _policy_input(proposal, capability, asset, incident, settings)
        new_input_digest = _digest(input_document)
        decision = await policy.evaluate_action(input_document)

    new_binding = (
        decision.policy_version,
        decision.decision,
        tuple(sorted(decision.required_roles)),
        new_input_digest,
    )
    invalidated = 0
    if invalidate_on_policy_change and proposal.policy_evaluated_at is not None:
        if previous_binding != new_binding:
            invalidated = invalidate_approvals(db, proposal, "policy_binding_changed")

    proposal.policy_input_digest = new_input_digest
    proposal.policy_decision = decision.decision
    proposal.policy_reasons = decision.reasons
    proposal.required_roles = decision.required_roles
    proposal.policy_source = decision.source
    proposal.policy_version = decision.policy_version
    proposal.policy_evaluated_at = utcnow()
    _apply_policy_state(db, proposal, decision)
    db.flush()
    return decision, invalidated


async def create_action_proposal(
    db: Session,
    request: ActionProposalCreate,
    *,
    principal: Principal,
    settings: Settings,
    policy: PolicyClient,
) -> ActionProposal:
    capability = _capability(db, request.capability, request.capability_version)
    asset = db.get(Asset, request.target_asset_id)
    incident = db.get(Incident, request.incident_id)
    if asset is None:
        raise ActionValidationError("target asset not found")
    if incident is None:
        raise ActionValidationError("incident not found")
    _validate_parameters(capability, request.parameters)
    _validate_evidence(db, request.incident_id, request.evidence_ids)

    now = utcnow()
    proposal = ActionProposal(
        id=uuid.uuid4(),
        capability_definition_id=capability.id,
        capability=capability.capability_id,
        capability_version=capability.version,
        capability_digest=capability.capability_digest,
        implementation_digest=capability.implementation_digest,
        target_asset_id=request.target_asset_id,
        parameters=request.parameters,
        reason=request.reason,
        incident_id=request.incident_id,
        evidence_ids=sorted(str(item) for item in request.evidence_ids),
        confidence=request.confidence,
        requester_type="user",
        requester_id=principal.subject,
        requester_roles=sorted(principal.roles),
        proposal_digest="0" * 64,
        policy_input_digest="0" * 64,
        created_at=now,
        updated_at=now,
    )
    proposal.proposal_digest = _digest(_proposal_binding(proposal))
    _validate_normative_schema(settings, proposal)
    db.add(proposal)
    db.flush()
    await evaluate_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
        invalidate_on_policy_change=False,
    )
    return proposal


async def revise_action_proposal(
    db: Session,
    proposal: ActionProposal,
    request: ActionProposalRevision,
    *,
    settings: Settings,
    policy: PolicyClient,
) -> int:
    capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
    if capability is None or capability.lifecycle != "ENABLED":
        raise ActionValidationError("capability version is unavailable")

    new_target = request.target_asset_id or proposal.target_asset_id
    new_parameters = request.parameters if request.parameters is not None else proposal.parameters
    new_reason = request.reason if request.reason is not None else proposal.reason
    new_evidence = (
        sorted(str(item) for item in request.evidence_ids)
        if request.evidence_ids is not None
        else proposal.evidence_ids
    )
    new_confidence = request.confidence if request.confidence is not None else proposal.confidence

    if db.get(Asset, new_target) is None:
        raise ActionValidationError("target asset not found")
    _validate_parameters(capability, new_parameters)
    _validate_evidence(db, proposal.incident_id, [uuid.UUID(item) for item in new_evidence])

    invalidated = invalidate_approvals(db, proposal, "proposal_revised")
    proposal.revision += 1
    proposal.target_asset_id = new_target
    proposal.parameters = new_parameters
    proposal.reason = new_reason
    proposal.evidence_ids = new_evidence
    proposal.confidence = new_confidence
    proposal.capability_digest = capability.capability_digest
    proposal.implementation_digest = capability.implementation_digest
    proposal.proposal_digest = _digest(_proposal_binding(proposal))
    proposal.state = "PROPOSED"
    _validate_normative_schema(settings, proposal)
    _decision, policy_invalidated = await evaluate_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
        invalidate_on_policy_change=False,
    )
    return invalidated + policy_invalidated


async def reevaluate_action_proposal(
    db: Session,
    proposal: ActionProposal,
    *,
    settings: Settings,
    policy: PolicyClient,
) -> int:
    capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
    invalidated = 0
    if capability is None or capability.lifecycle != "ENABLED":
        return (
            await evaluate_proposal(
                db,
                proposal,
                settings=settings,
                policy=policy,
            )
        )[1]

    digest_changed = (
        proposal.capability_digest != capability.capability_digest
        or proposal.implementation_digest != capability.implementation_digest
    )
    if digest_changed:
        invalidated += invalidate_approvals(db, proposal, "capability_digest_changed")
        proposal.revision += 1
        proposal.capability_digest = capability.capability_digest
        proposal.implementation_digest = capability.implementation_digest
        proposal.proposal_digest = _digest(_proposal_binding(proposal))
        proposal.state = "PROPOSED"
        _validate_normative_schema(settings, proposal)

    _decision, policy_invalidated = await evaluate_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
        invalidate_on_policy_change=not digest_changed,
    )
    return invalidated + policy_invalidated


async def record_approval(
    db: Session,
    proposal: ActionProposal,
    *,
    principal: Principal,
    decision: str,
    comment: str | None,
    settings: Settings,
    policy: PolicyClient,
) -> tuple[ActionApproval, int]:
    invalidated = await reevaluate_action_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
    )
    if proposal.policy_decision != "require_approval" or proposal.state == "DENIED":
        raise ActionValidationError("proposal is not awaiting human approval")
    if not proposal.required_roles:
        raise ActionValidationError("policy did not identify an approval role")
    if not any(_role_is_covered(role, list(principal.roles)) for role in proposal.required_roles):
        raise PermissionError("principal does not satisfy a required approver role")

    approval = ActionApproval(
        proposal_id=proposal.id,
        proposal_digest=proposal.proposal_digest,
        capability_digest=proposal.capability_digest,
        implementation_digest=proposal.implementation_digest,
        policy_version=proposal.policy_version,
        approver_id=principal.subject,
        approver_roles=sorted(principal.roles),
        decision=decision,
        comment=comment,
    )
    db.add(approval)
    db.flush()
    if decision == "reject":
        proposal.state = "REJECTED"
    elif _approvals_satisfy(db, proposal):
        proposal.state = "AUTHORIZED"
    else:
        proposal.state = "AWAITING_APPROVAL"
    db.flush()
    return approval, invalidated
