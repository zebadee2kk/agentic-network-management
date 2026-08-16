import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.action_models import ActionApproval, ActionProposal, CapabilityDefinition
from anm.action_schemas import (
    ActionProposalCreate,
    ActionProposalResponse,
    ActionProposalRevision,
    ApprovalCreate,
    ApprovalQueueItem,
    ApprovalResponse,
    CapabilityResponse,
    ReevaluateResponse,
)
from anm.auth import Principal, get_principal
from anm.config import Settings, get_settings
from anm.db import get_db
from anm.services.actions import (
    ActionValidationError,
    create_action_proposal,
    record_approval,
    reevaluate_action_proposal,
    revise_action_proposal,
)
from anm.services.audit import AuditService
from anm.services.policy import PolicyClient
from anm.state import get_policy_client

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]
Policy = Annotated[PolicyClient, Depends(get_policy_client)]


def _proposal_or_404(db: Session, proposal_id: uuid.UUID) -> ActionProposal:
    proposal = db.get(ActionProposal, proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="action proposal not found")
    return proposal


@router.get(
    "/api/v1/capabilities",
    response_model=list[CapabilityResponse],
    tags=["actions"],
)
def list_capabilities(db: Db, principal: CurrentPrincipal) -> list[CapabilityDefinition]:
    del principal
    return list(
        db.scalars(
            select(CapabilityDefinition)
            .where(CapabilityDefinition.lifecycle == "ENABLED")
            .order_by(CapabilityDefinition.risk, CapabilityDefinition.capability_id)
        )
    )


@router.post(
    "/api/v1/action-proposals",
    response_model=ActionProposalResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["actions"],
)
async def create_proposal(
    request: ActionProposalCreate,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> ActionProposal:
    try:
        proposal = await create_action_proposal(
            db,
            request,
            principal=principal,
            settings=settings,
            policy=policy,
        )
    except ActionValidationError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    AuditService.record(
        db,
        principal=principal,
        action="action.proposal.create",
        outcome=proposal.policy_decision,
        details={
            "proposal_id": str(proposal.id),
            "proposal_digest": proposal.proposal_digest,
            "capability": proposal.capability,
            "capability_version": proposal.capability_version,
            "capability_digest": proposal.capability_digest,
            "implementation_digest": proposal.implementation_digest,
            "policy_version": proposal.policy_version,
            "policy_source": proposal.policy_source,
            "policy_reasons": proposal.policy_reasons,
            "state": proposal.state,
        },
    )
    db.commit()
    db.refresh(proposal)
    return proposal


@router.get(
    "/api/v1/action-proposals",
    response_model=list[ActionProposalResponse],
    tags=["actions"],
)
def list_proposals(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ActionProposal]:
    del principal
    return list(
        db.scalars(select(ActionProposal).order_by(ActionProposal.created_at.desc()).limit(limit))
    )


@router.get(
    "/api/v1/action-proposals/approval-queue",
    response_model=list[ApprovalQueueItem],
    tags=["actions"],
)
def approval_queue(
    db: Db,
    principal: CurrentPrincipal,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ApprovalQueueItem]:
    del principal
    proposals = list(
        db.scalars(
            select(ActionProposal)
            .where(ActionProposal.state == "AWAITING_APPROVAL")
            .order_by(ActionProposal.created_at)
            .limit(limit)
        )
    )
    items: list[ApprovalQueueItem] = []
    for proposal in proposals:
        approvals = list(
            db.scalars(
                select(ActionApproval)
                .where(ActionApproval.proposal_id == proposal.id)
                .order_by(ActionApproval.created_at)
            )
        )
        items.append(ApprovalQueueItem(proposal=proposal, approvals=approvals))
    return items


@router.get(
    "/api/v1/action-proposals/{proposal_id}",
    response_model=ActionProposalResponse,
    tags=["actions"],
)
def get_proposal(
    proposal_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> ActionProposal:
    del principal
    return _proposal_or_404(db, proposal_id)


@router.post(
    "/api/v1/action-proposals/{proposal_id}/revise",
    response_model=ReevaluateResponse,
    tags=["actions"],
)
async def revise_proposal(
    proposal_id: uuid.UUID,
    request: ActionProposalRevision,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> ReevaluateResponse:
    proposal = _proposal_or_404(db, proposal_id)
    old_digest = proposal.proposal_digest
    try:
        invalidated = await revise_action_proposal(
            db,
            proposal,
            request,
            settings=settings,
            policy=policy,
        )
    except ActionValidationError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    AuditService.record(
        db,
        principal=principal,
        action="action.proposal.revise",
        outcome=proposal.policy_decision,
        details={
            "proposal_id": str(proposal.id),
            "old_proposal_digest": old_digest,
            "new_proposal_digest": proposal.proposal_digest,
            "revision": proposal.revision,
            "approvals_invalidated": invalidated,
            "state": proposal.state,
        },
    )
    db.commit()
    db.refresh(proposal)
    return ReevaluateResponse(proposal=proposal, approvals_invalidated=invalidated)


@router.post(
    "/api/v1/action-proposals/{proposal_id}/reevaluate",
    response_model=ReevaluateResponse,
    tags=["actions"],
)
async def reevaluate_proposal(
    proposal_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> ReevaluateResponse:
    proposal = _proposal_or_404(db, proposal_id)
    old_digest = proposal.proposal_digest
    invalidated = await reevaluate_action_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
    )
    AuditService.record(
        db,
        principal=principal,
        action="action.proposal.reevaluate",
        outcome=proposal.policy_decision,
        details={
            "proposal_id": str(proposal.id),
            "old_proposal_digest": old_digest,
            "new_proposal_digest": proposal.proposal_digest,
            "approvals_invalidated": invalidated,
            "policy_version": proposal.policy_version,
            "state": proposal.state,
        },
    )
    db.commit()
    db.refresh(proposal)
    return ReevaluateResponse(proposal=proposal, approvals_invalidated=invalidated)


@router.get(
    "/api/v1/action-proposals/{proposal_id}/approvals",
    response_model=list[ApprovalResponse],
    tags=["actions"],
)
def list_approvals(
    proposal_id: uuid.UUID,
    db: Db,
    principal: CurrentPrincipal,
) -> list[ActionApproval]:
    del principal
    _proposal_or_404(db, proposal_id)
    return list(
        db.scalars(
            select(ActionApproval)
            .where(ActionApproval.proposal_id == proposal_id)
            .order_by(ActionApproval.created_at)
        )
    )


@router.post(
    "/api/v1/action-proposals/{proposal_id}/approvals",
    response_model=ApprovalResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["actions"],
)
async def create_approval(
    proposal_id: uuid.UUID,
    request: ApprovalCreate,
    db: Db,
    principal: CurrentPrincipal,
    settings: RuntimeSettings,
    policy: Policy,
) -> ActionApproval:
    proposal = _proposal_or_404(db, proposal_id)
    try:
        approval, invalidated = await record_approval(
            db,
            proposal,
            principal=principal,
            decision=request.decision,
            comment=request.comment,
            settings=settings,
            policy=policy,
        )
    except PermissionError as exc:
        AuditService.record(
            db,
            principal=principal,
            action="action.approval.blocked",
            outcome="forbidden",
            details={
                "proposal_id": str(proposal.id),
                "proposal_digest": proposal.proposal_digest,
                "policy_version": proposal.policy_version,
                "policy_source": proposal.policy_source,
                "policy_reasons": proposal.policy_reasons,
                "proposal_state": proposal.state,
            },
        )
        # The re-evaluation performed before the role check is security state.
        # Persist it so a policy change or fail-closed result cannot be rolled back
        # merely because this principal is not allowed to approve the new state.
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ActionValidationError as exc:
        AuditService.record(
            db,
            principal=principal,
            action="action.approval.blocked",
            outcome="not_awaiting_approval",
            details={
                "proposal_id": str(proposal.id),
                "proposal_digest": proposal.proposal_digest,
                "policy_version": proposal.policy_version,
                "policy_source": proposal.policy_source,
                "policy_reasons": proposal.policy_reasons,
                "proposal_state": proposal.state,
            },
        )
        # As above, preserve deny/policy-drift/capability-drift invalidation state.
        db.commit()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="this approver already decided on the current proposal digest",
        ) from exc

    AuditService.record(
        db,
        principal=principal,
        action="action.approval.record",
        outcome=request.decision,
        details={
            "proposal_id": str(proposal.id),
            "proposal_digest": proposal.proposal_digest,
            "approval_id": str(approval.id),
            "policy_version": proposal.policy_version,
            "required_roles": proposal.required_roles,
            "approvals_invalidated_before_decision": invalidated,
            "proposal_state": proposal.state,
        },
    )
    db.commit()
    db.refresh(approval)
    return approval
