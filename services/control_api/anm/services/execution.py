import hashlib
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.action_models import ActionProposal, CapabilityDefinition
from anm.action_schemas import ActionProposalCreate
from anm.auth import Principal
from anm.config import Settings
from anm.execution_models import (
    ActionExecution,
    ExecutionBinding,
    ExecutionRollbackLink,
)
from anm.models import Asset, CredentialReference, OutboxEvent, PlatformSetting, utcnow
from anm.services.actions import create_action_proposal, reevaluate_action_proposal
from anm.services.policy import PolicyClient

EXECUTION_CONTROL_KEY = "execution.control"
EXECUTABLE_ADAPTERS = {
    "ansible_windows",
    "ansible_linux",
    "reference_endpoint",
    "reference_firewall",
}
ADAPTERS_REQUIRING_SECRET = EXECUTABLE_ADAPTERS
DISPATCH_ROLES = {
    "platform_admin",
    "security_admin",
    "network_operator",
    "endpoint_operator",
}


class ExecutionValidationError(ValueError):
    pass


class ExecutionPermissionError(PermissionError):
    pass


def _idempotency_key(proposal: ActionProposal) -> str:
    material = (
        f"execute:{proposal.proposal_digest}:"
        f"{proposal.capability_digest}:{proposal.implementation_digest}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def execution_enabled(db: Session) -> tuple[bool, str, Any]:
    setting = db.get(PlatformSetting, EXECUTION_CONTROL_KEY)
    if setting is None:
        return False, "execution disabled until explicitly enabled", None
    return (
        bool(setting.value.get("enabled", False)),
        str(setting.value.get("reason", "unspecified")),
        setting.updated_at,
    )


def set_execution_enabled(db: Session, *, enabled: bool, reason: str) -> PlatformSetting:
    setting = db.get(PlatformSetting, EXECUTION_CONTROL_KEY)
    value = {"enabled": enabled, "reason": reason}
    if setting is None:
        setting = PlatformSetting(key=EXECUTION_CONTROL_KEY, value=value)
        db.add(setting)
    else:
        setting.value = value
        setting.updated_at = utcnow()
    db.flush()
    return setting


def ensure_execution_control(db: Session) -> None:
    if db.get(PlatformSetting, EXECUTION_CONTROL_KEY) is None:
        db.add(
            PlatformSetting(
                key=EXECUTION_CONTROL_KEY,
                value={
                    "enabled": False,
                    "reason": "safe default: operator has not enabled execution",
                },
            )
        )
        db.flush()


def require_dispatch_role(principal: Principal) -> None:
    if not DISPATCH_ROLES.intersection(principal.roles):
        raise ExecutionPermissionError("principal is not allowed to dispatch executions")


def _binding_for(
    db: Session,
    *,
    asset_id: uuid.UUID,
    adapter: str,
) -> ExecutionBinding:
    binding = db.scalar(
        select(ExecutionBinding).where(
            ExecutionBinding.asset_id == asset_id,
            ExecutionBinding.adapter == adapter,
            ExecutionBinding.enabled.is_(True),
        )
    )
    if binding is None:
        raise ExecutionValidationError("no enabled execution binding for target and adapter")
    return binding


def _validate_capability_prechecks(
    proposal: ActionProposal,
    capability: CapabilityDefinition,
    binding: ExecutionBinding,
) -> None:
    execution = capability.manifest.get("execution", {})
    adapter = execution.get("adapter")
    if adapter not in EXECUTABLE_ADAPTERS:
        raise ExecutionValidationError("capability has no Phase 6 executable adapter")
    if adapter != binding.adapter:
        raise ExecutionValidationError("execution binding does not match capability adapter")
    if adapter in ADAPTERS_REQUIRING_SECRET and binding.credential_reference_id is None:
        raise ExecutionValidationError("execution binding has no credential reference")

    if adapter in {"ansible_windows", "ansible_linux"}:
        service_name = proposal.parameters.get("service_name")
        allowed_services = binding.config.get("allowed_services", [])
        if not isinstance(service_name, str) or service_name not in allowed_services:
            raise ExecutionValidationError("service is not allowlisted by the execution binding")


def _rollback_source_for_proposal(db: Session, proposal_id: uuid.UUID) -> uuid.UUID | None:
    link = db.scalar(
        select(ExecutionRollbackLink).where(
            ExecutionRollbackLink.rollback_proposal_id == proposal_id
        )
    )
    return None if link is None else link.source_execution_id


async def create_execution(
    db: Session,
    proposal: ActionProposal,
    *,
    principal: Principal,
    settings: Settings,
    policy: PolicyClient,
) -> tuple[ActionExecution, bool]:
    require_dispatch_role(principal)
    enabled, reason, _updated_at = execution_enabled(db)
    if not enabled:
        raise ExecutionValidationError(f"execution kill switch is disabled: {reason}")

    await reevaluate_action_proposal(db, proposal, settings=settings, policy=policy)
    if proposal.state != "AUTHORIZED":
        raise ExecutionValidationError("proposal is no longer authorized")

    capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
    asset = db.get(Asset, proposal.target_asset_id)
    if capability is None or capability.lifecycle != "ENABLED":
        raise ExecutionValidationError("capability is unavailable")
    if asset is None or asset.status != "active":
        raise ExecutionValidationError("target asset is unavailable")
    if proposal.capability_digest != capability.capability_digest:
        raise ExecutionValidationError("capability digest changed before dispatch")
    if proposal.implementation_digest != capability.implementation_digest:
        raise ExecutionValidationError("implementation digest changed before dispatch")

    adapter = str(capability.manifest.get("execution", {}).get("adapter", ""))
    binding = _binding_for(db, asset_id=asset.id, adapter=adapter)
    _validate_capability_prechecks(proposal, capability, binding)
    if (
        binding.credential_reference_id is not None
        and db.get(CredentialReference, binding.credential_reference_id) is None
    ):
        raise ExecutionValidationError("credential reference no longer exists")

    key = _idempotency_key(proposal)
    existing = db.scalar(select(ActionExecution).where(ActionExecution.idempotency_key == key))
    if existing is not None:
        return existing, True

    execution = ActionExecution(
        proposal_id=proposal.id,
        binding_id=binding.id,
        rollback_of_execution_id=_rollback_source_for_proposal(db, proposal.id),
        idempotency_key=key,
        capability=proposal.capability,
        capability_version=proposal.capability_version,
        target_asset_id=proposal.target_asset_id,
        proposal_digest=proposal.proposal_digest,
        capability_digest=proposal.capability_digest,
        implementation_digest=proposal.implementation_digest,
        policy_version=proposal.policy_version,
        target_criticality=asset.criticality,
        target_protected_roles=sorted(asset.protected_roles),
        state="QUEUED",
    )
    try:
        with db.begin_nested():
            db.add(execution)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(ActionExecution).where(ActionExecution.idempotency_key == key)
        )
        if existing is None:
            raise
        return existing, True

    message_id = f"execution:{execution.idempotency_key}"
    db.add(
        OutboxEvent(
            subject="action.execution.requested",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "execution_id": str(execution.id),
            },
        )
    )
    db.flush()
    return execution, False


def claim_execution_for_run(db: Session, execution_id: uuid.UUID) -> ActionExecution | None:
    execution = db.scalar(
        select(ActionExecution)
        .where(ActionExecution.id == execution_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if execution is None or execution.state != "QUEUED":
        return None
    execution.state = "RUNNING"
    execution.started_at = utcnow()
    execution.error_category = None
    execution.error_detail = None
    db.flush()
    return execution


def mark_execution_cancelled(
    db: Session,
    execution: ActionExecution,
    *,
    category: str,
    detail: str,
) -> None:
    execution.state = "CANCELLED"
    execution.error_category = category
    execution.error_detail = detail[:512]
    execution.completed_at = utcnow()
    db.flush()


def mark_executor_result(
    db: Session,
    execution: ActionExecution,
    *,
    outcome: str,
    result: dict[str, Any] | None = None,
    pre_state: dict[str, Any] | None = None,
    category: str | None = None,
) -> None:
    execution.pre_state = pre_state or {}
    execution.executor_result = result or {}
    execution.executor_completed_at = utcnow()
    if outcome == "success":
        execution.state = "EXECUTOR_SUCCEEDED"
        verify_message_id = f"verify:{execution.id}"
        db.add(
            OutboxEvent(
                subject="action.execution.verify_requested",
                message_id=verify_message_id,
                payload={
                    "message_id": verify_message_id,
                    "execution_id": str(execution.id),
                },
            )
        )
    elif outcome == "ambiguous":
        execution.state = "AMBIGUOUS"
        execution.error_category = category or "ambiguous_remote_result"
        verify_message_id = f"verify:{execution.id}"
        db.add(
            OutboxEvent(
                subject="action.execution.verify_requested",
                message_id=verify_message_id,
                payload={
                    "message_id": verify_message_id,
                    "execution_id": str(execution.id),
                },
            )
        )
    else:
        execution.state = "FAILED"
        execution.error_category = category or "definite_execution_failure"
        execution.completed_at = utcnow()
    db.flush()


def recover_stale_running(db: Session, *, stale_seconds: int) -> int:
    cutoff = utcnow() - timedelta(seconds=stale_seconds)
    rows = list(
        db.scalars(
            select(ActionExecution).where(
                ActionExecution.state == "RUNNING",
                ActionExecution.started_at.is_not(None),
                ActionExecution.started_at < cutoff,
            )
        )
    )
    for execution in rows:
        mark_executor_result(
            db,
            execution,
            outcome="ambiguous",
            category="executor_recovered_stale_running",
        )
    return len(rows)


def claim_execution_for_verification(
    db: Session,
    execution_id: uuid.UUID,
) -> tuple[ActionExecution | None, str | None]:
    execution = db.scalar(
        select(ActionExecution)
        .where(ActionExecution.id == execution_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if execution is None:
        return None, None
    if execution.state not in {"EXECUTOR_SUCCEEDED", "AMBIGUOUS"}:
        return None, None
    previous = execution.state
    if previous == "EXECUTOR_SUCCEEDED":
        execution.state = "VERIFYING"
    db.flush()
    return execution, previous


def mark_verification_result(
    db: Session,
    execution: ActionExecution,
    *,
    previous_state: str,
    verified: bool,
    result: dict[str, Any],
) -> None:
    execution.verification_result = result
    execution.verified_at = utcnow()
    if verified:
        execution.state = "SUCCEEDED"
        execution.completed_at = utcnow()
        execution.error_category = None
        execution.error_detail = None
    elif previous_state == "AMBIGUOUS":
        execution.state = "AMBIGUOUS"
        execution.error_category = "ambiguous_verification_inconclusive"
    else:
        execution.state = "VERIFICATION_FAILED"
        execution.error_category = "independent_verification_failed"
        execution.completed_at = utcnow()
    db.flush()


def _rollback_parameters(source: ActionExecution, proposal: ActionProposal) -> dict[str, Any]:
    if source.capability == "endpoint.isolate":
        return {"reason_code": "rollback"}
    if source.capability == "firewall.block_ip":
        address = proposal.parameters.get("address")
        if not isinstance(address, str):
            raise ExecutionValidationError("source firewall execution has no bound address")
        return {"address": address, "reason_code": "rollback"}
    raise ExecutionValidationError("capability does not have a supported rollback mapping")


async def create_rollback_proposal(
    db: Session,
    source: ActionExecution,
    *,
    principal: Principal,
    settings: Settings,
    policy: PolicyClient,
) -> ActionProposal:
    if source.state not in {"SUCCEEDED", "VERIFICATION_FAILED", "AMBIGUOUS"}:
        raise ExecutionValidationError("execution is not eligible for rollback planning")
    source_proposal = db.get(ActionProposal, source.proposal_id)
    capability = db.scalar(
        select(CapabilityDefinition).where(
            CapabilityDefinition.capability_id == source.capability,
            CapabilityDefinition.version == source.capability_version,
        )
    )
    if source_proposal is None or capability is None:
        raise ExecutionValidationError("source execution context is unavailable")
    rollback = capability.manifest.get("rollback")
    if not isinstance(rollback, dict):
        raise ExecutionValidationError("capability is not reversible")
    rollback_capability = rollback.get("capability")
    rollback_version = rollback.get("version")
    if not isinstance(rollback_capability, str) or not isinstance(rollback_version, str):
        raise ExecutionValidationError("rollback manifest is invalid")

    existing_link = db.scalar(
        select(ExecutionRollbackLink).where(
            ExecutionRollbackLink.source_execution_id == source.id
        )
    )
    if existing_link is not None:
        existing = db.get(ActionProposal, existing_link.rollback_proposal_id)
        if existing is not None:
            return existing

    request = ActionProposalCreate(
        capability=rollback_capability,
        capability_version=rollback_version,
        target_asset_id=source.target_asset_id,
        parameters=_rollback_parameters(source, source_proposal),
        reason=f"Rollback of execution {source.id}",
        incident_id=source_proposal.incident_id,
        evidence_ids=[uuid.UUID(item) for item in source_proposal.evidence_ids],
        confidence=source_proposal.confidence,
    )
    proposal = await create_action_proposal(
        db,
        request,
        principal=principal,
        settings=settings,
        policy=policy,
    )
    db.add(
        ExecutionRollbackLink(
            source_execution_id=source.id,
            rollback_proposal_id=proposal.id,
        )
    )
    db.flush()
    return proposal
