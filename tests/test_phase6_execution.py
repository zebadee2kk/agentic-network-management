import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from anm.action_models import ActionProposal, CapabilityDefinition
from anm.action_schemas import ActionProposalCreate
from anm.auth import Principal
from anm.config import Settings
from anm.db import Base
from anm.execution_models import ActionExecution, ExecutionBinding
from anm.models import Asset, AssetAddress, AssetIdentifier, CredentialReference, OutboxEvent
from anm.policy_types import ActionPolicyDecision
from anm.security_models import Incident
from anm.services.actions import create_action_proposal, record_approval
from anm.services.capabilities import sync_builtin_capabilities
from anm.services.execution import (
    ExecutionValidationError,
    claim_execution_for_run,
    claim_execution_for_verification,
    create_execution,
    create_rollback_proposal,
    ensure_execution_control,
    mark_executor_result,
    mark_verification_result,
    recover_stale_running,
    set_execution_enabled,
)
from anm.services.security import ingest_event


class StablePolicy:
    async def evaluate_action(self, input_document: dict) -> ActionPolicyDecision:
        del input_document
        return ActionPolicyDecision(
            decision="require_approval",
            reasons=["test_policy"],
            required_roles=["operator_approver"],
            source="opa",
            policy_version="phase6-test-policy-v1",
        )


class DenyPolicy:
    async def evaluate_action(self, input_document: dict) -> ActionPolicyDecision:
        del input_document
        return ActionPolicyDecision(
            decision="deny",
            reasons=["test_fail_closed_dispatch"],
            required_roles=[],
            source="opa",
            policy_version="phase6-test-policy-v2",
        )


def operator() -> Principal:
    return Principal(
        subject="operator@example.test",
        roles=("platform_admin",),
        provider="test",
    )


def approver() -> Principal:
    return Principal(
        subject="approver@example.test",
        roles=("platform_approver",),
        provider="test",
    )


def make_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    sync_builtin_capabilities(db)
    ensure_execution_control(db)
    db.commit()
    return db


def seed_incident(db: Session) -> tuple[Asset, Incident, uuid.UUID]:
    asset = Asset(
        display_name="LAB-ENDPOINT-01",
        asset_type="endpoint",
        protected_roles=[],
    )
    db.add(asset)
    db.flush()
    db.add(AssetIdentifier(asset_id=asset.id, namespace="wazuh", value="601"))
    db.add(AssetAddress(asset_id=asset.id, address="10.30.40.50", source="netbox"))
    event, _duplicate, incident = ingest_event(
        db,
        source="wazuh",
        source_instance="wazuh-lab",
        payload={
            "_id": "phase6-wazuh-1",
            "_source": {
                "timestamp": datetime.now(UTC).isoformat(),
                "agent": {"id": "601", "name": "LAB-ENDPOINT-01", "ip": "10.30.40.50"},
                "rule": {
                    "id": "99006",
                    "level": 12,
                    "description": "Containment candidate",
                    "groups": ["windows", "security"],
                },
            },
        },
    )
    assert incident is not None
    db.commit()
    return asset, incident, event.id


async def authorized_endpoint_proposal(
    db: Session,
    asset: Asset,
    incident: Incident,
    evidence_id: uuid.UUID,
) -> ActionProposal:
    policy = StablePolicy()
    settings = Settings(autonomy_level=2)
    proposal = await create_action_proposal(
        db,
        ActionProposalCreate(
            capability="endpoint.isolate",
            capability_version="1.0.0",
            target_asset_id=asset.id,
            parameters={"reason_code": "suspected_compromise", "duration_minutes": 60},
            reason="Contain endpoint during investigation.",
            incident_id=incident.id,
            evidence_ids=[evidence_id],
            confidence=0.97,
        ),
        principal=operator(),
        settings=settings,
        policy=policy,
    )
    await record_approval(
        db,
        proposal,
        principal=approver(),
        decision="approve",
        comment="Approved for Phase 6 test containment.",
        settings=settings,
        policy=policy,
    )
    db.commit()
    assert proposal.state == "AUTHORIZED"
    return proposal


def bind_reference_endpoint(db: Session, asset: Asset) -> ExecutionBinding:
    credential = CredentialReference(
        name=f"endpoint-{asset.id}",
        secret_ref="openbao://secret/phase6/endpoint",
    )
    db.add(credential)
    db.flush()
    binding = ExecutionBinding(
        asset_id=asset.id,
        adapter="reference_endpoint",
        endpoint="https://reference-edr.example.test",
        credential_reference_id=credential.id,
        config={"timeout_seconds": 5},
    )
    db.add(binding)
    db.commit()
    return binding


@pytest.mark.asyncio
async def test_execution_kill_switch_is_disabled_by_default() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)

    with pytest.raises(ExecutionValidationError, match="kill switch"):
        await create_execution(
            db,
            proposal,
            principal=operator(),
            settings=Settings(),
            policy=StablePolicy(),
        )


@pytest.mark.asyncio
async def test_duplicate_dispatch_returns_one_execution_and_one_side_effect_request() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    db.commit()

    first, first_duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    second, second_duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    db.commit()

    assert first_duplicate is False
    assert second_duplicate is True
    assert first.id == second.id
    assert len(list(db.scalars(select(ActionExecution)))) == 1
    requests = list(
        db.scalars(select(OutboxEvent).where(OutboxEvent.subject == "action.execution.requested"))
    )
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_execution_snapshot_is_immutable_from_later_proposal_changes() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    db.commit()

    expected_parameters = dict(execution.parameters)
    expected_evidence = list(execution.evidence_ids)
    expected_confidence = execution.confidence
    proposal.parameters = {"reason_code": "operator_request", "duration_minutes": 10}
    proposal.evidence_ids = []
    proposal.confidence = 0.1
    db.flush()

    assert execution.parameters == expected_parameters
    assert execution.evidence_ids == expected_evidence
    assert execution.confidence == expected_confidence
    assert execution.incident_id == incident.id


@pytest.mark.asyncio
async def test_dispatch_reauthorization_to_deny_blocks_execution_and_updates_state() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    db.commit()

    with pytest.raises(ExecutionValidationError, match="no longer authorized"):
        await create_execution(
            db,
            proposal,
            principal=operator(),
            settings=Settings(),
            policy=DenyPolicy(),
        )

    assert proposal.state == "DENIED"
    assert proposal.policy_decision == "deny"
    assert db.scalar(select(ActionExecution)) is None


@pytest.mark.asyncio
async def test_execution_claim_prevents_duplicate_worker_side_effect() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    db.commit()

    first = claim_execution_for_run(db, execution.id)
    db.commit()
    second = claim_execution_for_run(db, execution.id)

    assert first is not None
    assert second is None
    db.refresh(execution)
    assert execution.state == "RUNNING"


@pytest.mark.asyncio
async def test_executor_success_is_not_success_when_independent_verification_fails() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    claim_execution_for_run(db, execution.id)
    mark_executor_result(
        db,
        execution,
        outcome="success",
        result={"isolated_requested": True},
        pre_state={"known": True, "isolated": False},
    )
    db.commit()

    claimed, previous = claim_execution_for_verification(db, execution.id)
    assert claimed is not None
    assert previous == "EXECUTOR_SUCCEEDED"
    mark_verification_result(
        db,
        claimed,
        previous_state=previous,
        verified=False,
        result={"strategy": "test_probe", "observed": False},
    )
    db.commit()

    assert execution.state == "VERIFICATION_FAILED"
    assert execution.error_category == "independent_verification_failed"


@pytest.mark.asyncio
async def test_stale_running_execution_becomes_ambiguous_and_is_not_retried() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    claim_execution_for_run(db, execution.id)
    execution.started_at = datetime.now(UTC) - timedelta(minutes=10)
    db.commit()

    assert recover_stale_running(db, stale_seconds=60) == 1
    db.commit()
    assert execution.state == "AMBIGUOUS"
    assert recover_stale_running(db, stale_seconds=60) == 0
    verify_events = list(
        db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.subject == "action.execution.verify_requested"
            )
        )
    )
    assert len(verify_events) == 1


@pytest.mark.asyncio
async def test_inconclusive_verification_does_not_turn_ambiguous_into_failed() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    claim_execution_for_run(db, execution.id)
    mark_executor_result(db, execution, outcome="ambiguous", category="remote_timeout")
    db.commit()

    claimed, previous = claim_execution_for_verification(db, execution.id)
    assert claimed is not None
    assert previous == "AMBIGUOUS"
    mark_verification_result(
        db,
        claimed,
        previous_state=previous,
        verified=False,
        result={"strategy": "test_probe", "observed": False},
    )
    db.commit()

    assert execution.state == "AMBIGUOUS"
    assert execution.error_category == "ambiguous_verification_inconclusive"


@pytest.mark.asyncio
async def test_rollback_is_a_new_policy_gated_capability_proposal() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    execution.state = "SUCCEEDED"
    execution.pre_state = {"known": True, "isolated": False}
    db.commit()

    rollback = await create_rollback_proposal(
        db,
        execution,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    db.commit()

    assert rollback.capability == "endpoint.unisolate"
    assert rollback.parameters == {"reason_code": "rollback"}
    assert rollback.state == "AWAITING_APPROVAL"
    assert rollback.id != proposal.id
    assert rollback.incident_id == execution.incident_id
    assert rollback.evidence_ids == execution.evidence_ids


@pytest.mark.asyncio
async def test_rollback_refuses_unknown_pre_state() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    execution.state = "AMBIGUOUS"
    execution.pre_state = {"known": False}
    db.commit()

    with pytest.raises(ExecutionValidationError, match="no known pre-state"):
        await create_rollback_proposal(
            db,
            execution,
            principal=operator(),
            settings=Settings(),
            policy=StablePolicy(),
        )


@pytest.mark.asyncio
async def test_rollback_refuses_to_remove_preexisting_endpoint_isolation() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    execution.state = "SUCCEEDED"
    execution.pre_state = {"known": True, "isolated": True}
    db.commit()

    with pytest.raises(ExecutionValidationError, match="already isolated"):
        await create_rollback_proposal(
            db,
            execution,
            principal=operator(),
            settings=Settings(),
            policy=StablePolicy(),
        )


def test_executable_capabilities_bind_reviewed_implementation_artifacts() -> None:
    db = make_db()
    definitions = list(db.scalars(select(CapabilityDefinition)))
    executable = [
        item
        for item in definitions
        if item.manifest["execution"]["adapter"] != "reserved_phase6"
    ]
    assert executable
    forbidden = {"shell.exec", "ssh.run", "powershell.run", "network.run_cli"}
    assert not forbidden.intersection(item.capability_id for item in definitions)
    for definition in executable:
        artifacts = definition.manifest.get("artifacts", [])
        implementation = definition.manifest["execution"]["implementation"]
        assert implementation in artifacts
        assert len(definition.implementation_digest) == 64
        assert len(definition.capability_digest) == 64


@pytest.mark.asyncio
async def test_ansible_service_must_be_allowlisted_by_target_binding() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = StablePolicy()
    settings = Settings()
    proposal = await create_action_proposal(
        db,
        ActionProposalCreate(
            capability="windows.restart_service",
            capability_version="1.0.0",
            target_asset_id=asset.id,
            parameters={"service_name": "W32Time"},
            reason="Test reviewed service restart.",
            incident_id=incident.id,
            evidence_ids=[evidence_id],
            confidence=0.97,
        ),
        principal=operator(),
        settings=settings,
        policy=policy,
    )
    await record_approval(
        db,
        proposal,
        principal=approver(),
        decision="approve",
        comment=None,
        settings=settings,
        policy=policy,
    )
    credential = CredentialReference(
        name="windows-lab",
        secret_ref="openbao://secret/phase6/windows",
    )
    db.add(credential)
    db.flush()
    db.add(
        ExecutionBinding(
            asset_id=asset.id,
            adapter="ansible_windows",
            endpoint="10.30.40.50",
            credential_reference_id=credential.id,
            config={"allowed_services": ["Spooler"]},
        )
    )
    set_execution_enabled(db, enabled=True, reason="test window")
    db.commit()

    with pytest.raises(ExecutionValidationError, match="allowlisted"):
        await create_execution(
            db,
            proposal,
            principal=operator(),
            settings=settings,
            policy=policy,
        )


@pytest.mark.asyncio
async def test_execution_record_contains_reference_not_secret_value() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    proposal = await authorized_endpoint_proposal(db, asset, incident, evidence_id)
    bind_reference_endpoint(db, asset)
    set_execution_enabled(db, enabled=True, reason="test window")
    execution, _duplicate = await create_execution(
        db,
        proposal,
        principal=operator(),
        settings=Settings(),
        policy=StablePolicy(),
    )
    db.commit()

    serialized = repr(execution.__dict__)
    assert "openbao://" not in serialized
    assert "password" not in serialized.lower()
    assert "token" not in serialized.lower()
