import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from anm.action_models import ActionApproval, ActionProposal, CapabilityDefinition
from anm.action_schemas import ActionProposalCreate, ActionProposalRevision
from anm.auth import Principal
from anm.config import Settings
from anm.db import Base
from anm.models import Asset, AssetAddress, AssetIdentifier
from anm.policy_types import ActionPolicyDecision
from anm.security_models import Incident
from anm.services.actions import (
    ActionValidationError,
    create_action_proposal,
    record_approval,
    reevaluate_action_proposal,
    revise_action_proposal,
)
from anm.services.capabilities import sync_builtin_capabilities
from anm.services.security import ingest_event


class CapturingPolicy:
    def __init__(
        self,
        *,
        decision: str = "require_approval",
        required_roles: list[str] | None = None,
        policy_version: str = "test-policy-v1",
    ) -> None:
        self.decision = decision
        self.required_roles = required_roles or ["operator_approver"]
        self.policy_version = policy_version
        self.inputs: list[dict] = []

    async def evaluate_action(self, input_document: dict) -> ActionPolicyDecision:
        self.inputs.append(input_document)
        return ActionPolicyDecision(
            decision=self.decision,
            reasons=["test_policy"],
            required_roles=self.required_roles if self.decision == "require_approval" else [],
            source="opa",
            policy_version=self.policy_version,
        )


def make_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    sync_builtin_capabilities(db)
    db.commit()
    return db


def seed_incident(
    db: Session,
    *,
    protected_roles: list[str] | None = None,
) -> tuple[Asset, Incident, uuid.UUID]:
    asset = Asset(
        display_name="LAB-ENDPOINT-01",
        asset_type="endpoint",
        protected_roles=protected_roles or [],
    )
    db.add(asset)
    db.flush()
    db.add(AssetIdentifier(asset_id=asset.id, namespace="wazuh", value="501"))
    db.add(AssetAddress(asset_id=asset.id, address="10.20.30.40", source="netbox"))
    event, _duplicate, incident = ingest_event(
        db,
        source="wazuh",
        source_instance="wazuh-lab",
        payload={
            "_id": "phase5-wazuh-1",
            "_source": {
                "timestamp": datetime.now(UTC).isoformat(),
                "agent": {"id": "501", "name": "LAB-ENDPOINT-01", "ip": "10.20.30.40"},
                "rule": {
                    "id": "99001",
                    "level": 12,
                    "description": "Suspicious endpoint activity",
                    "groups": ["windows", "security"],
                },
            },
        },
    )
    assert incident is not None
    db.commit()
    return asset, incident, event.id


def proposal_request(
    asset: Asset,
    incident: Incident,
    evidence_id: uuid.UUID,
) -> ActionProposalCreate:
    return ActionProposalCreate(
        capability="endpoint.isolate",
        capability_version="1.0.0",
        target_asset_id=asset.id,
        parameters={"reason_code": "suspected_compromise", "duration_minutes": 60},
        reason="Contain the endpoint while the incident is investigated.",
        incident_id=incident.id,
        evidence_ids=[evidence_id],
        confidence=0.95,
    )


def operator() -> Principal:
    return Principal(
        subject="operator@example.test",
        roles=("platform_admin",),
        provider="test",
    )


def platform_approver() -> Principal:
    return Principal(
        subject="approver@example.test",
        roles=("platform_approver",),
        provider="test",
    )


@pytest.mark.asyncio
async def test_level_two_write_proposal_is_policy_evaluated_and_awaits_approval() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = CapturingPolicy()
    settings = Settings(autonomy_level=2)

    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=settings,
        policy=policy,
    )
    db.commit()

    assert proposal.state == "AWAITING_APPROVAL"
    assert proposal.policy_decision == "require_approval"
    assert proposal.required_roles == ["operator_approver"]
    assert len(proposal.proposal_digest) == 64
    assert len(proposal.capability_digest) == 64
    assert len(proposal.implementation_digest) == 64
    assert len(policy.inputs) == 1
    assert policy.inputs[0]["action"]["write"] is True
    assert policy.inputs[0]["environment"]["autonomy_level"] == 2
    assert policy.inputs[0]["action"]["proposal_digest"] == proposal.proposal_digest


@pytest.mark.asyncio
async def test_platform_approver_can_satisfy_operator_approval_without_execution() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = CapturingPolicy(required_roles=["operator_approver"])
    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=Settings(autonomy_level=2),
        policy=policy,
    )
    approval, _invalidated = await record_approval(
        db,
        proposal,
        principal=platform_approver(),
        decision="approve",
        comment="Approved for containment only.",
        settings=Settings(autonomy_level=2),
        policy=policy,
    )
    db.commit()

    assert proposal.state == "AUTHORIZED"
    assert approval.valid is True
    assert approval.proposal_digest == proposal.proposal_digest
    assert approval.capability_digest == proposal.capability_digest
    assert approval.implementation_digest == proposal.implementation_digest
    assert approval.policy_version == proposal.policy_version


@pytest.mark.asyncio
async def test_revising_parameters_invalidates_prior_approval_and_changes_digest() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = CapturingPolicy()
    settings = Settings(autonomy_level=2)
    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=settings,
        policy=policy,
    )
    approval, _ = await record_approval(
        db,
        proposal,
        principal=platform_approver(),
        decision="approve",
        comment=None,
        settings=settings,
        policy=policy,
    )
    old_digest = proposal.proposal_digest

    revision = ActionProposalRevision(
        parameters={"reason_code": "malware_containment", "duration_minutes": 30}
    )
    invalidated = await revise_action_proposal(
        db,
        proposal,
        revision,
        settings=settings,
        policy=policy,
    )
    db.commit()

    assert invalidated == 1
    assert proposal.revision == 2
    assert proposal.proposal_digest != old_digest
    assert proposal.state == "AWAITING_APPROVAL"
    db.refresh(approval)
    assert approval.valid is False
    assert approval.invalidated_reason == "proposal_revised"


@pytest.mark.asyncio
async def test_capability_digest_drift_invalidates_approval_before_reauthorization() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = CapturingPolicy()
    settings = Settings(autonomy_level=2)
    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=settings,
        policy=policy,
    )
    approval, _ = await record_approval(
        db,
        proposal,
        principal=platform_approver(),
        decision="approve",
        comment=None,
        settings=settings,
        policy=policy,
    )
    capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
    assert capability is not None
    capability.implementation_digest = "d" * 64
    capability.capability_digest = "e" * 64
    db.flush()

    invalidated = await reevaluate_action_proposal(
        db,
        proposal,
        settings=settings,
        policy=policy,
    )
    db.commit()

    assert invalidated == 1
    assert proposal.revision == 2
    assert proposal.implementation_digest == "d" * 64
    assert proposal.capability_digest == "e" * 64
    assert proposal.state == "AWAITING_APPROVAL"
    db.refresh(approval)
    assert approval.valid is False
    assert approval.invalidated_reason == "capability_digest_changed"


@pytest.mark.asyncio
async def test_policy_version_change_invalidates_existing_approval() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    settings = Settings(autonomy_level=2)
    policy_v1 = CapturingPolicy(policy_version="policy-v1")
    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=settings,
        policy=policy_v1,
    )
    approval, _ = await record_approval(
        db,
        proposal,
        principal=platform_approver(),
        decision="approve",
        comment=None,
        settings=settings,
        policy=policy_v1,
    )
    assert proposal.state == "AUTHORIZED"

    invalidated = await reevaluate_action_proposal(
        db,
        proposal,
        settings=settings,
        policy=CapturingPolicy(policy_version="policy-v2"),
    )
    db.commit()

    assert invalidated == 1
    assert proposal.policy_version == "policy-v2"
    assert proposal.state == "AWAITING_APPROVAL"
    db.refresh(approval)
    assert approval.valid is False
    assert approval.invalidated_reason == "policy_binding_changed"


@pytest.mark.asyncio
async def test_protected_roles_are_in_policy_input_and_can_escalate_required_role() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db, protected_roles=["identity"])
    policy = CapturingPolicy(required_roles=["platform_approver"])
    proposal = await create_action_proposal(
        db,
        proposal_request(asset, incident, evidence_id),
        principal=operator(),
        settings=Settings(autonomy_level=2),
        policy=policy,
    )

    assert policy.inputs[0]["target"]["protected_roles"] == ["identity"]
    assert proposal.required_roles == ["platform_approver"]
    with pytest.raises(PermissionError):
        await record_approval(
            db,
            proposal,
            principal=Principal(
                subject="operator-approver@example.test",
                roles=("operator_approver",),
                provider="test",
            ),
            decision="approve",
            comment=None,
            settings=Settings(autonomy_level=2),
            policy=policy,
        )


@pytest.mark.asyncio
async def test_invalid_capability_parameters_fail_before_policy_call() -> None:
    db = make_db()
    asset, incident, evidence_id = seed_incident(db)
    policy = CapturingPolicy()
    request = proposal_request(asset, incident, evidence_id)
    request.parameters = {"reason_code": "suspected_compromise", "duration_minutes": 99999}

    with pytest.raises(ActionValidationError):
        await create_action_proposal(
            db,
            request,
            principal=operator(),
            settings=Settings(),
            policy=policy,
        )
    assert policy.inputs == []
    assert db.scalar(select(ActionProposal)) is None


def test_builtin_catalogue_uses_only_reviewed_adapters_and_no_generic_shell_capability() -> None:
    db = make_db()
    definitions = list(db.scalars(select(CapabilityDefinition)))
    assert definitions
    forbidden = {"shell.exec", "ssh.run", "powershell.run", "network.run_cli"}
    allowed_adapters = {
        "reserved_phase6",
        "ansible_windows",
        "ansible_linux",
        "reference_endpoint",
        "reference_firewall",
    }
    assert not forbidden.intersection(item.capability_id for item in definitions)
    for definition in definitions:
        adapter = definition.manifest["execution"]["adapter"]
        assert adapter in allowed_adapters
        if adapter != "reserved_phase6":
            assert definition.manifest.get("artifacts")
            assert definition.manifest["execution"]["implementation"] in definition.manifest["artifacts"]
