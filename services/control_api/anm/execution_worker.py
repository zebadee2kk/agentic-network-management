import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError
from sqlalchemy import select

from anm.action_models import ActionProposal, CapabilityDefinition
from anm.config import get_settings
from anm.db import SessionLocal
from anm.execution_models import ActionExecution, ExecutionBinding
from anm.executors import get_executor
from anm.executors.base import ExecutionContext
from anm.models import Asset, CredentialReference, PlatformSetting, utcnow
from anm.services.actions import reevaluate_action_proposal
from anm.services.execution import (
    EXECUTION_CONTROL_KEY,
    mark_execution_cancelled,
    mark_executor_result,
    recover_stale_running,
)
from anm.services.policy import PolicyClient
from anm.services.secrets import OpenBaoClient
from anm.services.streams import ensure_stream

SUBJECT = "action.execution.requested"
CONSUMER = "phase6-deterministic-executor"
ACTION_SUBJECTS = ["action.>"]


async def _connect_nats(url: str):
    while True:
        try:
            return await nats.connect(url, connect_timeout=2, max_reconnect_attempts=-1)
        except Exception:
            await asyncio.sleep(1)


async def _prepare_execution(
    execution_id: uuid.UUID,
    *,
    policy: PolicyClient,
) -> tuple[ExecutionContext, str | None] | None:
    settings = get_settings()
    with SessionLocal() as db:
        # Serialize duplicate deliveries before any authorization or side-effect work.
        execution = db.scalar(
            select(ActionExecution)
            .where(ActionExecution.id == execution_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if execution is None or execution.state != "QUEUED":
            return None

        # Lock the kill-switch row in the same transaction as the execution claim.
        # A concurrent disable that commits first is observed here; once this transaction
        # commits RUNNING, the execution has already won the linearization race.
        control = db.scalar(
            select(PlatformSetting)
            .where(PlatformSetting.key == EXECUTION_CONTROL_KEY)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        enabled = bool(control and control.value.get("enabled", False))
        reason = (
            str(control.value.get("reason", "unspecified"))
            if control is not None
            else "execution control is unavailable"
        )
        if not enabled:
            mark_execution_cancelled(
                db,
                execution,
                category="kill_switch_disabled",
                detail=reason,
            )
            db.commit()
            return None

        # Keep mutable authorization context locked until RUNNING is durably committed.
        proposal = db.scalar(
            select(ActionProposal)
            .where(ActionProposal.id == execution.proposal_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        binding = db.scalar(
            select(ExecutionBinding)
            .where(ExecutionBinding.id == execution.binding_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        asset = db.scalar(
            select(Asset)
            .where(Asset.id == execution.target_asset_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if proposal is None or binding is None or asset is None:
            mark_execution_cancelled(
                db,
                execution,
                category="execution_context_unavailable",
                detail="proposal, asset or binding is unavailable",
            )
            db.commit()
            return None

        await reevaluate_action_proposal(db, proposal, settings=settings, policy=policy)
        capability = db.get(CapabilityDefinition, proposal.capability_definition_id)
        if proposal.state != "AUTHORIZED" or capability is None:
            mark_execution_cancelled(
                db,
                execution,
                category="authorization_changed",
                detail="proposal failed pre-side-effect re-authorization",
            )
            db.commit()
            return None
        if asset.status != "active":
            mark_execution_cancelled(
                db,
                execution,
                category="target_unavailable",
                detail="target asset is no longer active",
            )
            db.commit()
            return None
        if execution.target_criticality != asset.criticality or sorted(
            execution.target_protected_roles
        ) != sorted(asset.protected_roles):
            mark_execution_cancelled(
                db,
                execution,
                category="target_policy_context_changed",
                detail="target criticality or protected roles changed before side effect",
            )
            db.commit()
            return None
        if (
            execution.proposal_digest != proposal.proposal_digest
            or execution.capability_digest != capability.capability_digest
            or execution.implementation_digest != capability.implementation_digest
        ):
            mark_execution_cancelled(
                db,
                execution,
                category="execution_binding_drift",
                detail="proposal or implementation digest changed before side effect",
            )
            db.commit()
            return None
        if not binding.enabled:
            mark_execution_cancelled(
                db,
                execution,
                category="execution_binding_disabled",
                detail="execution binding was disabled before side effect",
            )
            db.commit()
            return None

        adapter = str(capability.manifest.get("execution", {}).get("adapter", ""))
        implementation = str(
            capability.manifest.get("execution", {}).get("implementation", "")
        )
        if adapter != binding.adapter:
            mark_execution_cancelled(
                db,
                execution,
                category="execution_adapter_drift",
                detail="capability adapter no longer matches target binding",
            )
            db.commit()
            return None

        secret_ref: str | None = None
        if binding.credential_reference_id is not None:
            credential = db.get(CredentialReference, binding.credential_reference_id)
            if credential is None:
                mark_execution_cancelled(
                    db,
                    execution,
                    category="credential_reference_missing",
                    detail="credential reference was removed before side effect",
                )
                db.commit()
                return None
            secret_ref = credential.secret_ref

        context = ExecutionContext(
            execution_id=str(execution.id),
            capability=execution.capability,
            target_asset_id=str(execution.target_asset_id),
            endpoint=binding.endpoint,
            parameters=dict(execution.parameters),
            binding_config=dict(binding.config),
            implementation=implementation,
        )
        # RUNNING is durable before external I/O. A crash after this commit is not
        # automatically retried; stale recovery converts it to AMBIGUOUS.
        execution.state = "RUNNING"
        execution.started_at = utcnow()
        execution.error_category = None
        execution.error_detail = None
        db.commit()
        return context, secret_ref


async def _execute_one(
    execution_id: uuid.UUID,
    *,
    policy: PolicyClient,
    secrets: OpenBaoClient,
) -> None:
    prepared = await _prepare_execution(execution_id, policy=policy)
    if prepared is None:
        return
    context, secret_ref = prepared
    secret = None
    try:
        if secret_ref is not None:
            secret = await secrets.read_kv_v2(secret_ref)
        context = ExecutionContext(
            execution_id=context.execution_id,
            capability=context.capability,
            target_asset_id=context.target_asset_id,
            endpoint=context.endpoint,
            parameters=context.parameters,
            binding_config=context.binding_config,
            implementation=context.implementation,
            secret=secret,
        )
        adapter_name = ""
        with SessionLocal() as db:
            execution = db.get(ActionExecution, execution_id)
            binding = None if execution is None else db.get(ExecutionBinding, execution.binding_id)
            if binding is not None:
                adapter_name = binding.adapter
        executor = get_executor(adapter_name)
        outcome = await executor.execute(context)
        with SessionLocal() as db:
            execution = db.get(ActionExecution, execution_id)
            if execution is not None and execution.state == "RUNNING":
                mark_executor_result(
                    db,
                    execution,
                    outcome=outcome.outcome,
                    result=outcome.result,
                    pre_state=outcome.pre_state,
                    category=outcome.category,
                )
                db.commit()
    except Exception:
        # Once RUNNING was committed we cannot prove whether a remote side effect took
        # place. Do not retry. Move to AMBIGUOUS and let the verifier reconcile state.
        with SessionLocal() as db:
            execution = db.get(ActionExecution, execution_id)
            if execution is not None and execution.state == "RUNNING":
                mark_executor_result(
                    db,
                    execution,
                    outcome="ambiguous",
                    category="executor_exception_after_claim",
                )
                db.commit()
    finally:
        if isinstance(secret, dict):
            secret.clear()


async def _handle_message(message, policy: PolicyClient, secrets: OpenBaoClient) -> None:
    try:
        payload = json.loads(message.data.decode("utf-8"))
        execution_id = uuid.UUID(str(payload["execution_id"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        await message.term()
        return

    await _execute_one(execution_id, policy=policy, secrets=secrets)
    # Execution requests are never NAKed after handling. Redelivery is not a safe
    # retry mechanism for external side effects; state reconciliation is used instead.
    await message.ack()


async def run_worker() -> None:
    settings = get_settings()
    policy = PolicyClient(settings)
    secrets = OpenBaoClient(settings)
    with SessionLocal() as db:
        recover_stale_running(db, stale_seconds=settings.execution_stale_seconds)
        db.commit()

    nc = await _connect_nats(settings.nats_url)
    js = nc.jetstream()
    await ensure_stream(js, name="ACTIONS", subjects=ACTION_SUBJECTS)
    subscription = await js.pull_subscribe(
        SUBJECT,
        durable=CONSUMER,
        stream="ACTIONS",
    )
    try:
        while True:
            try:
                messages = await subscription.fetch(1, timeout=1)
            except NATSTimeoutError:
                continue
            for message in messages:
                with suppress(Exception):
                    await message.in_progress()
                await _handle_message(message, policy, secrets)
    finally:
        with suppress(Exception):
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(run_worker())
