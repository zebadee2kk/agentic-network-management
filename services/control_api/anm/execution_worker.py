import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError

from anm.action_models import ActionProposal, CapabilityDefinition
from anm.config import get_settings
from anm.db import SessionLocal
from anm.execution_models import ActionExecution, ExecutionBinding
from anm.executors import get_executor
from anm.executors.base import ExecutionContext
from anm.models import Asset, CredentialReference
from anm.services.actions import reevaluate_action_proposal
from anm.services.execution import (
    claim_execution_for_run,
    execution_enabled,
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
        execution = db.get(ActionExecution, execution_id)
        if execution is None or execution.state != "QUEUED":
            return None
        enabled, reason, _updated_at = execution_enabled(db)
        if not enabled:
            mark_execution_cancelled(
                db,
                execution,
                category="kill_switch_disabled",
                detail=reason,
            )
            db.commit()
            return None

        proposal = db.get(ActionProposal, execution.proposal_id)
        binding = db.get(ExecutionBinding, execution.binding_id)
        asset = db.get(Asset, execution.target_asset_id)
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

        # The final side-effect claim uses a row lock and a fresh read. Concurrent
        # duplicate deliveries cannot both transition QUEUED -> RUNNING.
        claimed = claim_execution_for_run(db, execution_id)
        if claimed is None:
            db.rollback()
            return None
        context = ExecutionContext(
            execution_id=str(claimed.id),
            capability=claimed.capability,
            target_asset_id=str(claimed.target_asset_id),
            endpoint=binding.endpoint,
            parameters=dict(proposal.parameters),
            binding_config=dict(binding.config),
            implementation=implementation,
        )
        # RUNNING is durable before external I/O. A crash after this commit is not
        # automatically retried; stale recovery converts it to AMBIGUOUS.
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
