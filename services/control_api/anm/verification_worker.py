import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError

from anm.db import SessionLocal
from anm.execution_models import ActionExecution, ExecutionBinding
from anm.services.execution import (
    claim_execution_for_verification,
    mark_verification_result,
)
from anm.services.streams import ensure_stream
from anm.services.verification import verify_execution

SUBJECT = "action.execution.verify_requested"
CONSUMER = "phase6-independent-verifier"
ACTION_SUBJECTS = ["action.>"]


async def _connect_nats(url: str):
    while True:
        try:
            return await nats.connect(url, connect_timeout=2, max_reconnect_attempts=-1)
        except Exception:
            await asyncio.sleep(1)


async def _verify_one(execution_id: uuid.UUID) -> None:
    with SessionLocal() as db:
        execution, previous = claim_execution_for_verification(db, execution_id)
        if execution is None or previous is None:
            db.commit()
            return
        binding = db.get(ExecutionBinding, execution.binding_id)
        if binding is None:
            mark_verification_result(
                db,
                execution,
                previous_state=previous,
                verified=False,
                result={"reason": "verification_binding_unavailable"},
            )
            db.commit()
            return
        snapshot = (
            execution.id,
            previous,
            execution.capability,
            execution.target_asset_id,
            execution.executor_result,
            binding.id,
        )
        db.commit()

    with SessionLocal() as db:
        execution = db.get(ActionExecution, snapshot[0])
        binding = db.get(ExecutionBinding, snapshot[5])
        if execution is None or binding is None:
            return
        verified, result = await verify_execution(execution, binding)

    with SessionLocal() as db:
        execution = db.get(ActionExecution, execution_id)
        if execution is None:
            return
        # Another verifier may have completed the same request. Verification is
        # read-only, so duplicates are harmless, but terminal state is authoritative.
        if execution.state not in {"VERIFYING", "AMBIGUOUS"}:
            return
        mark_verification_result(
            db,
            execution,
            previous_state=snapshot[1],
            verified=verified,
            result=result,
        )
        db.commit()


async def _handle_message(message) -> None:
    try:
        payload = json.loads(message.data.decode("utf-8"))
        execution_id = uuid.UUID(str(payload["execution_id"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        await message.term()
        return
    try:
        await _verify_one(execution_id)
        await message.ack()
    except Exception:
        # Verification is read-only and idempotent; transient failures may retry.
        await message.nak(delay=5)


async def run_worker() -> None:
    from anm.config import get_settings

    settings = get_settings()
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
                await _handle_message(message)
    finally:
        with suppress(Exception):
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(run_worker())
