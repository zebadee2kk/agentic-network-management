import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError

from anm.config import get_settings
from anm.db import SessionLocal
from anm.models import DiscoveryRun, OutboxEvent, utcnow
from anm.services.discovery import DiscoveryConfigurationError, execute_discovery_run
from anm.services.events import claim_message
from anm.services.secrets import OpenBaoClient
from anm.services.streams import ensure_stream

CONSUMER = "phase2-discovery-worker"
SUBJECT = "discovery.run.requested"
TERMINAL_RUN_STATES = {"succeeded", "failed"}
OBSERVATION_SUBJECTS = [
    "discovery.>",
    "asset.observed.>",
    "topology.observed.>",
    "telemetry.>",
]


async def _connect_nats(url: str):
    while True:
        try:
            return await nats.connect(url, connect_timeout=2, max_reconnect_attempts=-1)
        except Exception:
            await asyncio.sleep(1)


def _fail_run(run_id: uuid.UUID, category: str, detail: str) -> None:
    with SessionLocal() as db:
        run = db.get(DiscoveryRun, run_id)
        if run is None:
            return
        run.status = "failed"
        run.error_category = category
        run.error_detail = detail[:512]
        run.completed_at = utcnow()
        db.commit()


async def _keep_message_alive(message, done: asyncio.Event) -> None:
    """Extend the JetStream acknowledgement lease during a long read-only discovery."""
    while not done.is_set():
        try:
            await asyncio.wait_for(done.wait(), timeout=10)
        except TimeoutError:
            with suppress(Exception):
                await message.in_progress()


async def _handle_message(message, secrets: OpenBaoClient) -> None:
    try:
        payload = json.loads(message.data.decode("utf-8"))
        message_id = str(payload["message_id"])
        run_id = uuid.UUID(str(payload["run_id"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        await message.term()
        return

    lease_done = asyncio.Event()
    lease_task: asyncio.Task[None] | None = None
    try:
        with SessionLocal() as db:
            run = db.get(DiscoveryRun, run_id)
            if run is None:
                await message.term()
                return

            claimed = claim_message(db, consumer=CONSUMER, message_id=message_id)
            if not claimed:
                db.rollback()
                run = db.get(DiscoveryRun, run_id)
                if run is None:
                    await message.term()
                    return
                if run.status in TERMINAL_RUN_STATES:
                    await message.ack()
                    return
                # A previous worker may have committed the receipt/status and died
                # before acknowledging. Discovery is GET-only and reconciliation is
                # identity/idempotency guarded, so recovering the unfinished run is safe.

            lease_task = asyncio.create_task(
                _keep_message_alive(message, lease_done),
                name=f"discovery-lease-{run_id}",
            )
            result = await execute_discovery_run(db, run, secrets)
            completion_message_id = str(uuid.uuid4())
            db.add(
                OutboxEvent(
                    subject="discovery.run.completed",
                    message_id=completion_message_id,
                    payload={
                        "message_id": completion_message_id,
                        "run_id": str(result.id),
                        "status": result.status,
                        "observations_count": result.observations_count,
                        "reconciled_count": result.reconciled_count,
                        "conflicts_count": result.conflicts_count,
                        "error_category": result.error_category,
                    },
                )
            )
            db.commit()
        await message.ack()
    except DiscoveryConfigurationError as exc:
        _fail_run(run_id, "configuration_error", str(exc))
        await message.ack()
    except Exception:
        _fail_run(run_id, "worker_error", "discovery worker failed; inspect redacted logs")
        # Read-only discovery failures are made explicit rather than endlessly
        # redelivered. Operators can inspect the run and request another run.
        await message.ack()
    finally:
        lease_done.set()
        if lease_task is not None:
            with suppress(Exception):
                await lease_task


async def run_worker() -> None:
    settings = get_settings()
    secrets = OpenBaoClient(settings)
    nc = await _connect_nats(settings.nats_url)
    js = nc.jetstream()
    await ensure_stream(js, name="OBSERVATIONS", subjects=OBSERVATION_SUBJECTS)
    subscription = await js.pull_subscribe(
        SUBJECT,
        durable=CONSUMER,
        stream="OBSERVATIONS",
    )
    try:
        while True:
            try:
                messages = await subscription.fetch(1, timeout=1)
            except NATSTimeoutError:
                continue
            for message in messages:
                await _handle_message(message, secrets)
    finally:
        with suppress(Exception):
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(run_worker())
