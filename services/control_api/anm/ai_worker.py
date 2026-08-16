import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError
from sqlalchemy import select

from anm.ai_models import InvestigationRun
from anm.config import get_settings
from anm.db import SessionLocal
from anm.models import EventProcessingReceipt
from anm.services.events import claim_message
from anm.services.investigation import execute_investigation
from anm.services.model_gateway import RelayModelGateway
from anm.services.streams import ensure_stream

CONSUMER = "phase4-ai-investigation-worker"
SUBJECT = "incident.investigation.requested"


async def _connect_nats(url: str):
    while True:
        try:
            return await nats.connect(url, connect_timeout=2, max_reconnect_attempts=-1)
        except Exception:
            await asyncio.sleep(1)


def _already_processed(message_id: str) -> bool:
    with SessionLocal() as db:
        return (
            db.scalar(
                select(EventProcessingReceipt.id).where(
                    EventProcessingReceipt.consumer == CONSUMER,
                    EventProcessingReceipt.message_id == message_id,
                )
            )
            is not None
        )


def _mark_processed(message_id: str) -> None:
    with SessionLocal() as db:
        claim_message(db, consumer=CONSUMER, message_id=message_id)
        db.commit()


async def _heartbeat(message, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except TimeoutError:
            with suppress(Exception):
                await message.in_progress()


async def _handle_message(message, gateway: RelayModelGateway) -> None:
    try:
        payload = json.loads(message.data.decode("utf-8"))
        message_id = str(payload["message_id"])
        run_id = uuid.UUID(str(payload["investigation_run_id"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        await message.term()
        return

    if _already_processed(message_id):
        await message.ack()
        return

    stop = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat(message, stop))
    try:
        with SessionLocal() as db:
            run = db.get(InvestigationRun, run_id)
            if run is None:
                _mark_processed(message_id)
                await message.ack()
                return
            await execute_investigation(
                db,
                run=run,
                settings=get_settings(),
                gateway=gateway,
            )
        _mark_processed(message_id)
        await message.ack()
    except Exception:
        # Investigation is read-only to managed infrastructure, but may incur provider
        # cost. Persisted successful steps allow a redelivery to resume without
        # intentionally repeating completed specialist calls.
        await message.nak(delay=10)
    finally:
        stop.set()
        with suppress(Exception):
            await heartbeat


async def run_worker() -> None:
    settings = get_settings()
    gateway = RelayModelGateway(settings)
    nc = await _connect_nats(settings.nats_url)
    js = nc.jetstream()
    await ensure_stream(
        js,
        name="DOMAIN_EVENTS",
        subjects=["asset.changed.>", "topology.changed.>", "finding.>", "incident.>"],
    )
    subscription = await js.pull_subscribe(
        SUBJECT,
        durable=CONSUMER,
        stream="DOMAIN_EVENTS",
    )
    try:
        while True:
            try:
                messages = await subscription.fetch(1, timeout=1)
            except NATSTimeoutError:
                continue
            for message in messages:
                await _handle_message(message, gateway)
    finally:
        with suppress(Exception):
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(run_worker())
