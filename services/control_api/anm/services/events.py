import asyncio
import json
from contextlib import suppress
from datetime import UTC, datetime

import nats
from nats.aio.client import Client as NATS
from nats.js import JetStreamContext
from nats.js.errors import NotFoundError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from anm.models import EventProcessingReceipt, OutboxEvent, PlatformSetting


class EventBus:
    def __init__(self, nats_url: str, session_factory: sessionmaker[Session]) -> None:
        self._nats_url = nats_url
        self._session_factory = session_factory
        self._nc: NATS | None = None
        self._js: JetStreamContext | None = None
        self._dispatcher_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    @property
    def connected(self) -> bool:
        return bool(self._nc and self._nc.is_connected)

    async def start(self) -> None:
        self._nc = await nats.connect(self._nats_url, connect_timeout=2, max_reconnect_attempts=-1)
        self._js = self._nc.jetstream()
        await self._ensure_streams()
        self._dispatcher_task = asyncio.create_task(self._dispatch_loop(), name="outbox-dispatcher")

    async def stop(self) -> None:
        self._stop.set()
        if self._dispatcher_task:
            await self._dispatcher_task
        if self._nc:
            await self._nc.drain()

    async def _ensure_streams(self) -> None:
        assert self._js is not None
        streams = {
            "SYSTEM": ["system.>"],
            "AUDIT": ["audit.>"],
        }
        for name, subjects in streams.items():
            try:
                await self._js.stream_info(name)
            except NotFoundError:
                await self._js.add_stream(name=name, subjects=subjects, storage="file")

    async def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            # The database is authoritative. Publication failure leaves events pending.
            with suppress(Exception):
                await self.dispatch_pending(limit=100)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except TimeoutError:
                continue

    async def dispatch_pending(self, limit: int = 100) -> int:
        if not self._js:
            return 0

        published = 0
        with self._session_factory() as db:
            rows = list(
                db.scalars(
                    select(OutboxEvent)
                    .where(OutboxEvent.published_at.is_(None))
                    .order_by(OutboxEvent.created_at)
                    .limit(limit)
                )
            )
            for row in rows:
                payload = json.dumps(row.payload, separators=(",", ":")).encode("utf-8")
                await self._js.publish(
                    row.subject,
                    payload,
                    headers={"Nats-Msg-Id": row.message_id},
                )
                row.published_at = datetime.now(UTC)
                db.commit()
                published += 1
        return published


def claim_message(db: Session, *, consumer: str, message_id: str) -> bool:
    """Atomically claim a message ID for a consumer without disturbing the outer transaction."""
    try:
        with db.begin_nested():
            db.add(EventProcessingReceipt(consumer=consumer, message_id=message_id))
            db.flush()
        return True
    except IntegrityError:
        return False


def apply_test_event_once(db: Session, *, message_id: str, aggregate_key: str) -> bool:
    """Exercise the exact receipt + domain mutation + outbox pattern used by later consumers."""
    if not claim_message(db, consumer="phase1-test-consumer", message_id=message_id):
        return False

    setting_key = f"test-aggregate:{aggregate_key}"
    setting = db.get(PlatformSetting, setting_key)
    count = 0 if setting is None else int(setting.value.get("count", 0))
    if setting is None:
        setting = PlatformSetting(key=setting_key, value={"count": count + 1})
        db.add(setting)
    else:
        setting.value = {"count": count + 1}

    db.add(
        OutboxEvent(
            subject="system.test_event_applied",
            message_id=f"domain:{message_id}",
            payload={
                "message_id": f"domain:{message_id}",
                "source_message_id": message_id,
                "aggregate_key": aggregate_key,
                "count": count + 1,
            },
        )
    )
    return True
