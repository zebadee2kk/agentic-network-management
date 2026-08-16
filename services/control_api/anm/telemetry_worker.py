import asyncio
import json
import uuid
from contextlib import suppress

import nats
from nats.errors import TimeoutError as NATSTimeoutError
from nats.js.errors import NotFoundError

from anm.config import get_settings
from anm.connectors.wazuh import WazuhConnectorError, WazuhIndexerConnector
from anm.db import SessionLocal
from anm.models import ManagedScope, OutboxEvent, utcnow
from anm.security_models import TelemetrySource
from anm.services.discovery import DiscoveryConfigurationError, validate_connector_endpoint
from anm.services.events import claim_message
from anm.services.secrets import OpenBaoClient
from anm.services.security import ingest_event

CONSUMER = "phase3-wazuh-telemetry-worker"
SUBJECT = "telemetry.wazuh.poll_requested"


async def _connect_nats(url: str):
    while True:
        try:
            return await nats.connect(url, connect_timeout=2, max_reconnect_attempts=-1)
        except Exception:
            await asyncio.sleep(1)


async def _heartbeat(message, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except TimeoutError:
            with suppress(Exception):
                await message.in_progress()


async def _process_source(source_id: uuid.UUID, secrets: OpenBaoClient) -> tuple[int, int]:
    with SessionLocal() as db:
        source = db.get(TelemetrySource, source_id)
        if source is None:
            raise DiscoveryConfigurationError("unknown telemetry source")
        if source.source_type != "wazuh":
            raise DiscoveryConfigurationError("telemetry worker only polls Wazuh sources")
        if not source.base_url or not source.secret_ref or source.scope_id is None:
            raise DiscoveryConfigurationError("Wazuh source is missing scope, URL or secret reference")
        scope = db.get(ManagedScope, source.scope_id)
        if scope is None or not scope.enabled:
            raise DiscoveryConfigurationError("Wazuh source scope is unavailable")

        # The endpoint must be in the explicit management egress allowlist before
        # the worker is permitted to dereference the Wazuh credential.
        await validate_connector_endpoint(source.base_url, scope.connector_cidrs)
        secret = await secrets.read_kv_v2(source.secret_ref)
        connector = WazuhIndexerConnector(
            base_url=source.base_url,
            secret=secret,
            timeout_seconds=float(source.config.get("timeout_seconds", 10)),
            verify_tls=bool(source.config.get("verify_tls", True)),
        )
        cursor = source.cursor.get("search_after")
        documents, next_cursor = await connector.poll(
            search_after=cursor if isinstance(cursor, list) else None,
            size=int(source.config.get("batch_size", 250)),
        )
        accepted = 0
        duplicates = 0
        for document in documents:
            _event, duplicate, _incident = ingest_event(
                db,
                source="wazuh",
                source_instance=source.name,
                payload=document,
            )
            if duplicate:
                duplicates += 1
            else:
                accepted += 1
        if next_cursor is not None:
            source.cursor = {"search_after": next_cursor}
        source.status = "healthy"
        source.updated_at = utcnow()
        message_id = str(uuid.uuid4())
        db.add(
            OutboxEvent(
                subject="telemetry.wazuh.poll_completed",
                message_id=message_id,
                payload={
                    "message_id": message_id,
                    "source_id": str(source.id),
                    "accepted": accepted,
                    "duplicates": duplicates,
                },
            )
        )
        db.commit()
        return accepted, duplicates


async def _handle_message(message, secrets: OpenBaoClient) -> None:
    try:
        payload = json.loads(message.data.decode("utf-8"))
        message_id = str(payload["message_id"])
        source_id = uuid.UUID(str(payload["source_id"]))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        await message.term()
        return

    with SessionLocal() as db:
        if not claim_message(db, consumer=CONSUMER, message_id=message_id):
            db.rollback()
            await message.ack()
            return
        db.commit()

    stop = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat(message, stop))
    try:
        await _process_source(source_id, secrets)
        await message.ack()
    except (DiscoveryConfigurationError, WazuhConnectorError):
        with SessionLocal() as db:
            source = db.get(TelemetrySource, source_id)
            if source is not None:
                source.status = "degraded"
                source.updated_at = utcnow()
                db.commit()
        await message.ack()
    except Exception:
        with SessionLocal() as db:
            source = db.get(TelemetrySource, source_id)
            if source is not None:
                source.status = "degraded"
                source.updated_at = utcnow()
                db.commit()
        # Polling is read-only and canonical event persistence is deduplicated. A
        # transient worker crash can therefore safely redeliver the poll request.
        await message.nak(delay=5)
    finally:
        stop.set()
        with suppress(Exception):
            await heartbeat


async def run_worker() -> None:
    settings = get_settings()
    secrets = OpenBaoClient(settings)
    nc = await _connect_nats(settings.nats_url)
    js = nc.jetstream()
    try:
        await js.stream_info("OBSERVATIONS")
    except NotFoundError:
        await js.add_stream(
            name="OBSERVATIONS",
            subjects=["discovery.>", "asset.observed.>", "topology.observed.>", "telemetry.>"],
            storage="file",
        )
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
