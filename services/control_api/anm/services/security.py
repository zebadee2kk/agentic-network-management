import hashlib
import json
import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.models import Asset, AssetAddress, AssetIdentifier, OutboxEvent, utcnow
from anm.security_models import (
    AnomalyFinding,
    Baseline,
    CanonicalEvent,
    FeatureDefinition,
    FeatureSample,
    Incident,
    IncidentAsset,
    IncidentEvidence,
    IncidentTimeline,
    RawEventReference,
)
from anm.security_schemas import CanonicalEventEnvelope, EventSource

CORRELATION_WINDOW = timedelta(minutes=15)
CORRELATABLE_SEVERITY = 4
TERMINAL_INCIDENT_STATES = {"CLOSED", "FALSE_POSITIVE"}
INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"TRIAGE", "FALSE_POSITIVE", "CLOSED"},
    "TRIAGE": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "INVESTIGATING": {"ACTION_PROPOSED", "RESOLVED", "FALSE_POSITIVE"},
    "ACTION_PROPOSED": {"AWAITING_APPROVAL", "INVESTIGATING", "RESOLVED"},
    "AWAITING_APPROVAL": {"REMEDIATING", "INVESTIGATING", "RESOLVED"},
    "REMEDIATING": {"VERIFYING", "INVESTIGATING"},
    "VERIFYING": {"RESOLVED", "REMEDIATING", "INVESTIGATING"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "CLOSED": set(),
    "FALSE_POSITIVE": {"CLOSED", "TRIAGE"},
}


class InvalidIncidentTransition(ValueError):
    pass


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        return utcnow()
    return _as_utc(parsed)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _json_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _dedupe_key(source: str, instance: str, source_event_id: str | None, digest: str) -> str:
    material = f"{source}\0{instance}\0{source_event_id or digest}".encode()
    return hashlib.sha256(material).hexdigest()


def _unique_asset_by_identifier(
    db: Session,
    namespace: str,
    value: str | None,
) -> uuid.UUID | None:
    if not value:
        return None
    ids = set(
        db.scalars(
            select(AssetIdentifier.asset_id).where(
                AssetIdentifier.namespace == namespace,
                AssetIdentifier.value == str(value),
            )
        )
    )
    return next(iter(ids)) if len(ids) == 1 else None


def _unique_asset_by_address(db: Session, values: list[str | None]) -> uuid.UUID | None:
    candidates: set[uuid.UUID] = set()
    for value in values:
        if not value:
            continue
        candidates.update(
            db.scalars(select(AssetAddress.asset_id).where(AssetAddress.address == str(value)))
        )
    return next(iter(candidates)) if len(candidates) == 1 else None


def _asset_site(db: Session, asset_id: uuid.UUID | None) -> uuid.UUID | None:
    if asset_id is None:
        return None
    asset = db.get(Asset, asset_id)
    return asset.site_id if asset else None


def normalize_wazuh(
    db: Session,
    *,
    source_instance: str,
    payload: dict[str, Any],
) -> CanonicalEventEnvelope:
    source_event_id = str(payload.get("_id") or payload.get("id") or "") or None
    source_doc = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
    agent = source_doc.get("agent") if isinstance(source_doc.get("agent"), dict) else {}
    rule = source_doc.get("rule") if isinstance(source_doc.get("rule"), dict) else {}
    data = source_doc.get("data") if isinstance(source_doc.get("data"), dict) else {}
    level = int(rule.get("level") or 0)
    severity = max(0, min(10, round(level * 10 / 15)))
    description = str(rule.get("description") or source_doc.get("full_log") or "Wazuh alert")
    groups = [str(item) for item in rule.get("groups", []) if str(item)][:24]
    classifications = [f"wazuh:{item}"[:128] for item in groups]

    command_line = ""
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    event_data = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    for key in ("commandLine", "commandline", "processCommandLine"):
        if event_data.get(key):
            command_line = str(event_data[key])
            break
    combined = f"{description} {command_line}".lower()
    if "powershell" in combined:
        classifications.append("execution.powershell")

    agent_id = str(agent.get("id")) if agent.get("id") is not None else None
    asset_id = _unique_asset_by_identifier(db, "wazuh", agent_id)
    if asset_id is None:
        asset_id = _unique_asset_by_address(
            db,
            [str(agent.get("ip")) if agent.get("ip") else None, data.get("srcip")],
        )

    attributes = {
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_level": level,
        "rule_groups": groups,
        "src_ip": data.get("srcip"),
        "dest_ip": data.get("dstip"),
        "src_user": data.get("srcuser"),
        "dest_user": data.get("dstuser"),
        "command_line": command_line or None,
        "full_log": source_doc.get("full_log"),
    }
    return CanonicalEventEnvelope(
        event_id=uuid.uuid4(),
        occurred_at=_parse_timestamp(source_doc.get("timestamp")),
        ingested_at=utcnow(),
        source=EventSource(
            connector="wazuh",
            instance=source_instance,
            source_event_id=source_event_id,
        ),
        type="endpoint.alert",
        severity=severity,
        confidence=min(1.0, 0.45 + (level / 30)),
        asset_id=asset_id,
        site_id=_asset_site(db, asset_id),
        classifications=sorted(set(classifications))[:32],
        summary=description[:2048],
        raw_reference=(f"wazuh://{source_instance}/{source_event_id}" if source_event_id else None),
        attributes=attributes,
        trust="untrusted_evidence",
    )


def normalize_suricata(
    db: Session,
    *,
    source_instance: str,
    payload: dict[str, Any],
) -> CanonicalEventEnvelope:
    event_type = str(payload.get("event_type") or "unknown").lower()
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    flow_id = str(payload.get("flow_id")) if payload.get("flow_id") is not None else None
    signature_id = str(alert.get("signature_id")) if alert.get("signature_id") is not None else None
    tx_id = str(payload.get("tx_id")) if payload.get("tx_id") is not None else None
    source_event_id = ":".join(item for item in (flow_id, event_type, signature_id, tx_id) if item)
    source_event_id = source_event_id or None

    native_severity = int(alert.get("severity") or 0)
    severity = {1: 9, 2: 7, 3: 5}.get(native_severity, 4 if event_type == "alert" else 2)
    signature = str(alert.get("signature") or "")
    category = str(alert.get("category") or "")
    if event_type == "alert":
        summary = signature or category or "Suricata network alert"
        canonical_type = "network.alert"
    elif event_type == "anomaly":
        anomaly = payload.get("anomaly") if isinstance(payload.get("anomaly"), dict) else {}
        summary = str(anomaly.get("event") or "Suricata network anomaly")
        canonical_type = "network.anomaly"
    else:
        summary = f"Suricata {event_type} telemetry"
        canonical_type = f"network.{event_type}" if event_type.isidentifier() else "network.event"

    classifications = [f"suricata:{event_type}"[:128]]
    indicator_text = f"{signature} {category}".lower()
    if "command and control" in indicator_text or " c2" in f" {indicator_text}":
        classifications.append("network.c2")

    src_ip = str(payload.get("src_ip")) if payload.get("src_ip") else None
    dest_ip = str(payload.get("dest_ip")) if payload.get("dest_ip") else None
    asset_id = _unique_asset_by_address(db, [src_ip, dest_ip])
    attributes: dict[str, Any] = {
        "flow_id": flow_id,
        "src_ip": src_ip,
        "src_port": payload.get("src_port"),
        "dest_ip": dest_ip,
        "dest_port": payload.get("dest_port"),
        "proto": payload.get("proto"),
        "app_proto": payload.get("app_proto"),
        "direction": payload.get("direction"),
        "alert": alert or None,
    }
    for key in ("dns", "tls", "http", "anomaly", "fileinfo"):
        if isinstance(payload.get(key), dict):
            attributes[key] = payload[key]

    return CanonicalEventEnvelope(
        event_id=uuid.uuid4(),
        occurred_at=_parse_timestamp(payload.get("timestamp")),
        ingested_at=utcnow(),
        source=EventSource(
            connector="suricata",
            instance=source_instance,
            source_event_id=source_event_id,
        ),
        type=canonical_type,
        severity=severity,
        confidence=0.9 if event_type == "alert" else 0.7,
        asset_id=asset_id,
        site_id=_asset_site(db, asset_id),
        classifications=classifications,
        summary=summary[:2048],
        raw_reference=(
            f"suricata://{source_instance}/{source_event_id}" if source_event_id else None
        ),
        attributes=attributes,
        trust="untrusted_evidence",
    )


def event_to_envelope(event: CanonicalEvent) -> CanonicalEventEnvelope:
    return CanonicalEventEnvelope(
        event_id=event.id,
        schema_version="1.0.0",
        occurred_at=event.occurred_at,
        ingested_at=event.ingested_at,
        source=EventSource(
            connector=event.source_connector,
            instance=event.source_instance,
            source_event_id=event.source_event_id,
        ),
        type=event.event_type,
        severity=event.severity,
        confidence=event.confidence,
        asset_id=event.asset_id,
        site_id=event.site_id,
        classifications=event.classifications,
        summary=event.summary,
        raw_reference=event.raw_reference,
        attributes=event.attributes,
        trust="untrusted_evidence",
        correlation_id=event.correlation_id,
        causation_id=event.causation_id,
    )


def _persist_envelope(
    db: Session,
    envelope: CanonicalEventEnvelope,
    raw_payload: dict[str, Any],
) -> tuple[CanonicalEvent, bool]:
    digest = _json_digest(raw_payload)
    dedupe_key = _dedupe_key(
        envelope.source.connector,
        envelope.source.instance,
        envelope.source.source_event_id,
        digest,
    )
    existing = db.scalar(select(CanonicalEvent).where(CanonicalEvent.dedupe_key == dedupe_key))
    if existing is not None:
        return existing, True

    event = CanonicalEvent(
        id=envelope.event_id,
        schema_version=envelope.schema_version,
        occurred_at=envelope.occurred_at,
        ingested_at=envelope.ingested_at,
        source_connector=envelope.source.connector,
        source_instance=envelope.source.instance,
        source_event_id=envelope.source.source_event_id,
        dedupe_key=dedupe_key,
        event_type=envelope.type,
        severity=envelope.severity,
        confidence=envelope.confidence,
        asset_id=envelope.asset_id,
        site_id=envelope.site_id,
        classifications=envelope.classifications,
        summary=envelope.summary,
        raw_reference=envelope.raw_reference,
        attributes=envelope.attributes,
        trust="untrusted_evidence",
        correlation_id=envelope.correlation_id,
        causation_id=envelope.causation_id,
    )
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(CanonicalEvent).where(CanonicalEvent.dedupe_key == dedupe_key))
        if existing is None:
            raise
        return existing, True

    db.add(
        RawEventReference(
            canonical_event_id=event.id,
            source_type=envelope.source.connector,
            source_pointer=envelope.raw_reference,
            payload_sha256=digest,
        )
    )
    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="telemetry.event.canonicalized",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "event_id": str(event.id),
                "source": event.source_connector,
                "asset_id": str(event.asset_id) if event.asset_id else None,
                "trust": "untrusted_evidence",
            },
        )
    )
    db.flush()
    return event, False


def observe_feature(
    db: Session,
    *,
    asset_id: uuid.UUID,
    feature_key: str,
    value: float,
    observed_at: datetime,
    source_event_id: uuid.UUID | None = None,
    threshold: float = 3.0,
    minimum_samples: int = 5,
) -> AnomalyFinding | None:
    definition = db.get(FeatureDefinition, feature_key)
    if definition is None:
        db.add(
            FeatureDefinition(
                key=feature_key,
                description="Deterministic running baseline using Welford mean/variance",
                algorithm="welford_zscore",
                config={"threshold": threshold, "minimum_samples": minimum_samples},
            )
        )
    sample = FeatureSample(
        asset_id=asset_id,
        feature_key=feature_key,
        value=float(value),
        observed_at=observed_at,
        source_event_id=source_event_id,
    )
    db.add(sample)
    db.flush()

    baseline = db.scalar(
        select(Baseline).where(
            Baseline.asset_id == asset_id,
            Baseline.feature_key == feature_key,
        )
    )
    if baseline is None:
        baseline = Baseline(asset_id=asset_id, feature_key=feature_key)
        db.add(baseline)
        db.flush()

    finding: AnomalyFinding | None = None
    if baseline.sample_count >= minimum_samples:
        variance = baseline.m2 / max(1, baseline.sample_count - 1)
        stddev = math.sqrt(max(0.0, variance))
        if stddev > 0:
            score = abs(value - baseline.mean) / stddev
        elif value != baseline.mean:
            score = 10.0
        else:
            score = 0.0
        if score >= threshold:
            finding = AnomalyFinding(
                asset_id=asset_id,
                feature_key=feature_key,
                sample_id=sample.id,
                score=score,
                threshold=threshold,
                reasons=[
                    "deterministic_zscore_threshold_exceeded",
                    f"baseline_samples:{baseline.sample_count}",
                ],
            )
            db.add(finding)

    new_count = baseline.sample_count + 1
    delta = value - baseline.mean
    new_mean = baseline.mean + delta / new_count
    delta2 = value - new_mean
    baseline.m2 += delta * delta2
    baseline.mean = new_mean
    baseline.sample_count = new_count
    baseline.updated_at = utcnow()
    return finding


def _shared_indicator_reasons(
    db: Session,
    incident_id: uuid.UUID,
    event: CanonicalEvent,
) -> list[str]:
    indicator_keys = ("src_ip", "dest_ip", "domain", "process_hash", "command_line")
    current = {
        key: event.attributes.get(key)
        for key in indicator_keys
        if event.attributes.get(key)
    }
    if not current:
        return []
    prior_events = db.scalars(
        select(CanonicalEvent)
        .join(IncidentEvidence, IncidentEvidence.event_id == CanonicalEvent.id)
        .where(IncidentEvidence.incident_id == incident_id)
    )
    reasons: list[str] = []
    for prior in prior_events:
        for key, value in current.items():
            if prior.attributes.get(key) == value:
                reason = f"shared_indicator:{key}"
                if reason not in reasons:
                    reasons.append(reason)
    return reasons


def correlate_event(db: Session, event: CanonicalEvent) -> Incident | None:
    if event.asset_id is None or event.severity < CORRELATABLE_SEVERITY:
        return None
    event_time = _as_utc(event.occurred_at)
    window_start = event_time - CORRELATION_WINDOW
    incident = db.scalar(
        select(Incident)
        .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
        .where(
            IncidentAsset.asset_id == event.asset_id,
            Incident.state.not_in(TERMINAL_INCIDENT_STATES),
            Incident.last_activity_at >= window_start,
        )
        .order_by(Incident.last_activity_at.desc())
        .limit(1)
    )

    created = incident is None
    if incident is None:
        incident = Incident(
            title=event.summary[:256],
            severity=event.severity,
            confidence=event.confidence,
            summary=f"Deterministic incident opened from {event.source_connector} telemetry",
            opened_at=event_time,
            last_activity_at=event_time,
        )
        db.add(incident)
        db.flush()
        db.add(IncidentAsset(incident_id=incident.id, asset_id=event.asset_id))
        reasons = ["initial_detection", "same_asset"]
    else:
        reasons = ["same_asset", "bounded_time_window:15m"]
        previous_sources = set(
            db.scalars(
                select(CanonicalEvent.source_connector)
                .join(IncidentEvidence, IncidentEvidence.event_id == CanonicalEvent.id)
                .where(IncidentEvidence.incident_id == incident.id)
            )
        )
        if previous_sources and event.source_connector not in previous_sources:
            reasons.append("cross_source_corroboration")
        reasons.extend(_shared_indicator_reasons(db, incident.id, event))
        incident.severity = max(incident.severity, event.severity)
        incident.confidence = max(incident.confidence, event.confidence)
        incident.last_activity_at = max(_as_utc(incident.last_activity_at), event_time)

    evidence = IncidentEvidence(
        incident_id=incident.id,
        event_id=event.id,
        correlation_reasons=sorted(set(reasons)),
    )
    db.add(evidence)
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            occurred_at=event_time,
            entry_type="evidence_added",
            summary=event.summary,
            evidence_event_id=event.id,
            details={
                "source": event.source_connector,
                "correlation_reasons": evidence.correlation_reasons,
                "trust": "untrusted_evidence",
            },
        )
    )
    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="incident.created" if created else "incident.updated",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "incident_id": str(incident.id),
                "event_id": str(event.id),
                "correlation_reasons": evidence.correlation_reasons,
            },
        )
    )
    db.flush()
    return incident


def ingest_event(
    db: Session,
    *,
    source: str,
    source_instance: str,
    payload: dict[str, Any],
) -> tuple[CanonicalEvent, bool, Incident | None]:
    if source == "wazuh":
        envelope = normalize_wazuh(db, source_instance=source_instance, payload=payload)
    elif source == "suricata":
        envelope = normalize_suricata(db, source_instance=source_instance, payload=payload)
    else:
        raise ValueError("unsupported telemetry source")

    event, duplicate = _persist_envelope(db, envelope, payload)
    if duplicate:
        return event, True, None
    finding = None
    if event.asset_id is not None:
        finding = observe_feature(
            db,
            asset_id=event.asset_id,
            feature_key="security.event_severity",
            value=float(event.severity),
            observed_at=event.occurred_at,
            source_event_id=event.id,
        )
    incident = correlate_event(db, event)
    if finding is not None:
        message_id = str(uuid.uuid4())
        db.add(
            OutboxEvent(
                subject="finding.anomaly.created",
                message_id=message_id,
                payload={
                    "message_id": message_id,
                    "finding_id": str(finding.id),
                    "asset_id": str(finding.asset_id),
                    "feature_key": finding.feature_key,
                    "score": finding.score,
                },
            )
        )
    return event, False, incident


def transition_incident(
    db: Session,
    *,
    incident: Incident,
    new_state: str,
    reason: str,
    actor_id: str,
) -> Incident:
    if new_state == incident.state:
        raise InvalidIncidentTransition("incident is already in requested state")
    if new_state not in INCIDENT_TRANSITIONS.get(incident.state, set()):
        raise InvalidIncidentTransition(
            f"invalid incident transition {incident.state}->{new_state}"
        )
    previous = incident.state
    incident.state = new_state
    now = utcnow()
    incident.last_activity_at = now
    if new_state == "RESOLVED":
        incident.resolved_at = now
    if new_state in {"CLOSED", "FALSE_POSITIVE"}:
        incident.closed_at = now
    if previous == "RESOLVED" and new_state == "INVESTIGATING":
        incident.resolved_at = None
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            occurred_at=now,
            entry_type="state_transition",
            summary=f"Incident state changed from {previous} to {new_state}",
            details={"reason": reason, "actor_id": actor_id},
        )
    )
    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="incident.state_changed",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "incident_id": str(incident.id),
                "previous_state": previous,
                "state": new_state,
                "actor_id": actor_id,
            },
        )
    )
    return incident
