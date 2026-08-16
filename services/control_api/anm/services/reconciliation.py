import ipaddress
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from anm.models import (
    Asset,
    AssetAddress,
    AssetIdentifier,
    AssetObservation,
    ConnectorInstance,
    OutboxEvent,
    ReconciliationCandidate,
    TopologyEdge,
    utcnow,
)

SOURCE_NAMESPACES = {"netbox", "librenms"}
IMMUTABLE_NAMESPACES = {"serial", "device_uuid", "chassis_uuid"}
MAC_NAMESPACES = {"mac"}
NAME_NAMESPACES = {"hostname", "fqdn"}
VALID_ASSET_TYPES = {
    "endpoint",
    "server",
    "network_device",
    "firewall",
    "router",
    "switch",
    "wireless_ap",
    "hypervisor",
    "virtual_machine",
    "iot",
    "printer",
    "service",
    "unknown",
}
VALID_PROTECTED_ROLES = {
    "identity",
    "backup",
    "core_network",
    "security_control",
    "platform_control",
    "hypervisor",
    "critical_application",
}


class ImmutableIdentityConflict(ValueError):
    pass


def _normalise_identifier(namespace: str, value: str) -> tuple[str, str]:
    namespace = namespace.strip().lower()
    value = value.strip()
    if namespace in NAME_NAMESPACES | MAC_NAMESPACES:
        value = value.lower()
    return namespace, value


def _management_ip(attributes: dict[str, Any]) -> str | None:
    value = attributes.get("management_ip")
    if not value:
        return None
    candidate = str(value).split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _identifier_asset_ids(db: Session, namespace: str, value: str) -> set[uuid.UUID]:
    rows = db.scalars(
        select(AssetIdentifier.asset_id).where(
            AssetIdentifier.namespace == namespace,
            AssetIdentifier.value == value,
        )
    )
    return set(rows)


def _asset_has_immutable_mismatch(
    db: Session,
    asset_id: uuid.UUID,
    identifiers: list[dict[str, Any]],
) -> list[str]:
    mismatches: list[str] = []
    for item in identifiers:
        namespace, value = _normalise_identifier(str(item["namespace"]), str(item["value"]))
        if namespace not in IMMUTABLE_NAMESPACES:
            continue
        existing = set(
            db.scalars(
                select(AssetIdentifier.value).where(
                    AssetIdentifier.asset_id == asset_id,
                    AssetIdentifier.namespace == namespace,
                )
            )
        )
        if existing and value not in existing:
            mismatches.append(f"immutable_mismatch:{namespace}")
    return mismatches


def _candidate_scores(
    db: Session,
    observation: AssetObservation,
) -> tuple[dict[uuid.UUID, float], dict[uuid.UUID, list[str]], set[uuid.UUID]]:
    scores: dict[uuid.UUID, float] = defaultdict(float)
    reasons: dict[uuid.UUID, list[str]] = defaultdict(list)
    strong_assets: set[uuid.UUID] = set()

    for item in observation.identifiers:
        namespace, value = _normalise_identifier(str(item["namespace"]), str(item["value"]))
        matched = _identifier_asset_ids(db, namespace, value)
        if namespace in SOURCE_NAMESPACES:
            score = 1.0
            strong_assets.update(matched)
            reason = f"source_mapping:{namespace}"
        elif namespace in IMMUTABLE_NAMESPACES:
            score = 0.98
            strong_assets.update(matched)
            reason = f"immutable_identifier:{namespace}"
        elif namespace in MAC_NAMESPACES:
            score = 0.90
            reason = "mac_match"
        elif namespace == "fqdn":
            score = 0.80
            reason = "fqdn_match"
        elif namespace == "hostname":
            score = 0.75
            reason = "hostname_match"
        else:
            score = 0.0
            reason = ""
        for asset_id in matched:
            if score > scores[asset_id]:
                scores[asset_id] = score
            if reason and reason not in reasons[asset_id]:
                reasons[asset_id].append(reason)

    management_ip = _management_ip(observation.attributes)
    if management_ip:
        for asset_id in db.scalars(
            select(AssetAddress.asset_id).where(AssetAddress.address == management_ip)
        ):
            if 0.35 > scores[asset_id]:
                scores[asset_id] = 0.35
            if "ip_match_weak_evidence" not in reasons[asset_id]:
                reasons[asset_id].append("ip_match_weak_evidence")

    return dict(scores), dict(reasons), strong_assets


def _record_candidates(
    db: Session,
    observation: AssetObservation,
    scores: dict[uuid.UUID, float],
    reasons: dict[uuid.UUID, list[str]],
    *,
    status: str,
    extra_reasons: list[str] | None = None,
) -> None:
    for asset_id, score in scores.items():
        combined = list(reasons.get(asset_id, []))
        for reason in extra_reasons or []:
            if reason not in combined:
                combined.append(reason)
        db.add(
            ReconciliationCandidate(
                observation_id=observation.id,
                candidate_asset_id=asset_id,
                score=score,
                reasons=combined,
                status=status,
            )
        )


def _connector(db: Session, observation: AssetObservation) -> ConnectorInstance:
    connector = db.get(ConnectorInstance, observation.connector_instance_id)
    if connector is None:
        raise ValueError("observation references unknown connector")
    return connector


def _new_asset_from_observation(db: Session, observation: AssetObservation) -> Asset:
    connector = _connector(db, observation)
    attributes = observation.attributes
    asset_type = str(attributes.get("asset_type", "unknown"))
    if asset_type not in VALID_ASSET_TYPES:
        asset_type = "unknown"
    roles = [
        str(role)
        for role in attributes.get("protected_roles", [])
        if str(role) in VALID_PROTECTED_ROLES
    ]
    display_name = str(
        attributes.get("display_name")
        or attributes.get("hostname")
        or f"asset-{str(observation.id)[:8]}"
    )
    asset = Asset(
        display_name=display_name,
        asset_type=asset_type,
        criticality=str(attributes.get("criticality", "standard")),
        status=str(attributes.get("status", "active")),
        site_id=connector.site_id,
        network_zone=(
            str(attributes["network_zone"]) if attributes.get("network_zone") else None
        ),
        protected_roles=sorted(set(roles)),
    )
    db.add(asset)
    db.flush()
    _apply_observation_to_asset(db, observation, asset)
    return asset


def _apply_observation_to_asset(
    db: Session,
    observation: AssetObservation,
    asset: Asset,
) -> None:
    mismatches = _asset_has_immutable_mismatch(db, asset.id, observation.identifiers)
    if mismatches:
        raise ImmutableIdentityConflict(",".join(mismatches))

    now = utcnow()
    for item in observation.identifiers:
        namespace, value = _normalise_identifier(str(item["namespace"]), str(item["value"]))
        existing = db.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.namespace == namespace,
                AssetIdentifier.value == value,
            )
        )
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, float(item.get("confidence", 1.0)))
        else:
            db.add(
                AssetIdentifier(
                    asset_id=asset.id,
                    namespace=namespace,
                    value=value,
                    confidence=float(item.get("confidence", 1.0)),
                    first_seen=observation.observed_at,
                    last_seen=observation.observed_at,
                )
            )

    management_ip = _management_ip(observation.attributes)
    if management_ip:
        address = db.scalar(
            select(AssetAddress).where(
                AssetAddress.asset_id == asset.id,
                AssetAddress.address == management_ip,
            )
        )
        source = _connector(db, observation).connector_type
        if address:
            address.last_seen = now
        else:
            db.add(
                AssetAddress(
                    asset_id=asset.id,
                    address=management_ip,
                    source=source,
                    first_seen=observation.observed_at,
                    last_seen=observation.observed_at,
                )
            )

    incoming_roles = {
        str(role)
        for role in observation.attributes.get("protected_roles", [])
        if str(role) in VALID_PROTECTED_ROLES
    }
    asset.protected_roles = sorted(set(asset.protected_roles) | incoming_roles)
    if not asset.network_zone and observation.attributes.get("network_zone"):
        asset.network_zone = str(observation.attributes["network_zone"])
    asset.updated_at = now
    observation.reconciled_asset_id = asset.id
    observation.reconciliation_state = "matched"

    message_id = str(uuid.uuid4())
    db.add(
        OutboxEvent(
            subject="asset.changed.reconciled",
            message_id=message_id,
            payload={
                "message_id": message_id,
                "asset_id": str(asset.id),
                "observation_id": str(observation.id),
                "connector_instance_id": str(observation.connector_instance_id),
            },
        )
    )


def reconcile_observation(db: Session, observation: AssetObservation) -> str:
    if observation.reconciled_asset_id is not None:
        return observation.reconciliation_state

    scores, reasons, strong_assets = _candidate_scores(db, observation)
    if len(strong_assets) > 1:
        observation.reconciliation_state = "conflict"
        _record_candidates(
            db,
            observation,
            scores,
            reasons,
            status="conflict",
            extra_reasons=["immutable_or_source_identity_disagreement"],
        )
        return "conflict"

    if len(strong_assets) == 1:
        asset_id = next(iter(strong_assets))
        mismatches = _asset_has_immutable_mismatch(db, asset_id, observation.identifiers)
        if mismatches:
            observation.reconciliation_state = "conflict"
            _record_candidates(
                db,
                observation,
                scores,
                reasons,
                status="conflict",
                extra_reasons=mismatches,
            )
            return "conflict"
        asset = db.get(Asset, asset_id)
        if asset is None:
            raise ValueError("candidate asset disappeared during reconciliation")
        _apply_observation_to_asset(db, observation, asset)
        return "matched"

    if scores:
        ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_asset_id, best_score = ordered[0]
        tied_best = sum(1 for _, score in ordered if score == best_score) > 1
        if best_score >= 0.90 and not tied_best:
            asset = db.get(Asset, best_asset_id)
            if asset is None:
                raise ValueError("candidate asset disappeared during reconciliation")
            mismatches = _asset_has_immutable_mismatch(db, asset.id, observation.identifiers)
            if not mismatches:
                _apply_observation_to_asset(db, observation, asset)
                return "matched"
        observation.reconciliation_state = "pending_review"
        _record_candidates(db, observation, scores, reasons, status="pending")
        return "pending_review"

    asset = _new_asset_from_observation(db, observation)
    observation.reconciliation_state = "created"
    observation.reconciled_asset_id = asset.id
    return "created"


def resolve_candidate(
    db: Session,
    candidate: ReconciliationCandidate,
    decision: str,
) -> Asset | None:
    observation = db.get(AssetObservation, candidate.observation_id)
    if observation is None:
        raise ValueError("candidate observation no longer exists")
    asset: Asset | None = None
    if decision == "attach":
        if candidate.candidate_asset_id is None:
            raise ValueError("candidate has no asset to attach")
        asset = db.get(Asset, candidate.candidate_asset_id)
        if asset is None:
            raise ValueError("candidate asset no longer exists")
        _apply_observation_to_asset(db, observation, asset)
    elif decision == "new_asset":
        asset = _new_asset_from_observation(db, observation)
        observation.reconciliation_state = "created_manual"
    elif decision == "reject":
        candidate.status = "rejected"
        candidate.resolution = "reject"
        candidate.resolved_at = utcnow()
        return None
    else:
        raise ValueError("unsupported reconciliation decision")

    for related in db.scalars(
        select(ReconciliationCandidate).where(
            ReconciliationCandidate.observation_id == observation.id
        )
    ):
        related.status = "resolved"
        related.resolution = decision
        related.resolved_at = utcnow()
    return asset


def rebuild_topology(db: Session) -> int:
    materialized = 0
    observations = db.scalars(
        select(AssetObservation).where(AssetObservation.reconciled_asset_id.is_not(None))
    )
    for observation in observations:
        connector = _connector(db, observation)
        for hint in observation.topology:
            namespace, value = _normalise_identifier(
                str(hint["target_namespace"]),
                str(hint["target_value"]),
            )
            targets = _identifier_asset_ids(db, namespace, value)
            if len(targets) != 1:
                continue
            target_id = next(iter(targets))
            source_id = observation.reconciled_asset_id
            if source_id is None or source_id == target_id:
                continue
            relationship = str(hint["relationship"])
            existing = db.scalar(
                select(TopologyEdge).where(
                    TopologyEdge.source_asset_id == source_id,
                    TopologyEdge.target_asset_id == target_id,
                    TopologyEdge.relationship == relationship,
                    TopologyEdge.source == connector.connector_type,
                    TopologyEdge.origin == "observed",
                )
            )
            if existing:
                existing.observed_at = observation.observed_at
                existing.confidence = float(hint.get("confidence", 1.0))
                existing.edge_metadata = dict(hint.get("metadata", {}))
                continue
            db.add(
                TopologyEdge(
                    source_asset_id=source_id,
                    target_asset_id=target_id,
                    relationship=relationship,
                    source=connector.connector_type,
                    origin="observed",
                    confidence=float(hint.get("confidence", 1.0)),
                    observed_at=observation.observed_at,
                    edge_metadata=dict(hint.get("metadata", {})),
                )
            )
            materialized += 1
    return materialized
