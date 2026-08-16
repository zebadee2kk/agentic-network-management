import hashlib
import json
from typing import Any

from anm.action_models import ActionProposal


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def proposal_binding(proposal: ActionProposal) -> dict[str, Any]:
    return {
        "proposal_id": str(proposal.id),
        "schema_version": proposal.schema_version,
        "revision": proposal.revision,
        "capability": proposal.capability,
        "capability_version": proposal.capability_version,
        "capability_digest": proposal.capability_digest,
        "implementation_digest": proposal.implementation_digest,
        "target_asset_id": str(proposal.target_asset_id),
        "parameters": proposal.parameters,
        "reason": proposal.reason,
        "incident_id": str(proposal.incident_id),
        "evidence_ids": sorted(proposal.evidence_ids),
        "confidence": proposal.confidence,
        "requested_by": {
            "type": proposal.requester_type,
            "id": proposal.requester_id,
            "roles": sorted(proposal.requester_roles),
        },
    }


def compute_proposal_digest(proposal: ActionProposal) -> str:
    return canonical_digest(proposal_binding(proposal))
