import hashlib
import json
from importlib import resources
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from anm.action_models import CapabilityDefinition

FORBIDDEN_CAPABILITY_IDS = {
    "shell.exec",
    "ssh.run",
    "powershell.run",
    "ansible.run_arbitrary_playbook",
    "http.request_arbitrary",
    "sql.execute_arbitrary",
    "firewall.apply_raw_config",
    "network.run_cli",
}


class CapabilityManifestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_.-]{1,128}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    description: str = Field(min_length=1, max_length=1024)
    risk: int = Field(ge=0, le=5)
    write: bool
    reversible: bool
    lifecycle: str = Field(pattern=r"^(DRAFT|REVIEWED|ENABLED|DEPRECATED|DISABLED)$")
    parameters_schema: dict[str, Any]
    execution: dict[str, Any]
    verification: dict[str, Any]
    rollback: dict[str, Any] | None = None


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_builtin_manifests() -> list[CapabilityManifestSpec]:
    root = resources.files("anm.capability_manifests")
    manifests: list[CapabilityManifestSpec] = []
    for item in sorted(root.iterdir(), key=lambda entry: entry.name):
        if not item.name.endswith(".json"):
            continue
        payload = json.loads(item.read_text(encoding="utf-8"))
        manifest = CapabilityManifestSpec.model_validate(payload)
        if manifest.id in FORBIDDEN_CAPABILITY_IDS:
            raise ValueError(f"forbidden generic capability in built-in catalogue: {manifest.id}")
        if manifest.execution.get("adapter") != "reserved_phase6":
            raise ValueError(
                f"Phase 5 capability {manifest.id} contains an executable adapter; "
                "only reserved_phase6 is permitted"
            )
        manifests.append(manifest)
    if not manifests:
        raise ValueError("built-in capability catalogue is empty")
    return manifests


def capability_digests(manifest: CapabilityManifestSpec) -> tuple[str, str, str]:
    manifest_dict = manifest.model_dump(mode="json")
    manifest_digest = _digest(manifest_dict)
    implementation_digest = _digest(
        {
            "execution": manifest.execution,
            "verification": manifest.verification,
            "rollback": manifest.rollback,
        }
    )
    capability_digest = _digest(
        {
            "id": manifest.id,
            "version": manifest.version,
            "manifest_digest": manifest_digest,
            "implementation_digest": implementation_digest,
        }
    )
    return manifest_digest, implementation_digest, capability_digest


def sync_builtin_capabilities(db: Session) -> list[CapabilityDefinition]:
    synced: list[CapabilityDefinition] = []
    for manifest in _load_builtin_manifests():
        manifest_digest, implementation_digest, capability_digest = capability_digests(manifest)
        definition = db.scalar(
            select(CapabilityDefinition).where(
                CapabilityDefinition.capability_id == manifest.id,
                CapabilityDefinition.version == manifest.version,
            )
        )
        payload = manifest.model_dump(mode="json")
        if definition is None:
            definition = CapabilityDefinition(
                capability_id=manifest.id,
                version=manifest.version,
                description=manifest.description,
                risk=manifest.risk,
                write=manifest.write,
                reversible=manifest.reversible,
                lifecycle=manifest.lifecycle,
                parameter_schema=manifest.parameters_schema,
                manifest=payload,
                manifest_digest=manifest_digest,
                implementation_digest=implementation_digest,
                capability_digest=capability_digest,
            )
            db.add(definition)
        else:
            definition.description = manifest.description
            definition.risk = manifest.risk
            definition.write = manifest.write
            definition.reversible = manifest.reversible
            definition.lifecycle = manifest.lifecycle
            definition.parameter_schema = manifest.parameters_schema
            definition.manifest = payload
            definition.manifest_digest = manifest_digest
            definition.implementation_digest = implementation_digest
            definition.capability_digest = capability_digest
        synced.append(definition)
    db.flush()
    return synced
