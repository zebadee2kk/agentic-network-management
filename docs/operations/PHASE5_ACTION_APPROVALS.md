# Phase 5 — Policy-gated action proposals and approvals

Phase 5 makes remediation authorization a first-class platform workflow. It **does not execute managed-infrastructure changes**.

## Boundary

```text
incident/evidence
      |
      v
 typed action proposal
      |
      v
 capability schema + digest binding
      |
      v
 OPA policy evaluation (fail closed)
      |
      +--> DENIED
      |
      +--> AUTHORIZED (policy says allow; still no executor in Phase 5)
      |
      `--> AWAITING_APPROVAL --> durable human approval/rejection
```

There is no executor service, execution queue, shell/SSH/PowerShell tool, infrastructure credential dereference or managed-network write path in Phase 5.

## Built-in capability catalogue

Built-in manifests live in `anm.capability_manifests` and are synchronized to the database when the control API starts. The shipped Phase-5 catalogue contains:

- `inventory.refresh` — risk 0, read only
- `endpoint.security_scan` — risk 1, read only/control activity
- `windows.restart_service` — risk 2 write
- `endpoint.isolate` — risk 2 write
- `firewall.block_ip` — risk 2 write

Every manifest contains only declarative metadata and a `reserved_phase6` implementation marker. Production execution code is intentionally absent.

The registry computes three SHA-256 values:

- `manifest_digest` — complete manifest
- `implementation_digest` — execution/verification/rollback portion
- `capability_digest` — capability/version plus the above digests

A proposal copies and binds the current capability and implementation digests.

## Proposal validation

`POST /api/v1/action-proposals` accepts a capability/version, target asset, bounded parameters, incident/evidence references, reason and confidence.

Before OPA is called, the control plane verifies:

1. capability/version exists and is `ENABLED`
2. target asset exists
3. incident exists
4. evidence IDs belong to that incident
5. parameters satisfy the capability-specific JSON Schema
6. the complete platform-built proposal satisfies `schemas/action-proposal.schema.json`

The requester identity and roles are derived from the authenticated principal; clients cannot assert a different human identity in the proposal payload.

## Policy contract

OPA receives an exact proposal snapshot:

```json
{
  "action": {
    "capability": "endpoint.isolate",
    "capability_version": "1.0.0",
    "risk": 2,
    "write": true,
    "reversible": true,
    "capability_digest": "...",
    "implementation_digest": "...",
    "proposal_digest": "..."
  },
  "target": {
    "asset_id": "...",
    "criticality": "standard",
    "protected_roles": []
  },
  "incident": {
    "id": "...",
    "severity": 9,
    "confidence": 0.97,
    "proposal_confidence": 0.95
  },
  "requester": {
    "type": "user",
    "id": "...",
    "roles": []
  },
  "environment": {"autonomy_level": 2}
}
```

The stored `policy_input_digest` proves which input was evaluated. OPA returns `decision`, `reasons`, `required_roles` and `policy_version`. Timeout, transport failure or invalid output returns a local `deny` decision.

## Baseline policy

The baseline policy is intentionally conservative:

- risk 5: always denied
- read-only capabilities: may be allowed without approval
- protected target role: `platform_approver`
- risk 4 write: `platform_approver`
- risk 3 write: `security_approver`
- autonomy Level 0–2 write: at least `operator_approver`
- low incident confidence: `security_approver`
- Level 3+ low-risk write with >=0.90 deterministic incident confidence: may be authorized by policy

`ANM_AUTONOMY_LEVEL=2` is the default.

An `AUTHORIZED` Phase-5 proposal means only that the authorization gate is satisfied. There is no dispatch path yet.

## Durable approvals

Approvals are records, never chat text. Each approval binds:

- proposal ID
- proposal digest
- capability digest
- implementation digest
- OPA policy version
- approver identity
- approver-role snapshot
- approve/reject decision

Role coverage is hierarchical for Phase 5:

- `platform_approver` may satisfy platform/security/operator approval requirements
- `security_approver` may satisfy security/operator requirements
- `operator_approver` satisfies operator approval only

## Mutation and drift

`POST /api/v1/action-proposals/{id}/revise` creates a new proposal revision in place. Changing target, parameters, reason, evidence or confidence recomputes the proposal digest and invalidates all prior approvals.

`POST /api/v1/action-proposals/{id}/reevaluate` checks the current capability/implementation digests and current policy binding. If capability artifacts or policy version/requirements changed, existing approvals become invalid and the proposal returns to the appropriate authorization state.

This implements INV-005 and INV-015: an approval cannot be replayed against materially different action content.

## Operator endpoints

- `GET /api/v1/capabilities`
- `POST /api/v1/action-proposals`
- `GET /api/v1/action-proposals`
- `GET /api/v1/action-proposals/approval-queue`
- `GET /api/v1/action-proposals/{id}`
- `POST /api/v1/action-proposals/{id}/revise`
- `POST /api/v1/action-proposals/{id}/reevaluate`
- `GET /api/v1/action-proposals/{id}/approvals`
- `POST /api/v1/action-proposals/{id}/approvals`

## Phase 6 handoff

Phase 6 may add a deterministic executor only after re-checking at dispatch time:

- proposal is still `AUTHORIZED`
- current proposal/capability/implementation digests still match
- policy is re-evaluated
- required approvals remain valid
- target protected roles have not changed
- idempotency identity is reserved
- prechecks pass

Execution success must then be independently verified and rollback semantics enforced. None of those write mechanisms are present in Phase 5.
