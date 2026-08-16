# Low-Level Design

## 1. Purpose

This document translates the HLD into implementable service boundaries, APIs, schemas, state machines, message subjects, trust rules and execution contracts for v1.

The design intentionally favours explicit contracts over clever framework coupling. Every service may be refactored internally, but published event/API/schema contracts require versioning.

## 2. Proposed implementation stack

### Control plane

- Python 3.12+ runtime target initially; exact supported minor is pinned in implementation.
- FastAPI-style HTTP API with Pydantic-style request/response validation.
- SQLAlchemy/Alembic-style explicit relational schema/migrations.
- PostgreSQL for platform state.
- NATS JetStream client for asynchronous events/jobs.

### UI

- TypeScript web application.
- React-based component architecture.
- OpenAPI-generated API client where practical.
- No direct browser access to upstream products, OpenBao, OPA or NATS.

### Policy/secrets

- OPA Rego policies stored under `policies/opa/` and versioned with releases.
- OpenBao accessed using workload/service identity; no shared platform-wide root token.

### AI

- Thin internal `ModelGateway` interface.
- Structured response schemas for all platform-impacting output.
- Agents use platform tool APIs, never raw infrastructure SDK credentials.

## 3. Service boundaries

For v1, these logical services MAY be deployed in fewer physical processes to reduce appliance overhead. The boundaries remain logical contracts so they can split later.

### `control-api`

Responsibilities:

- HTTP API
- authentication integration
- RBAC checks
- request correlation IDs
- resource orchestration
- no direct infrastructure credentials

### `asset-service`

Tables/objects:

- `assets`
- `asset_identifiers`
- `asset_addresses`
- `asset_labels`
- `asset_relationships`
- `asset_observations`
- `reconciliation_candidates`

Key rules:

- `assets.id` is UUID and immutable.
- external connector IDs live in `asset_identifiers`.
- IP addresses are attributes/observations, not durable identity on their own.
- merges preserve an audit record and aliases to the surviving ID.

### `topology-service`

Tables/objects:

- `topology_nodes` (references canonical assets or logical network objects)
- `topology_edges`
- `topology_observations`
- `topology_drift_findings`

Initial edge types:

- `connected_to`
- `member_of_vlan`
- `routed_via`
- `hosted_on`
- `depends_on`
- `managed_by`
- `located_at`

Every edge includes `source`, `confidence`, `observed_at`, and optional `expires_at`.

### `event-service`

Objects:

- `canonical_events`
- `raw_event_references`
- `event_processing_receipts`

`canonical_events` is intentionally compact. Large/raw payload retention remains in upstream systems or future object storage.

### `behaviour-service`

Objects:

- `feature_definitions`
- `feature_samples`
- `baselines`
- `anomaly_findings`

Feature evaluators are deterministic functions with explicit windows and versioned algorithm configuration.

### `incident-service`

Objects:

- `incidents`
- `incident_assets`
- `incident_evidence`
- `incident_hypotheses`
- `incident_timeline`
- `incident_findings`

State enum:

```text
NEW
TRIAGE
INVESTIGATING
ACTION_PROPOSED
AWAITING_APPROVAL
REMEDIATING
VERIFYING
RESOLVED
CLOSED
FALSE_POSITIVE
```

Only the incident service applies transitions.

### `agent-service`

Objects:

- `investigation_runs`
- `agent_steps`
- `model_invocations`
- `agent_outputs`

The service owns:

- tool allowlists by agent role
- evidence minimisation
- model request metadata
- schema validation
- token/cost accounting metadata

It does NOT own:

- secrets
- policy authority
- approval
- execution

### `action-service`

Objects:

- `capability_definitions`
- `action_proposals`
- `policy_decisions`
- `approval_requests`
- `approvals`
- `executions`
- `verification_results`
- `rollback_requests`

The action service is the only platform service allowed to create an execution request.

### `executor`

Responsibilities:

- consume authorized execution jobs
- validate execution token/context
- resolve capability implementation
- run prechecks
- retrieve required secret references from OpenBao
- execute deterministic adapter/playbook
- return execution result

No LLM SDK/library should be linked into the executor image.

### `verification-service`

Responsibilities:

- load capability verifier contract
- query independent sensor(s)
- evaluate expected postconditions
- mark verification success/failure
- propose rollback if declared and permitted

## 4. Canonical asset model

Minimum entity:

```json
{
  "id": "uuid",
  "display_name": "FIN-LT-023",
  "asset_type": "endpoint",
  "criticality": "standard",
  "site_id": "uuid-or-null",
  "network_zone": "staff",
  "status": "active",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

Identifier entity:

```json
{
  "asset_id": "uuid",
  "namespace": "wazuh",
  "external_id": "142",
  "confidence": 1.0,
  "first_seen": "timestamp",
  "last_seen": "timestamp"
}
```

Examples of namespaces:

```text
serial
mac
hostname
fqdn
netbox
librenms
wazuh
meshcentral
velociraptor
vendor:<name>
```

### Reconciliation order

Candidate matching should generally favour:

1. explicit existing connector mapping
2. immutable hardware/agent identifiers
3. serial/device UUID
4. MAC address with context
5. hostname/FQDN with context
6. IP address only as weak/temporary evidence

Conflicting immutable identifiers prohibit automatic merge.

## 5. Canonical event envelope

Normative JSON Schema lives under `schemas/event-envelope.schema.json`.

Conceptual fields:

```text
event_id
schema_version
occurred_at
ingested_at
source
source_event_id
type
severity
confidence
asset_id?
site_id?
classifications[]
summary
raw_reference?
attributes{}
trust="untrusted_evidence"
```

The normalizer must not map source strings into instruction fields. Text fields remain data.

## 6. NATS streams and consumers

Suggested streams:

### `OBSERVATIONS`

Subjects:

```text
asset.observed.>
topology.observed.>
telemetry.>
```

Retention: bounded by time/size; source telemetry is not a permanent event archive.

### `DOMAIN_EVENTS`

Subjects:

```text
asset.changed.>
topology.drift.>
finding.>
incident.>
```

### `ACTIONS`

Subjects:

```text
action.proposed
action.policy_decided
action.approval_requested
action.approved
action.denied
action.execution_requested
action.executed
action.verification_completed
action.rollback_requested
```

### `AUDIT`

Subject:

```text
audit.event
```

A durable consumer stores authoritative audit records in PostgreSQL. Future append-only external sinks may subscribe independently.

### Idempotency

Every message contains:

- `message_id`
- `event_id` or domain aggregate ID
- `causation_id`
- `correlation_id`

Consumers persist receipts keyed by consumer + message ID where a duplicate could cause side effects.

## 7. Incident correlation v1

Initial correlation is deterministic and explainable.

Signals:

- same canonical asset
- same user/principal where available
- source/destination overlap
- shared process/hash/domain/IP
- topology relationship
- bounded time windows
- known rule correlation groups

Output must record **why** events were grouped.

AI may suggest links during investigation, but AI suggestions do not silently merge incidents.

## 8. Action proposal contract

Normative schema lives under `schemas/action-proposal.schema.json`.

Conceptual example:

```json
{
  "proposal_id": "uuid",
  "capability": "endpoint.isolate",
  "capability_version": "1.0.0",
  "target_asset_id": "uuid",
  "parameters": {},
  "reason": "Probable C2 activity",
  "incident_id": "uuid",
  "evidence_ids": ["uuid"],
  "confidence": 0.97,
  "requested_by": {
    "type": "agent",
    "id": "soc-investigator"
  }
}
```

Unknown fields are rejected for security-sensitive payloads unless a schema version explicitly permits them.

## 9. Capability registry

Each capability has a manifest stored/versioned in source control.

Minimum fields:

```yaml
id: endpoint.isolate
version: 1.0.0
risk: 2
reversible: true
parameters_schema: schemas/capabilities/endpoint.isolate.json
required_connector_capabilities:
  - endpoint.isolate
prechecks:
  - target_online
  - target_not_protected_role
executor: endpoint
verification:
  strategy: network_isolation
rollback:
  capability: endpoint.unisolate
```

Runtime database records the exact manifest digest used.

## 10. Action state machine

```text
PROPOSED
  -> VALIDATING
  -> POLICY_PENDING
  -> DENIED
  -> APPROVAL_PENDING
  -> AUTHORIZED
  -> EXECUTION_PENDING
  -> EXECUTING
  -> VERIFYING
  -> SUCCEEDED
  -> FAILED
  -> ROLLBACK_PENDING
  -> ROLLING_BACK
  -> ROLLED_BACK
  -> ROLLBACK_FAILED
```

Invalid transitions are rejected.

## 11. OPA input/output contract

Input document:

```json
{
  "action": {
    "capability": "endpoint.isolate",
    "version": "1.0.0",
    "risk": 2,
    "reversible": true,
    "parameters": {}
  },
  "target": {
    "asset_id": "uuid",
    "asset_type": "endpoint",
    "criticality": "standard",
    "roles": [],
    "network_zone": "staff"
  },
  "incident": {
    "severity": "high",
    "confidence": 0.97
  },
  "requester": {
    "type": "agent",
    "id": "remediation-planner"
  },
  "environment": {
    "autonomy_level": 2,
    "maintenance_window": false
  }
}
```

Output contract:

```json
{
  "decision": "require_approval",
  "reasons": ["autonomy_level_2"],
  "required_roles": ["security_approver"]
}
```

Allowed decisions:

- `deny`
- `require_approval`
- `allow`

OPA failure or invalid output = deny/fail closed.

## 12. Approval rules

Approval record contains:

- action proposal digest
- policy decision ID
- approver identity
- decision
- timestamp
- expiry
- optional justification

If material action parameters change after approval, previous approval becomes invalid.

Risk 4+ actions require at least explicit human approval in v1; risk 5 destructive actions are prohibited by default policy.

## 13. Executor authorization

Execution jobs must include a signed/unguessable execution authorization reference generated only after policy/approval completion.

Executor independently re-fetches the authoritative action record; it must not trust parameters solely from a NATS message.

Before execution:

1. action state is `EXECUTION_PENDING`
2. policy decision remains valid
3. approval remains valid if required
4. capability/version exists and digest matches
5. target has not become policy-protected
6. idempotency key has not already completed

## 14. Secret handling

Database stores only secret references such as:

```text
openbao://network/fortigate/site-a
```

Only connector/executor service identities can dereference secrets they need.

AI/API responses must redact any field classified as secret even if an upstream connector accidentally returns it.

Logs must never contain secret values. Structured logging middleware should reject/redact configured sensitive field names.

## 15. Verification contract

Each capability declares postconditions.

Example `windows.restart_service`:

```yaml
postconditions:
  - source: wazuh
    check: service_state
    expected: running
  - source: tcp_probe
    check: port_open
    expected: true
```

A successful Ansible task followed by failed postconditions is `FAILED`, not `SUCCEEDED`.

## 16. AI agent tool boundaries

### Supervisor

Read/query/delegate only.

### SOC Analyst

Allowed tools:

- query canonical incident/event APIs
- query Wazuh through platform connector facade
- query Suricata evidence
- query asset/topology context
- add structured hypotheses/evidence links

### Network Analyst

Allowed tools:

- topology path queries
- LibreNMS metrics/state
- NetBox intended state
- read-only device connector queries explicitly exposed by control plane

### Remediation Planner

Allowed tools:

- list available capabilities for target
- get capability metadata/risk
- create action proposal

No agent receives `execute`, `ssh`, arbitrary URL fetch-to-internal-network, shell or secret tools.

## 17. Prompt injection handling

All evidence passed to models is wrapped in a typed evidence structure with explicit trust metadata.

The agent runtime must:

- separate system/developer/tool instructions from evidence text
- label evidence as untrusted
- never parse evidence text into tool invocations
- require tool calls to originate from model tool-call protocol and validate them against role allowlists
- reject attempts to provide unregistered tool names/parameters
- prohibit evidence from changing policy/autonomy configuration

## 18. API resource outline

```text
GET/POST   /api/v1/assets
GET/PATCH  /api/v1/assets/{id}
GET        /api/v1/assets/{id}/topology
GET        /api/v1/assets/{id}/events

GET/POST   /api/v1/networks
POST       /api/v1/discovery/runs
GET        /api/v1/discovery/runs/{id}

GET        /api/v1/incidents
GET/PATCH  /api/v1/incidents/{id}
POST       /api/v1/incidents/{id}/investigations

GET        /api/v1/capabilities
POST       /api/v1/actions/proposals
GET        /api/v1/actions/{id}
POST       /api/v1/actions/{id}/approve
POST       /api/v1/actions/{id}/deny

GET/POST   /api/v1/connectors
POST       /api/v1/connectors/{id}/test
GET        /api/v1/connectors/{id}/health

GET        /api/v1/audit
```

No generic `/execute-command` endpoint exists.

## 19. Connector SDK contract

Read side:

```text
test_connection()
health()
capabilities()
discover(scope)
query(resource, filters)
```

Write side is capability-based:

```text
precheck(capability, target, params)
execute(capability, target, params, secret_handles)
verify_hint(...)
```

Connector capability declarations are authoritative for what implementations exist, but platform policy is authoritative for whether they may be invoked.

## 20. Deployment/network rules

Suggested container networks:

```text
edge
control
data
identity
telemetry
ai
execution
management
```

Important constraints:

- AI network has no route to management network.
- executor network has no default Internet egress.
- telemetry ingestion cannot call execution endpoints.
- OpenBao and OPA are reachable only by explicitly permitted services.
- databases are not published on host interfaces by default.

Production VM host firewall rules must reinforce container-level segmentation.

## 21. Failure semantics

- OPA timeout/error -> action denied/fail closed.
- OpenBao timeout/error -> action remains pending/failed; no fallback plaintext credential.
- connector timeout -> retry only if capability is proven idempotent or execution state is safely reconcilable.
- ambiguous execution outcome -> `UNKNOWN`/manual review path rather than blind retry.
- verifier unavailable -> action remains unverified; do not claim success.

## 22. Testing requirements

Every capability requires:

- schema tests
- policy tests
- precheck tests
- executor unit/integration tests
- idempotency test
- verification test
- rollback test if reversible
- adversarial test where a malicious event/log attempts to trigger or alter the action

The platform may not enable Level 3+ autonomy until the relevant capability set passes the dedicated autonomy test suite.
