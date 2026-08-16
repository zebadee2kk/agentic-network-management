# High-Level Design

## 1. Architectural objective

Agentic Network Management (ANM) is a platform-owned control plane that composes replaceable monitoring, inventory, security and automation products into a safe closed-loop operations system.

The architecture deliberately separates five concerns:

1. **Observation** — sensors collect state and telemetry.
2. **Control** — the platform owns assets, incidents, approvals, policy integration and audit.
3. **Reasoning** — AI agents investigate evidence and propose actions.
4. **Authority** — deterministic policy decides whether an action may proceed.
5. **Execution** — deterministic executors perform pre-defined actions and independent verification checks the result.

## 2. Reference architecture

```text
                          USERS
                            |
                         HTTPS
                            |
                 +----------v----------+
                 |      Web / API      |
                 +----------+----------+
                            |
+---------------------------------------------------------------+
|                    PLATFORM CONTROL PLANE                     |
|                                                               |
|  Asset Registry      Incident Engine      Approval Service    |
|  Topology Service    Correlation Engine   Action Service      |
|  Connector Manager   Behaviour Service    Audit Service       |
|  AI Supervisor       Model Gateway        Verification        |
+----------+----------------------+--------------------+---------+
           |                      |                    |
           v                      v                    v
     NATS JetStream           OpenBao                OPA
     event backbone           secrets              authority
           |
   +-------+---------------------------------------------------+
   |                       CONNECTOR LAYER                     |
   |                                                           |
   | NetBox | LibreNMS | Wazuh | Suricata | Ansible | Vendor |
   +--+-----------+---------+---------+-----------+------------+
      |           |         |         |           |
      v           v         v         v           v
  topology    network    endpoint   NIDS      managed assets
   truth       state      security
```

Optional capabilities such as Zeek, MeshCentral, Velociraptor and vulnerability scanners connect through the same connector/provider model and do not own platform workflow state.

## 3. Trust zones

### 3.1 Edge/UI zone

Contains browser-facing reverse proxy/UI endpoints. It may call only documented control-plane APIs. It has no direct route to managed infrastructure and no access to raw infrastructure credentials.

### 3.2 Control zone

Contains platform APIs and stateful control-plane services. It can read/write platform-owned PostgreSQL data, publish/consume permitted NATS subjects and invoke policy/secrets APIs according to service identity.

### 3.3 AI reasoning zone

Contains agent workers and model gateway. It has access only to read/query tools and proposal APIs explicitly exposed by the control plane. It has no direct route to managed networks and no secret-read capability.

### 3.4 Execution zone

Contains the executor and connector workers permitted to change managed assets. It can request narrowly scoped secrets from OpenBao. It accepts only validated, authorized capability executions from the action service. Internet egress is denied by default.

### 3.5 Telemetry zone

Contains inbound telemetry collectors and adapters. Data from this zone is untrusted. It may publish normalized events but may not influence control instructions directly.

### 3.6 Data/identity zone

Contains PostgreSQL, OpenBao, OPA and optionally Keycloak. Network access is restricted by service role; these services are not directly exposed to managed endpoints or the public Internet.

## 4. Platform-owned domain model

The platform is authoritative for:

- canonical asset UUID and external identity mappings
- incidents and incident state
- evidence references
- findings/anomalies
- AI investigation records
- action proposals
- policy decisions
- approvals
- executions
- verification results
- audit trail
- connector configuration/state references

The platform is **not** authoritative for all underlying telemetry or specialist data. Raw data should remain in its source system where practical.

## 5. External authority boundaries

### NetBox

Authoritative for intended network/infrastructure representation where configured: sites, network devices, interfaces, prefixes, VLANs, VRFs, IPs, circuits and topology relationships.

### LibreNMS

Authoritative for its observed network-device polling/discovery state and health metrics.

### Wazuh

Authoritative for Wazuh endpoint agents, alerts and endpoint/security telemetry stored by Wazuh.

### Suricata

Authoritative for NIDS events produced by its sensors.

### OpenBao

Authoritative for secrets and credential lifecycle.

### OPA

Authoritative for allow/deny/approval policy decisions at the moment of action authorization.

### Ansible/vendor executor

Authoritative only for executor activity/result metadata; success is not accepted until verification completes.

## 6. Core services

### API Gateway / Control API

- user/API entrypoint
- authentication/authorization integration
- request validation
- resource APIs
- rate limiting and correlation IDs

### Asset Service

- canonical asset CRUD
- external identity mappings
- identity confidence and conflict management
- asset criticality and network-zone context

### Discovery Service

- schedules passive/active discovery within approved scopes
- executes discovery adapters
- creates observations rather than directly mutating identity

### Reconciliation Service

- converts observations into candidate asset matches
- merges/links identities when confidence rules permit
- raises conflicts for manual review

### Topology Service

- combines intended and observed relationships
- exposes path/context queries to users and agents
- flags drift between source-of-truth and observed state

### Event Normalizer

- converts source-specific payloads into canonical event envelopes
- labels untrusted fields
- records source references

### Behaviour Service

- deterministic/statistical feature calculation
- baseline storage
- anomaly findings

### Correlation Service

- groups related canonical events/findings into incidents
- uses asset identity, time, topology and rule relationships

### Incident Service

- owns incident state machine
- evidence/timeline/hypothesis associations
- interfaces for human and agent investigation

### AI Supervisor

- delegates read-only investigation tasks to specialist agents
- enforces tool scopes
- validates structured results
- records model/provider metadata and evidence lineage

### Remediation Planner

- converts an investigation conclusion into one or more typed capability proposals
- cannot execute a capability

### Policy Service

- creates OPA input documents from action, asset, incident, actor and environment context
- records policy bundle/version and result

### Approval Service

- owns approval requests, expiry, approver identity and separation-of-duties rules

### Action Service

- validates capability/version/parameters
- enforces idempotency
- invokes policy/approval flow
- dispatches authorized execution jobs

### Executor

- maps capability to known implementation
- retrieves JIT secrets
- performs pre-check, action and local result capture
- has no model access

### Verification Service

- evaluates capability-specific postconditions using independent signals where practical
- determines verified success/failure
- can request declared rollback through the same policy/action path

### Audit Service

- records append-oriented audit events for significant decisions and state transitions
- protects evidence of who/what/when/why/model/policy/action/result

## 7. Event backbone

NATS JetStream is the asynchronous backbone.

Recommended subject taxonomy:

```text
asset.observed.*
asset.reconciled.*
asset.changed.*

topology.observed.*
topology.drift.*

telemetry.security.*
telemetry.network.*
telemetry.health.*

finding.created.*
finding.updated.*

incident.created
incident.updated
incident.escalated
incident.resolved

action.proposed
action.policy_decided
action.approval_requested
action.approved
action.denied
action.execution_requested
action.executed
action.verification_completed
action.rollback_requested

audit.event
```

All consumers must be idempotent. At-least-once delivery is assumed.

## 8. Primary data flows

### 8.1 Discovery

```text
approved scope -> discovery adapter -> observation -> NATS
-> reconciliation -> canonical asset -> topology update -> audit
```

### 8.2 Security incident

```text
Wazuh/Suricata -> source connector -> normalizer -> canonical event
-> correlation/behaviour -> incident -> investigation -> evidence/hypothesis
```

### 8.3 Remediation

```text
investigation -> typed action proposal -> schema validation
-> OPA -> optional approval -> execution job -> JIT credential
-> deterministic action -> verification -> success/failure/rollback -> audit
```

### 8.4 AI request

```text
incident context -> evidence selector -> redaction/data policy
-> specialist agent -> model gateway -> structured output validation
-> evidence-linked investigation result
```

No secrets or direct executor credentials enter this path.

## 9. Deployment profiles

### Minimal

- platform API/UI
- PostgreSQL
- NATS
- OPA
- OpenBao
- NetBox
- LibreNMS

### Security

Minimal plus:

- Wazuh
- Suricata

### AI

- model gateway
- agent supervisor/workers

### RMM

- MeshCentral connector/profile

### DFIR

- Velociraptor connector/profile

### NDR

- Zeek connector/profile

### Vulnerability

- a `VulnerabilityProvider` implementation (Greenbone community suitable for lab/non-production evaluation unless deployment support is separately engineered)

### Production

- external/Keycloak OIDC
- OpenTelemetry/Prometheus/Grafana
- backups, image signing/provenance, hardened host controls

## 10. Deployment form factors

### Development/lab

Docker Compose on a supported Linux host.

### Recommended production

A versioned Linux VM appliance image with the supported container runtime, host firewalling, storage layout and upgrade tooling controlled by the project.

### Scale/enterprise future

Kubernetes and/or horizontally separated services only after the single-appliance architecture and service contracts are stable.

## 11. Availability and degraded modes

The platform must explicitly represent degraded states.

Examples:

- AI unavailable -> monitoring/correlation/manual operations continue.
- Wazuh unavailable -> endpoint security visibility degraded; network monitoring continues.
- NetBox unavailable -> existing cached topology remains readable; authoritative topology writes are suspended.
- OPA unavailable -> **fail closed for writes**.
- OpenBao unavailable -> privileged actions cannot execute; reads continue where possible.
- NATS unavailable -> producers use bounded retry/outbox patterns; actions are not silently lost.
- PostgreSQL unavailable -> control-plane mutations stop; sensors may buffer according to connector design.

## 12. Security architecture summary

The HLD depends on hard technical separation:

- models cannot reach managed assets directly
- models cannot retrieve secrets
- all writes are typed capabilities
- OPA is mandatory for writes and fails closed
- human approval is a platform state, not a prompt convention
- executors do not reason
- verification is separate from execution
- logs/evidence are untrusted input
- audit records link every decision to evidence, policy and actor/model

## 13. Key architectural decisions pending detailed ADRs

- Backend implementation: Python/FastAPI-style typed service layer is the default candidate.
- UI implementation: TypeScript/React-style web application is the default candidate.
- Database access: SQL migrations and explicit schemas; no implicit schema creation in production.
- AI framework: keep agent runtime thin and replaceable; do not couple domain objects to one agent framework.
- Topology representation: start in PostgreSQL relational structures plus recursive/path queries; introduce a graph database only if measured requirements justify it.
- Workflow: PostgreSQL state machines + NATS for v1; no Temporal dependency in v1.
