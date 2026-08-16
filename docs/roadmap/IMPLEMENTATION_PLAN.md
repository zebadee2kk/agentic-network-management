# Implementation Plan

The project is built in gated phases. Later phases may start only when the security and contract prerequisites they depend on exist.

## Phase 0 — Architecture and repository foundation

**Goal:** freeze the project contract before broad implementation.

Deliverables:

- PRD, HLD, LLD
- threat model and security invariants
- component decision matrix
- canonical asset/event/action schemas
- baseline OPA policy
- ADRs for core architectural choices
- connector/capability contracts
- test strategy
- CI foundations for schema/policy/security validation

Exit criteria:

- architecture review accepted
- no unresolved path allowing model -> arbitrary execution
- v1 scope agreed

## Phase 1 — Control-plane skeleton

**Goal:** a running local platform with durable domain state but no managed-network write capability.

Deliverables:

- backend application skeleton
- PostgreSQL migrations
- NATS connectivity and outbox/idempotency patterns
- local authentication abstraction
- OpenBao integration/bootstrap design
- OPA client and fail-closed handling
- audit service
- health/readiness endpoints
- initial web shell

Acceptance criteria:

- services restart without losing domain state
- OPA outage prevents test write authorization
- OpenBao secrets are referenced, not copied into DB
- duplicate test event delivery does not duplicate domain mutation

## Phase 2 — Asset discovery and reconciliation

**Goal:** discover a lab network and create a useful canonical inventory/topology.

Deliverables:

- managed scope model
- passive/low-impact discovery framework
- NetBox connector
- LibreNMS connector
- asset observation ingestion
- reconciliation engine
- identity conflict UI/API
- topology relationships

Acceptance criteria:

- same test device seen by NetBox and LibreNMS maps to one canonical asset
- conflicting immutable identities do not auto-merge
- IP-only changes do not create destructive identity churn
- source-specific IDs remain external mappings

## Phase 3 — Security telemetry and incidents

**Goal:** ingest security/network evidence and produce explainable incidents.

Deliverables:

- Wazuh connector
- Suricata EVE ingestion
- canonical event normalizers
- initial behaviour feature service
- deterministic correlation rules
- incident state machine
- evidence/timeline UI

Acceptance criteria:

- Wazuh and Suricata evidence concerning one endpoint can correlate into one incident
- incident shows exact correlation reasons
- malicious prompt-like text in telemetry remains evidence and cannot call tools

## Phase 4 — AI investigation (read-only)

**Goal:** add model-assisted reasoning without changing authority boundaries.

Deliverables:

- `ModelGateway` interface
- OpenAI-compatible adapter
- optional LiteLLM/local endpoint adapters
- evidence selector/redaction
- SOC Analyst
- Network Analyst
- Supervisor/Investigator
- structured output validation
- cost/token metadata

Acceptance criteria:

- agents have no secret or execution tools
- invalid model outputs are rejected
- external-model path demonstrably excludes secrets
- platform remains functional when model gateway is disabled

## Phase 5 — Action proposal, policy and approval

**Goal:** make remediation proposals first-class but still non-executing.

Deliverables:

- capability registry/manifests
- action proposal API/state machine
- OPA input/output contract
- approval service/UI
- role/risk/autonomy baseline policies
- proposal digest binding

Acceptance criteria:

- changing target/parameters invalidates approval
- OPA error fails closed
- risk 5 denied
- Level 2 requires approval for write actions
- protected asset role escalates approval

## Phase 6 — Deterministic execution and verification

**Goal:** safely close the loop for a small action catalogue.

Initial capabilities:

- endpoint isolate/unisolate
- block/unblock external IP through one reference firewall adapter
- restart Windows service
- restart Linux service
- inventory refresh
- endpoint security scan

Patching may enter this phase only after service actions are proven safe.

Deliverables:

- hardened executor process/image
- OpenBao JIT secret retrieval
- Ansible execution adapter
- capability prechecks
- idempotency/reconciliation
- verification service
- rollback state machine
- operator kill switch

Acceptance criteria:

- duplicate execution message produces no duplicate side effect
- successful executor with failed verifier is not marked successful
- supported reversible action can be rolled back
- executor has no model dependency
- executor cannot execute unregistered commands/playbooks

## Phase 7 — Patching and configuration drift

**Goal:** broaden from incident response to infrastructure operations.

Deliverables:

- controlled Windows/Linux patch capabilities
- maintenance windows
- pre/post health checks
- intended-vs-observed NetBox/LibreNMS drift findings
- low-risk drift remediation for lab targets

## Phase 8 — Optional operational profiles

Independent profiles:

- Zeek / NDR
- MeshCentral / RMM
- Velociraptor / DFIR
- vulnerability provider/Greenbone lab adapter
- Keycloak/external OIDC production profile
- OpenTelemetry/Prometheus/Grafana
- local-model profile

None may rewrite core incident/action contracts.

## Phase 9 — Hardening and guarded autonomy

**Goal:** prove the platform safe enough to allow selected Level 3 automation.

Deliverables:

- adversarial prompt-injection suite
- chaos/retry tests
- connector compromise simulations
- false-positive remediation simulations
- host/container hardening
- SBOM/licence/provenance CI
- backup/restore and upgrade tests
- documented recovery procedures

Level 3 is enabled only per-capability after its autonomy tests pass.

## Phase 10 — Appliance and MSP evolution

Future work:

- versioned VM appliance image
- installer/upgrader/rollback tooling
- HA scale profile
- tenant isolation design
- MSP hub/leaf federation
- policy bundle distribution
- remote health/status without exposing customer secrets

## Definition of done for every feature

A feature is not complete until it has:

- explicit API/event/schema contract
- authorization rules
- audit events
- failure semantics
- health/observability
- unit tests
- integration tests where applicable
- security/adversarial test when it crosses a trust boundary
- documentation
- upgrade/migration consideration

For action capabilities also require:

- risk classification
- prechecks
- idempotency behaviour
- verification
- rollback declaration
- OPA tests
