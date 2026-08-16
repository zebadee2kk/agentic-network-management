# Product Requirements Document

## 1. Purpose

Agentic Network Management (ANM) is a self-hosted infrastructure and security operations platform for organisations that want open, locally controlled monitoring and remediation without stitching together multiple disconnected dashboards.

The product combines mature open-source sensors and automation engines behind a platform-owned control plane. ANM owns the canonical asset identity, incident lifecycle, action/approval lifecycle, policy integration, AI reasoning contracts, verification and audit trail.

## 2. Product promise

An administrator should be able to deploy an appliance, define one or more managed networks, provide approved credentials, discover the environment, review the resulting asset/topology model, enable selected monitoring profiles, optionally configure an AI provider, and begin receiving correlated incidents and remediation recommendations.

The product MUST function without an AI provider. AI augments investigation and planning; it does not own monitoring, authority or execution.

## 3. Target users

### Primary

- Small and medium businesses with limited security/network operations staffing.
- MSPs and consultants managing customer infrastructure.
- Technical operators wanting an open-source, self-hosted alternative to fragmented RMM/NMS/SIEM tooling.
- Labs and home-lab operators who want a single infrastructure operations plane.

### Secondary

- Security teams wanting an extensible evidence and remediation layer over existing tooling.
- Network teams wanting topology-aware incident correlation and guarded automation.

## 4. Core jobs to be done

The system SHALL allow an operator to:

1. Define networks, sites and management scopes.
2. Discover assets through passive and low-impact techniques.
3. Reconcile identities from multiple upstream tools into one canonical asset.
4. Build and maintain network/topology relationships.
5. Monitor endpoint, network, security and health telemetry.
6. Normalize upstream alerts/events into canonical events.
7. Correlate related events into incidents.
8. Establish simple behavioural baselines and flag deviations.
9. Investigate an incident using deterministic queries plus optional AI reasoning.
10. Present evidence, confidence, hypotheses and recommended actions.
11. Convert recommendations into typed action proposals.
12. Evaluate every write action against policy.
13. Require human approval where policy requires it.
14. Execute only pre-defined, versioned capabilities through deterministic executors.
15. Independently verify the result.
16. Roll back reversible failed changes where policy/capability supports it.
17. Produce a complete audit timeline.
18. Continue monitoring and deterministic operations when AI is disabled or unavailable.

## 5. v1 scope

### 5.1 Platform core

- Web UI and API.
- PostgreSQL platform database.
- NATS JetStream event bus.
- OpenBao secrets integration.
- OPA policy integration.
- Local authentication with an OIDC-ready abstraction.
- Canonical asset registry.
- Asset identity reconciliation.
- Incident engine and explicit state machines.
- Approval, execution, verification and audit services.

### 5.2 Discovery and inventory

- Managed-network definition.
- Passive/low-impact discovery adapters for ICMP, ARP, SNMP and supported device APIs.
- LibreNMS connector.
- NetBox connector.
- Synchronisation/reconciliation rather than assuming either upstream tool is globally authoritative.

### 5.3 Security monitoring

- Wazuh connector for endpoint/security telemetry.
- Suricata EVE ingestion for passive NIDS events.
- Event normalisation.
- Basic event correlation.
- Incident creation.

### 5.4 Behaviour service

Initial deterministic/statistical features:

- rolling averages and medians
- median absolute deviation
- exponentially weighted moving averages
- first-seen events
- rare-event frequency
- peer deviation
- time-of-day/day-of-week baselines
- rate-of-change alarms

AI SHALL NOT be required to calculate anomaly scores.

### 5.5 AI

- BYOK/local model gateway abstraction.
- At least one OpenAI-compatible adapter.
- Optional LiteLLM adapter.
- Optional local/OpenAI-compatible model endpoint.
- SOC Analyst agent.
- Network Analyst agent.
- Investigator/supervisor.
- Remediation Planner that can only emit structured proposals.

### 5.6 Controlled remediation

Initial capability catalogue should include a small reversible set, such as:

- `endpoint.isolate`
- `endpoint.unisolate`
- `firewall.block_ip`
- `firewall.unblock_ip`
- `windows.restart_service`
- `linux.restart_service`
- `windows.install_security_updates`
- `linux.install_security_updates`
- `inventory.refresh`
- `endpoint.security_scan`

Exact executors depend on installed connectors and must declare supported capabilities.

## 6. Out of scope for v1

- Arbitrary AI shell access.
- Model-generated production scripts/playbooks executed without review.
- Inline AI-controlled IPS.
- Permanent full-packet capture by default.
- Full MSP multi-tenancy/federation.
- Replacing Wazuh, NetBox, LibreNMS, Suricata or Ansible with home-grown equivalents.
- Building a new remote desktop stack.
- Building a new vulnerability scanner.
- High-risk autonomous core-network changes.
- Destructive AI-triggered actions.

## 7. Optional/post-v1 profiles

- Zeek NDR/deep network evidence.
- MeshCentral interactive RMM.
- Velociraptor DFIR and hunting.
- Greenbone or another vulnerability scanner through `VulnerabilityProvider`.
- Keycloak production IAM profile.
- OpenTelemetry/Prometheus/Grafana platform observability profile.
- Local-model GPU profile.
- HA and clustered deployment profile.
- MSP hub/leaf architecture.

## 8. Functional requirements

### Assets

- FR-AST-001: Every asset SHALL receive an immutable platform UUID.
- FR-AST-002: External identities SHALL be modelled as mappings, not primary keys.
- FR-AST-003: Reconciliation SHALL support hostname, FQDN, serial, MAC, IP and connector-specific identifiers with confidence scoring.
- FR-AST-004: Potential identity collisions SHALL be reviewable and never silently merge high-confidence conflicting assets.

### Events

- FR-EVT-001: External events SHALL be normalized into a canonical envelope.
- FR-EVT-002: Raw payloads SHOULD remain in the source system or immutable object storage; canonical events SHOULD store references when practical.
- FR-EVT-003: Events SHALL include an idempotency/event ID.

### Incidents

- FR-INC-001: An incident SHALL link events/evidence, assets, hypotheses and actions.
- FR-INC-002: Incident state transitions SHALL be validated by an explicit state machine.
- FR-INC-003: AI output SHALL never directly change incident execution state without a platform service applying the transition.

### Actions

- FR-ACT-001: Every production write SHALL reference a registered capability and version.
- FR-ACT-002: Capability inputs SHALL be validated against a schema.
- FR-ACT-003: Every production write SHALL be evaluated by OPA.
- FR-ACT-004: Capabilities SHALL declare risk, prechecks, verifier and rollback support.
- FR-ACT-005: Arbitrary remote shell execution SHALL not be exposed as an AI tool.
- FR-ACT-006: Execution requests SHALL have an idempotency key.

### Verification

- FR-VER-001: Success SHALL not be determined solely from executor return codes.
- FR-VER-002: Verification SHOULD use a different signal/source from the executor where practical.
- FR-VER-003: Failed verification SHALL produce a failure state and invoke rollback only when declared and policy-approved.

### AI

- FR-AI-001: Models SHALL receive only the minimum evidence required for a task.
- FR-AI-002: Secrets SHALL never be inserted into model context.
- FR-AI-003: Untrusted evidence SHALL be explicitly labelled and treated as data, not instruction.
- FR-AI-004: AI outputs used by the platform SHALL be schema constrained and rejected if invalid.
- FR-AI-005: Model/provider selection SHALL be abstracted from agent logic.

## 9. Non-functional requirements

### Security

- Least privilege by service and connector.
- Just-in-time secret retrieval by executor/connectors.
- Strong separation between reasoning and action planes.
- Full auditability of policy, approval and execution decisions.
- No Internet egress for execution workers unless explicitly required by a capability.

### Reliability

- Event consumers must be idempotent.
- Loss/restart of the AI layer must not stop monitoring.
- Workflow states must survive process restarts.
- Connectors must expose health/degraded states.

### Operability

- Core lab deployment should run through Docker Compose.
- Recommended production packaging is a controlled Linux VM appliance running containerised services.
- Optional profiles must not be required for core health.
- Configuration should be declarative and exportable.

### Extensibility

- New sensors/actuators integrate through connector contracts.
- New remediation actions integrate through capability manifests.
- New AI providers integrate through a model gateway interface.
- New vulnerability/RMM/DFIR products must not require changes to the incident core.

## 10. Autonomy model

- Level 0 — Observe only.
- Level 1 — Automated investigation and enrichment.
- Level 2 — Recommend actions; human executes/approves. **Default.**
- Level 3 — Automatically execute approved low-risk/reversible action classes.
- Level 4 — Guarded autonomous remediation within strict policy; disabled until specifically enabled and validated.

Destructive actions remain prohibited regardless of autonomy level unless the architecture is deliberately changed through an ADR and threat-model review.

## 11. Success criteria for first usable release

A v1 demonstration is successful when the system can:

1. Discover a small test network and reconcile NetBox/LibreNMS identities.
2. Enrol a Wazuh endpoint and ingest Suricata events.
3. Correlate multiple observations concerning the same asset into one incident.
4. Ask the SOC/Network agents to gather evidence without privileged write access.
5. Produce a typed remediation proposal.
6. Pass that proposal through OPA and an approval gate.
7. Execute a pre-defined reversible action through Ansible/Wazuh/vendor adapter.
8. Verify the outcome independently.
9. Display the complete timeline and evidence in the UI.
10. Repeat the same flow with the AI provider disabled, substituting deterministic/manual investigation where necessary.

## 12. Product principles

- Integrate mature tools; do not reinvent them.
- Own the control plane and canonical domain model.
- Treat every upstream product as replaceable.
- Deterministic software detects and executes; AI reasons and proposes.
- Safety gates are technical controls, not prompt instructions.
- Make the safe path the easiest path.
