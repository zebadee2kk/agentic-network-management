# Threat Model

## 1. Scope

This threat model covers the ANM appliance/control plane, bundled connectors, AI reasoning layer, action plane, secrets/policy services and trust relationship with managed infrastructure.

It does not assume that monitored endpoints, logs, users, network devices or external AI providers are trustworthy.

## 2. Assets to protect

### Critical

- infrastructure credentials and private keys
- OpenBao root/unseal/recovery material
- policy bundles and policy decision integrity
- action authorization state
- executor identities
- audit integrity
- managed infrastructure availability
- configuration backups and recovery material

### High

- topology and inventory
- security telemetry
- incident evidence
- model prompts/responses containing operational data
- user identity/session data
- connector tokens

## 3. Threat actors

- unauthenticated Internet attacker
- attacker already present on a managed endpoint
- attacker controlling a log/event source
- compromised network device
- malicious or compromised administrator
- compromised connector dependency/container
- compromised external LLM provider/account
- prompt-injection author
- software supply-chain attacker
- attacker with access to the container host
- faulty/hallucinating model
- accidental operator error

## 4. Trust boundaries

```text
User/browser
    |
    | TB-1 HTTPS/auth
    v
Control plane
    |
    +---- TB-2 ---> AI reasoning/provider
    |
    +---- TB-3 ---> OpenBao / OPA / identity
    |
    +---- TB-4 ---> Event/telemetry adapters
    |
    +---- TB-5 ---> Action executor
                       |
                       | TB-6 management protocols
                       v
                 Managed assets
```

Every boundary requires authenticated, authorized and logged communication appropriate to the deployment profile.

## 5. Primary abuse cases

### TM-001 — Prompt injection in telemetry

**Scenario:** An attacker causes a hostname, log line, process argument, HTTP response or ticket text to contain instructions intended to manipulate an agent.

**Impact:** Incorrect investigation or attempted unauthorized tool use.

**Controls:**

- evidence marked as untrusted data
- strict agent tool allowlists
- no policy/secret/action authority in AI zone
- structured outputs
- policy and approval outside LLM
- no direct managed-network connectivity from AI workers
- adversarial regression tests

### TM-002 — Model hallucinates a destructive fix

**Scenario:** The model recommends rebooting a core switch or deleting a resource.

**Controls:**

- remediation planner can only select registered capabilities
- risk metadata and protected roles
- OPA deny/approval decisions
- destructive capabilities absent/denied in v1
- human approval for high-risk actions

### TM-003 — Duplicate message causes duplicate side effect

**Scenario:** NATS redelivers an execution request after timeout.

**Controls:**

- action/execution idempotency keys
- durable execution records
- executor re-fetches authoritative state
- capability-specific reconciliation
- ambiguous outcomes not blindly retried

### TM-004 — Credential exfiltration through model

**Scenario:** A connector response or error includes a password/token and the agent forwards it to an external model.

**Controls:**

- secret values confined to executor/connector boundary
- response scrubbing/redaction
- schemas that exclude secret fields
- model gateway egress/data policy
- no secret dereference permission for agent identity

### TM-005 — Compromised connector tampers with platform

**Scenario:** A vendor connector is compromised and sends malicious observations or attempts to invoke actions.

**Controls:**

- connector-specific service identity
- read/write capabilities separated
- telemetry connectors publish observations only
- action dispatch possible only through action service
- schema validation
- least-privilege network rules
- signed/pinned build provenance where possible

### TM-006 — OPA bypass

**Scenario:** A developer introduces a direct route from UI/agent to executor.

**Controls:**

- action service is only dispatch authority
- executor requires authorization reference and re-fetches state
- network ACL/service auth prevents direct agent/UI access
- architecture tests assert no bypass endpoints
- code review checklist tied to INV-004

### TM-007 — Approval replay

**Scenario:** An approval for one action is reused after parameters or target change.

**Controls:**

- approval bound to immutable proposal digest
- expiry
- mutation invalidates approval
- executor checks current digest/state

### TM-008 — Compromised executor

**Scenario:** Executor is exploited and possesses network access/secret permissions.

**Controls:**

- narrow service identity and secret paths
- isolated execution network
- deny Internet egress by default
- short-lived credentials where possible
- hardened minimal image
- no model/client/browser libraries
- audit secret access
- split high-risk connector workers in hardened profiles

### TM-009 — Platform host compromise

**Scenario:** Root access on the appliance host defeats container isolation.

**Controls:**

- production VM/appliance boundary
- hardened host firewall
- automatic security updates under controlled policy
- minimal host packages
- encrypted backups/secrets
- image/SBOM/provenance checks
- document that Docker networks are not a root-compromise security boundary

### TM-010 — Malicious administrator

**Scenario:** Authenticated administrator attempts to abuse automation.

**Controls:**

- RBAC
- separate approver roles
- policy restrictions independent from UI role
- audit trail
- optional dual approval for critical actions
- external identity/MFA production profile

### TM-011 — AI provider compromise/data leak

**Scenario:** Sensitive evidence is sent to a provider that should not receive it, or provider output is malicious.

**Controls:**

- model gateway data classification/routing
- local-only option
- provider allowlists
- evidence minimisation/redaction
- output treated as untrusted recommendation
- no provider has credentials/action authority

### TM-012 — Inventory poisoning

**Scenario:** Attacker manipulates hostname/MAC/SNMP data so two assets are incorrectly merged, causing remediation to target the wrong device.

**Controls:**

- confidence-based reconciliation
- immutable identifier conflicts block automatic merge
- IP address alone is weak identity
- protected-role checks at execution time
- target details displayed in approvals

### TM-013 — Network discovery causes disruption

**Scenario:** Scanning/probing fragile industrial/IoT devices causes instability.

**Controls:**

- passive-first discovery
- explicit managed scopes
- per-scope probe policy
- low-impact defaults
- rate limits
- opt-in authenticated/active discovery
- deny lists for sensitive ranges/devices

### TM-014 — False positive triggers automated containment

**Scenario:** Benign traffic produces multiple high-severity alerts and an endpoint is isolated.

**Controls:**

- Level 2 default autonomy
- confidence/evidence thresholds in OPA
- protected/critical asset role escalation
- reversible actions preferred
- verifier and rollback path
- automated actions initially limited to tested low-risk capabilities

### TM-015 — Supply-chain compromise

**Scenario:** Upstream container/image/dependency is malicious or compromised.

**Controls:**

- pin versions/digests
- SBOM generation
- dependency/licence scanning
- vulnerability scanning
- image signing/provenance verification roadmap
- staged upgrades and compatibility tests
- avoid `latest` tags in releases

## 6. Security requirements derived from threats

- No public exposure of database/NATS/OpenBao/OPA management ports by default.
- All production service-to-service requests authenticated where supported.
- TLS for trust-boundary crossings in production profile.
- Connector credentials stored only in OpenBao.
- Action records include exact target and capability digest.
- Audit events cannot be mutable through normal user APIs.
- Rate limits and resource quotas protect ingestion and AI paths.
- Uploads/evidence are size bounded and parser hardened.
- SSRF protections apply to connector/model/tool URLs.
- Managed network scopes are explicit; arbitrary CIDR scanning is not a generic agent capability.

## 7. Threat-model gates for releases

### Before v0.1

- service/network threat boundaries documented
- no secrets in repository
- OpenBao bootstrap design reviewed
- OPA fail-closed test exists

### Before first write capability

- action state machine implemented
- executor authentication/authorization enforced
- policy and approval digest binding tested
- idempotency test passes
- verification required

### Before external AI provider support

- prompt-injection tests
- secret/redaction tests
- provider routing/data classification documented
- tool allowlist tests

### Before Level 3 autonomy

- dedicated adversarial action suite
- chaos/retry tests
- protected-role policy tests
- rollback verification
- operator kill switch / autonomy disable path
- incident simulation demonstrating safe false-positive handling

## 8. Residual risks

- A root compromise of the appliance may undermine multiple controls.
- Vendor management protocols may be inherently weak or non-transactional.
- Some actions cannot be perfectly verified from an independent source.
- Asset identity reconciliation can never be infallible in highly dynamic networks.
- AI can still provide bad analysis; the architecture reduces its authority rather than promising perfect reasoning.
- Open-source component vulnerabilities and breaking changes require continuous lifecycle governance.

These residual risks should be visible in deployment guidance rather than hidden behind an “autonomous” product claim.
