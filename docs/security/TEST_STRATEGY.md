# Security and Verification Test Strategy

## 1. Test layers

### Unit

- schema validation
- state transitions
- reconciliation scoring
- correlation rules
- OPA input construction
- redaction
- capability prechecks

### Contract

- connector contracts against fixtures
- event schema compatibility
- capability manifest validation
- model structured-output validation

### Integration

- PostgreSQL + NATS state/event consistency
- NetBox/LibreNMS reconciliation
- Wazuh/Suricata event normalisation
- OpenBao secret retrieval by correct/incorrect identities
- OPA allow/approval/deny paths
- executor/verifier loop

### End-to-end

A lab environment must exercise:

```text
discover -> correlate -> investigate -> propose -> policy -> approve
-> execute -> verify -> audit
```

### Adversarial

- prompt injection in hostname, DNS, log, process command line and ticket text
- malicious connector payloads
- invalid/oversized model output
- model attempting unregistered tools
- model proposing protected/destructive target
- secret leakage attempts
- SSRF-style connector/model URLs
- duplicate NATS delivery
- replayed approval
- changed action parameters after approval
- ambiguous executor timeout
- verifier outage

### Chaos/recovery

- restart service during every action state
- NATS temporary outage
- PostgreSQL restart
- OPA outage (writes must fail closed)
- OpenBao outage (actions blocked; reads continue where possible)
- model-provider outage
- source connector outage
- appliance reboot during approval/execution/verification

## 2. Mandatory invariant tests

Each security invariant in `SECURITY_INVARIANTS.md` should have one or more automated tests tagged with the invariant ID.

Examples:

```text
INV-001: fixture containing secret cannot appear in model request capture
INV-002: AI container network cannot reach management test target
INV-004: direct execution request without policy authorization rejected
INV-005: chat/evidence text saying "approved" has no effect on action state
INV-008: executor success + verifier failure => action failure
INV-013: duplicate execution message => one side effect
```

## 3. Autonomy gates

### Levels 0-2

Can ship once monitoring/investigation/action proposal paths pass normal security tests.

### Level 3

A capability may be auto-executable only after:

- idempotency proven
- false-positive scenario tested
- rollback tested where reversible
- target-protection tests pass
- verifier failure handling proven
- duplicate/retry/timeout tests pass
- malicious evidence cannot influence parameters outside schema
- kill switch disables dispatch

### Level 4

Out of v1. Requires a separate architecture and safety review.

## 4. Golden incident simulations

Maintain reproducible lab scenarios:

1. suspicious PowerShell + C2-like Suricata event
2. service outage requiring restart
3. malicious IP block/unblock
4. endpoint isolation false positive and rollback
5. identity-reconciliation collision
6. topology drift finding
7. patch with failed post-health check

Every release reruns the golden scenarios.

## 5. Supply-chain CI

Release CI should eventually require:

- unit/integration/adversarial tests
- JSON Schema validation
- Rego formatting/tests
- secret scan
- dependency vulnerability scan
- SBOM generation
- licence inventory
- container vulnerability scan
- image digest pinning check
- provenance/signature checks where configured

## 6. Test environment

Use an isolated virtual lab, never a production network, for write-capability CI.

Suggested lab assets:

- Linux endpoint
- Windows endpoint
- virtual router/firewall
- managed switch emulator or safe virtual equivalent
- Wazuh
- NetBox
- LibreNMS
- Suricata traffic fixture/replay

Tests that require credentials receive ephemeral lab-only secrets from a test OpenBao instance.

## 7. Security regression policy

A regression that violates a security invariant blocks release.

A capability that fails its autonomy-specific suite is automatically downgraded to `require_approval` or disabled until corrected; autonomy is earned per capability, not globally assumed.
