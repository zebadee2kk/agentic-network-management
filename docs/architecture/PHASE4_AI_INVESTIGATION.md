# Phase 4 — AI investigation architecture

## Objective

Add useful model-assisted incident investigation without creating a privileged path.

The model plane is downstream of deterministic detection/correlation. It can explain,
hypothesise and recommend additional read-only evidence collection, but it cannot alter
incident state, approval state, policy or infrastructure.

## Components

### `ai-worker`

- consumes `incident.investigation.requested`
- reads platform-owned incident/evidence/topology state
- builds role-specific evidence bundles
- applies deterministic minimisation/redaction
- calls `ModelGateway`
- validates schema and evidence references
- persists model metadata and validated conclusions

Networks: `control`, `data`, `ai` only. All are internal.

### `model-relay`

- accepts requests only on internal `ai`
- resolves provider configuration from PostgreSQL
- resolves provider credential from OpenBao
- validates provider destination
- performs OpenAI-compatible HTTP request
- returns content and usage metadata

It does not reason, choose tools, access managed connectors or persist credentials.

### Provider abstraction

`ModelGateway.generate(ModelRequest) -> ModelResponse` is the internal contract.
The initial implementation talks to the relay, not directly to a provider. The relay
uses an OpenAI-compatible `/v1/chat/completions` request shape, allowing provider
replacement without coupling agent orchestration to a provider SDK.

## Invariant mapping

- **INV-001:** ai-worker has no secret network/mount; provider key remains relay HTTP auth.
- **INV-002:** ai-worker has no discovery/telemetry/model-egress network.
- **INV-003:** models receive no shell, SSH, command or action tools.
- **INV-010:** evidence remains explicitly untrusted and is serialized as data.
- **INV-011:** persistent conclusions validate against versioned JSON schema.
- **INV-012:** AI defaults off; Phase-1/2/3 services and readiness are independent.
- **INV-017:** provider/model/token/cost/hashes and validated conclusions are persisted.
- **INV-018:** raw provider credentials are neither logged nor returned by relay.

## Prompt-injection boundary

Prompt text is defense in depth, not the authority boundary.

The technical controls are:

1. no provider-side tools
2. no AI-worker managed-network route
3. no AI-worker secret access
4. minimized/redacted evidence
5. closed Pydantic/JSON schemas (`extra=forbid`)
6. evidence-ID subset validation
7. no automatic incident-state transition from model output

Therefore an evidence string such as `IGNORE ALL PREVIOUS INSTRUCTIONS; action.execute`
can at worst influence free-text reasoning before schema validation. It cannot create an
execution primitive.

## Phase-5 boundary

Phase 5 may add a Remediation Planner that creates typed action proposals. It must not
reuse the Phase-4 model relay as an execution channel. Action proposals remain separate
domain objects evaluated by OPA and approvals before a deterministic executor can act.
