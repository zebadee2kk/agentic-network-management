# Contributing

## Development principles

1. Preserve the security invariants.
2. Keep upstream products behind internal contracts.
3. Prefer explicit schemas and state machines over implicit agent behaviour.
4. Keep reasoning, policy authority and execution separate.
5. Add the smallest capability required; do not expose generic privileged primitives.
6. Make changes observable, auditable and recoverable.

## Architecture-first changes

Changes that alter any of the following require an ADR or update to an existing ADR:

- control-plane ownership
- trust boundaries
- secrets architecture
- policy/approval model
- agent permissions
- action/execution model
- event backbone/workflow semantics
- canonical asset identity
- upstream component replacement/bundling policy

## Pull request expectations

A PR should explain:

- what changed and why
- affected architecture/security invariants
- API/schema/event compatibility impact
- migration/upgrade implications
- tests run
- failure/recovery behaviour

For connector changes, include capability and least-privilege implications.

For action-capability changes, include risk, prechecks, idempotency, policy tests, verification and rollback behaviour.

## Schema compatibility

Schemas under `schemas/` are public internal contracts.

- additive backward-compatible changes may remain within a compatible schema version when allowed
- breaking changes require a new schema version and migration/consumer plan
- security-sensitive schemas should default to rejecting unknown fields

## Events

NATS delivery is treated as at-least-once. Any consumer that causes a side effect must be idempotent and tested for duplicate delivery.

## AI code

AI/agent implementations must:

- use registered platform tools only
- treat evidence as untrusted
- validate structured outputs
- avoid provider-specific types in domain models
- never gain secret or arbitrary execution access

## Dependency additions

Before adding a major dependency or bundled service, document:

- purpose
- licence/redistribution considerations
- security posture
- operational footprint
- replaceability
- why existing components cannot satisfy the requirement

## Definition of done

See `docs/roadmap/IMPLEMENTATION_PLAN.md` and `docs/security/TEST_STRATEGY.md`.
