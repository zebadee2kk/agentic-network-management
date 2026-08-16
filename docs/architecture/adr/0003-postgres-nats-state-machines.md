# ADR-0003: PostgreSQL state machines plus NATS JetStream for v1 workflows

- Status: Accepted
- Date: 2026-08-16

## Context

ANM needs durable incident/action workflows that can pause for approval, survive service restarts and process asynchronous telemetry. A dedicated durable workflow platform such as Temporal is attractive but adds significant operational complexity to the initial appliance.

## Decision

For v1:

- PostgreSQL stores authoritative workflow/domain state.
- NATS JetStream carries asynchronous observations, domain events and execution jobs.
- Services implement explicit validated state machines.
- Transactional outbox/idempotency patterns are used where database changes and event publication must remain consistent.
- All event consumers that can produce side effects are idempotent.

Temporal or another workflow engine may be introduced later behind an internal workflow abstraction only when measured complexity justifies it.

## Consequences

### Positive

- fewer heavy infrastructure dependencies
- straightforward backup/recovery model
- workflow state remains inspectable in the platform database
- NATS remains useful for later hub/edge evolution

### Negative

- ANM must implement workflow/state-machine discipline itself
- long-running retry/timer semantics require careful engineering
- future migration to a workflow engine may require adapter work

## Rejected alternatives

- Temporal as a mandatory v1 dependency
- in-memory workflow state
- relying on NATS messages as the sole source of workflow truth
