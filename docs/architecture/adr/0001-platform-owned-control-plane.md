# ADR-0001: Platform-owned control plane

- Status: Accepted
- Date: 2026-08-16

## Context

ANM integrates products that each have their own object models and workflows. Allowing one upstream product to become the global source for incidents, approvals, actions or identities would tightly couple the platform to that product and make replacement difficult.

## Decision

ANM owns the canonical control-plane domain model in its own PostgreSQL database.

ANM is authoritative for canonical asset UUIDs and external identity mappings, incidents, evidence references, action proposals, policy decisions, approvals, executions, verification and audit state.

Upstream products remain authoritative only for their specialist data domains, such as Wazuh telemetry or NetBox intended network state.

## Consequences

### Positive

- upstream tools are replaceable
- workflow semantics remain coherent
- cross-product correlation becomes possible
- upgrades/relicensing of one product do not redefine ANM's domain

### Negative

- requires reconciliation and connector logic
- duplicates some metadata held by source systems
- demands careful eventual-consistency handling

## Rejected alternatives

1. Use Wazuh as the global incident/workflow database.
2. Use NetBox as the global CMDB for every endpoint, incident and action.
3. Let connectors exchange source-specific IDs without a canonical asset identity.
