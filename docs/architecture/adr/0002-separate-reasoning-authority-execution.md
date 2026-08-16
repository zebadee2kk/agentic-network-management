# ADR-0002: Separate reasoning, authority and execution

- Status: Accepted
- Date: 2026-08-16

## Context

The platform will use AI agents to investigate incidents and recommend remediation. Giving a model direct infrastructure credentials or arbitrary execution access would make hallucination, prompt injection and provider compromise high-impact safety failures.

## Decision

The architecture separates three roles:

1. **Reasoning** — AI agents gather evidence and create typed proposals.
2. **Authority** — OPA plus durable human approvals decide whether a proposal may proceed.
3. **Execution** — deterministic executors perform registered/versioned capabilities and cannot reason with an LLM.

Models have no secret access and no direct network route to managed infrastructure.

## Consequences

### Positive

- prompt injection cannot directly authorize a change
- policy remains deterministic and testable
- execution is reproducible and auditable
- model/provider can be replaced or disabled

### Negative

- more platform components and state transitions
- slower than unconstrained agent shell access
- remediation catalogue must be explicitly engineered

## Rejected alternatives

- model-generated shell/PowerShell executed directly
- model-generated Ansible playbooks executed automatically
- asking the model itself whether an action is safe
- using prompt text as the human approval mechanism
