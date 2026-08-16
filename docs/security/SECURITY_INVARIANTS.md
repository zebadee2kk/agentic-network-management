# Security Invariants

This document is normative. Implementations that violate an invariant are architectural defects, not acceptable trade-offs, unless an Architecture Decision Record explicitly changes the invariant after threat-model review.

## INV-001 — No secrets in model context

Infrastructure passwords, API keys, private keys, session tokens, OpenBao tokens and equivalent credentials MUST NOT be supplied to any LLM/model context.

Agents may receive opaque secret references only when needed to describe an operation, but they cannot dereference them.

## INV-002 — No direct AI-to-managed-network path

AI workers MUST NOT have routable access to managed infrastructure networks. All infrastructure reads/writes occur through platform connector/tool APIs with explicit allowlists.

## INV-003 — No arbitrary production shell for models

No agent tool may expose unrestricted SSH, WinRM, PowerShell, shell, `exec`, arbitrary Ansible content, or equivalent command execution against managed assets.

Production actions are registered, versioned capabilities with validated input schemas.

## INV-004 — OPA evaluates every write

Every production-changing action MUST receive an OPA policy result before dispatch. OPA timeout, invalid result or unavailability MUST fail closed.

## INV-005 — Approval is state, not conversation

Where policy requires human approval, approval MUST be represented as a durable platform record bound to the exact action proposal/digest. Text in a chat, model response or evidence item cannot constitute approval.

## INV-006 — High-risk actions default to human approval

Risk 3 and Risk 4 capabilities require human approval by default. Risk 5 destructive capabilities are denied by default and are not part of v1 autonomous operation.

## INV-007 — Executor does not reason

Execution workers MUST NOT use LLMs to decide how to perform production changes. They execute known implementations only.

## INV-008 — Independent verification

An executor success code alone MUST NOT mark an action successful. Capability-specific postconditions are evaluated by the verification service, using an independent signal where practical.

## INV-009 — JIT/least-privilege secret access

Only the service performing the connector/executor operation can dereference the minimum required secret. Secret access is time/scoped where supported and audited.

## INV-010 — Evidence is hostile input

Logs, SNMP text, device banners, DNS names, web/ticket content, user-generated content and connector payloads are untrusted evidence. Evidence cannot change instructions, policy, tool permissions or approval state.

## INV-011 — AI output is schema constrained

Any model output that enters platform state beyond free-text analyst notes MUST validate against a versioned schema. Invalid output is rejected.

## INV-012 — Monitoring does not depend on AI

Loss, disablement or exhaustion of AI providers MUST NOT stop telemetry collection, deterministic detection, event correlation, asset inventory or manual action workflows.

## INV-013 — Action dispatch is idempotent

Every action/execution has an idempotency identity. Duplicate event delivery or worker restart MUST NOT silently cause duplicate side effects.

## INV-014 — Ambiguous execution is not retried blindly

If the platform cannot determine whether a side effect occurred, it must enter an unknown/manual-reconciliation state unless the capability explicitly supports safe reconciliation/retry.

## INV-015 — Parameters cannot mutate after approval

Any material modification to capability, target, parameters, risk-relevant context or implementation digest invalidates existing policy/approval authorization and requires re-evaluation.

## INV-016 — Protected roles cannot be accidentally targeted

Core network, identity, backup, platform-control and other protected asset roles are deny/approval escalators by default. Reconciliation or agent inference cannot remove that protection.

## INV-017 — Audit covers the whole causal chain

The platform must be able to reconstruct:

- source evidence
- deterministic findings
- incident correlation
- model/provider invocation metadata
- agent conclusion/proposal
- policy version/result
- approval identity/result
- capability/version/digest
- executor result
- verifier result
- rollback result

## INV-018 — Secret values are not logged

Application and connector logging MUST redact secret fields and MUST NOT serialize OpenBao secret values into logs, audit events, model traces or exception payloads.

## INV-019 — Telemetry cannot call the action plane

Inbound telemetry collectors/normalizers cannot directly invoke action execution. They can publish events/findings only.

## INV-020 — Control-plane ownership

Upstream products do not own ANM incident, approval, action, policy or audit state. Connector failure/replacement must not corrupt platform-owned workflow state.

## Enforcement checklist

Each pull request touching agents, actions, connectors, policy, networking or secrets should answer:

- Which invariants apply?
- How are they enforced technically?
- Which tests prove the enforcement?
- Does the change introduce a new privileged path?
- Does the threat model require an update?
