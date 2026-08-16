# Agentic Network Management

A self-hosted, open-source autonomous infrastructure and security operations platform.

The platform discovers an environment, builds a living asset and topology model, ingests network and endpoint telemetry, detects operational and cybersecurity problems, uses AI to investigate and correlate evidence, proposes deterministic remediation, applies policy and human approval, executes through controlled automation, verifies the outcome, and records a complete audit trail.

## Core operating loop

```text
DISCOVER -> MODEL -> OBSERVE -> DETECT -> CORRELATE -> INVESTIGATE
         -> PROPOSE -> POLICY -> APPROVE -> EXECUTE -> VERIFY -> LEARN
```

## Non-negotiable architecture

The LLM is a reasoning component, never an authority or privileged executor.

```text
AI reasoning
    |
    v
structured action proposal
    |
    v
schema validation
    |
    v
OPA policy decision
    |
    +---- DENY
    |
    +---- REQUIRE HUMAN APPROVAL
    |
    +---- ALLOW
             |
             v
      deterministic executor
             |
             v
          target
             |
             v
     independent verification
```

The system MUST remain useful when no AI provider is configured.

## Reference stack

### Platform-owned core

- Control-plane API and UI
- Canonical asset registry and identity reconciliation
- Topology correlation
- Event normalization and correlation
- Behaviour/anomaly feature service
- Incident state machine
- AI supervisor and specialist agents
- Action capability catalogue
- Approval workflow
- Policy integration
- Verification and rollback framework
- Connector SDK
- Audit model

### Upstream capabilities

- PostgreSQL — platform state
- NATS JetStream — event backbone
- Open Policy Agent — action policy authority
- OpenBao — secrets, PKI, transient credentials
- NetBox — network source of truth
- LibreNMS — network discovery and health monitoring
- Wazuh — endpoint telemetry, XDR/SIEM
- Suricata — passive network IDS
- Ansible — deterministic remediation

Optional profiles add Zeek, MeshCentral, Velociraptor, vulnerability scanners, local models, and production observability.

## Security invariants

1. Models never receive infrastructure secrets.
2. Models cannot open arbitrary connections to managed assets.
3. Models cannot execute arbitrary shell commands against managed assets.
4. Every production write is schema validated and evaluated by OPA.
5. High-risk actions require human approval by default.
6. Every action and decision is auditable.
7. Every change has independent post-action verification.
8. Credentials are retrieved just-in-time by executors.
9. Logs, tickets, web content and device data are untrusted input.
10. Monitoring and deterministic automation continue if AI is unavailable.

See [`docs/security/SECURITY_INVARIANTS.md`](docs/security/SECURITY_INVARIANTS.md) for the normative version.

## Repository map

```text
.
├── docs/
│   ├── architecture/
│   ├── product/
│   ├── roadmap/
│   └── security/
├── schemas/                 # canonical machine-readable contracts
├── policies/opa/            # policy-as-code
├── connectors/              # integration adapters / SDK
├── capabilities/            # deterministic action definitions
├── services/                # platform-owned services
├── agents/                  # read/reason/propose agents
├── deploy/                  # Compose/VM/Kubernetes packaging
└── tests/                   # unit, integration, security and adversarial tests
```

## Initial v1 boundary

The first usable release is intentionally smaller than the long-term platform:

- asset registry and reconciliation
- NetBox + LibreNMS discovery/inventory integration
- Wazuh + Suricata security ingestion
- NATS event backbone
- correlation and incident engine
- BYOK/local AI gateway
- SOC and network analyst agents
- remediation planner
- OPA policy and approval gate
- Ansible action executor
- independent verification
- a small, versioned catalogue of reversible actions

Zeek, MeshCentral, Velociraptor, active vulnerability scanning, advanced configuration drift remediation, MSP federation and high-autonomy modes are post-v1 profiles.

## Project status

**Architecture foundation / pre-implementation.** The repository is being populated with the PRD, HLD, LLD, threat model, canonical schemas, connector contracts, ADRs and implementation backlog before broad coding begins.

## Documentation

- [Product requirements](docs/product/PRODUCT_REQUIREMENTS.md)
- [High-level design](docs/architecture/HLD.md)
- [Low-level design](docs/architecture/LLD.md)
- [Security invariants](docs/security/SECURITY_INVARIANTS.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Component decision matrix](docs/architecture/COMPONENT_MATRIX.md)
- [Implementation roadmap](docs/roadmap/IMPLEMENTATION_PLAN.md)

## Licence

See [`LICENSE`](LICENSE). Third-party components retain their own licences; redistribution and image composition must pass the project's dependency/licence governance checks before release.
