# Component Decision Matrix

This document records the initial upstream component choices and, more importantly, the boundary each component is allowed to own.

Third-party versions, licences and redistribution terms MUST be re-verified by release automation/legal review before publishing composed images or appliance artefacts. Do not infer redistribution rights solely from source availability.

| Capability | Initial component | v1 status | ANM boundary |
|---|---|---:|---|
| Platform database | PostgreSQL | Core | ANM owns schema/domain state |
| Event backbone | NATS JetStream | Core | Transport only; ANM owns domain semantics |
| Policy engine | Open Policy Agent | Core | OPA is write-policy authority |
| Secrets/PKI | OpenBao | Core | Secrets never copied into ANM DB/model context |
| Network source of truth | NetBox | Core infrastructure | Intended network/infrastructure state, not ANM incidents/actions |
| Network monitoring/discovery | LibreNMS | Core infrastructure | Observed polling/device health, not canonical identity authority |
| Endpoint/XDR/SIEM | Wazuh | Core security | Security telemetry/alerts, not ANM incident lifecycle |
| Network IDS | Suricata | Core security | Passive sensor/event producer |
| Remediation/configuration | Ansible Community | Core action plane | Known implementations only; no AI-generated production playbooks |
| AI provider gateway | Internal `ModelGateway` | Core interface | Provider-agnostic abstraction |
| LiteLLM | LiteLLM | Optional adapter | Convenience proxy/routing; never a domain dependency |
| Enterprise IAM | Keycloak/external OIDC | Production profile | Identity/federation; ANM retains application authorization/policy context |
| Deep network evidence | Zeek | Optional NDR | Evidence provider only |
| Interactive RMM | MeshCentral | Optional RMM | Human remote support; not ANM action authority |
| DFIR/hunting | Velociraptor | Optional DFIR | Forensic evidence provider |
| Vulnerability scanning | Provider interface | Optional | `VulnerabilityProvider` abstraction |
| Community vulnerability implementation | Greenbone | Lab/evaluation adapter initially | Do not treat upstream community container deployment as production baseline |
| Platform telemetry | OpenTelemetry + Prometheus/Grafana | Production profile | Observes ANM itself |
| Durable workflow engine | PostgreSQL state machines + NATS | v1 | ANM-owned workflow state |
| Temporal | Temporal | Deferred | Potential future workflow provider; not v1 dependency |
| Network scanning | Native passive/SNMP/ICMP/etc. | Core | Scope-controlled discovery |
| Nmap | External optional adapter | Not bundled | Avoid making redistribution/licence assumptions |
| TacticalRMM | — | Excluded | Not aligned with project's open-source/redistribution model |

## Component principles

### 1. Upstream tools are replaceable

ANM services depend on internal contracts, not source-specific object models.

Example:

```text
ANM incident -> EvidenceProvider -> Wazuh adapter
                            \-----> future Defender adapter
```

### 2. No upstream product owns ANM workflow

Wazuh alert state, NetBox objects or Ansible task state cannot replace:

- incident state
- action proposal state
- approval state
- policy decision history
- verification state
- platform audit

### 3. Connectors advertise capabilities

Example:

```json
{
  "connector": "fortigate",
  "capabilities": [
    "network.interfaces.read",
    "network.routes.read",
    "firewall.rules.read",
    "firewall.block_ip",
    "firewall.unblock_ip"
  ]
}
```

Agent tools query this catalogue; they do not assume a vendor feature exists.

### 4. Optional profiles cannot contaminate core contracts

The incident/action model cannot contain mandatory Greenbone-, Zeek-, MeshCentral- or Velociraptor-specific fields. Source-specific data belongs in evidence metadata and connector mappings.

## Licensing governance

The repository should add automated checks for:

- SPDX/SBOM generation
- direct/transitive dependency licences
- container image licences/notices
- redistribution constraints
- CVEs
- image provenance/signature where available

Any component with unusual redistribution or commercial-use constraints receives a dedicated ADR before being bundled.

## Upgrade governance

Each upstream component gets:

- pinned version/digest in release manifests
- compatibility adapter tests
- documented migration procedure
- health probe
- rollback version where practical

Never ship release manifests using floating `latest` tags.
