# Connector SDK Specification

## 1. Purpose

Connectors isolate ANM from source-specific APIs and object models. Every upstream product or vendor integration must implement a platform contract rather than leaking its native SDK throughout the control plane.

Connectors are divided into **read capabilities** and **write capabilities**. A telemetry connector does not gain write authority merely because the upstream product supports writes.

## 2. Connector identity

Each connector instance has:

```text
connector_type       e.g. wazuh, netbox, librenms, fortigate
connector_instance   UUID
site_id               optional UUID
version               connector implementation version
config_reference      non-secret configuration
secret_reference      OpenBao reference only
status                healthy/degraded/offline/disabled
```

## 3. Core interface

Conceptual interface:

```python
class Connector:
    async def test_connection(self) -> ConnectionTestResult: ...
    async def health(self) -> HealthResult: ...
    async def capabilities(self) -> list[CapabilityDescriptor]: ...
    async def discover(self, scope: DiscoveryScope) -> list[Observation]: ...
    async def query(self, request: QueryRequest) -> QueryResult: ...
```

Write-capable connectors additionally implement only registered actions:

```python
class ActionConnector(Connector):
    async def precheck(self, request: ExecutionRequest) -> PrecheckResult: ...
    async def execute(self, request: ExecutionRequest, secrets: SecretHandles) -> ExecutionResult: ...
```

There is deliberately no generic `run_command()` method.

## 4. Capability advertisement

Example:

```json
{
  "connector_type": "fortigate",
  "capabilities": [
    {
      "id": "network.interfaces.read",
      "mode": "read"
    },
    {
      "id": "firewall.block_ip",
      "mode": "write",
      "implementation_version": "1.0.0"
    }
  ]
}
```

Capability advertisement says what the connector can implement. It does **not** authorize invocation; OPA and the action service do that.

## 5. Discovery observations

Connectors emit observations, never canonical assets directly.

Example:

```json
{
  "observation_id": "uuid",
  "connector_instance": "uuid",
  "observed_at": "2026-08-16T17:00:00Z",
  "kind": "device",
  "attributes": {
    "hostname": "sw-01",
    "serial": "ABC123",
    "management_ip": "10.0.0.10"
  },
  "identifiers": [
    {"namespace": "serial", "value": "ABC123", "confidence": 1.0},
    {"namespace": "librenms", "value": "42", "confidence": 1.0}
  ]
}
```

The reconciliation service decides whether that observation maps to an existing asset.

## 6. Query restrictions

Query APIs must be typed or allowlisted. Connectors must not expose arbitrary SQL, arbitrary URL fetches, raw shell or vendor command strings to agents.

Examples of acceptable query resources:

```text
asset_status
interfaces
routes
vlans
security_alerts
service_state
process_tree
recent_connections
```

## 7. Secret model

Connector configuration stores only an opaque reference such as:

```text
openbao://connectors/fortigate/site-a
```

Read-only connectors should use read-only upstream credentials wherever possible.

Write credentials should be separate from read credentials when the upstream system supports it.

## 8. Network access

Connector workers receive only the network reachability required for their declared function.

Examples:

- Wazuh API adapter -> Wazuh API only.
- NetBox adapter -> NetBox only.
- execution firewall adapter -> approved management address/port only.
- AI worker -> no connector management network.

## 9. Error contract

All connector errors map into typed categories:

```text
authentication_failed
authorization_failed
connection_failed
timeout
rate_limited
unsupported
invalid_response
conflict
ambiguous_result
upstream_error
```

Raw upstream exceptions may be logged after redaction but must not become API contracts.

## 10. Idempotency

For writes, the connector receives a platform execution ID and idempotency key.

Connectors should use upstream transaction/request IDs where available. If an upstream API is non-idempotent, the connector must define a reconciliation strategy before the capability can be autonomous.

## 11. Required connector tests

Every connector requires:

- configuration schema test
- authentication failure test
- health test
- response normalisation test
- timeout test
- secret-redaction test
- least-privilege capability test

Write connectors additionally require:

- precheck tests
- policy-bypass negative test
- idempotency/retry test
- ambiguous-result handling test
- verifier compatibility test
- rollback test where declared

## 12. Initial connector implementation order

1. NetBox
2. LibreNMS
3. Wazuh
4. Suricata EVE ingestion
5. Ansible executor
6. one reference firewall connector
7. optional Zeek
8. optional MeshCentral
9. optional Velociraptor
10. `VulnerabilityProvider` adapter
