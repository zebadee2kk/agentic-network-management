# Phase 3 security telemetry operations

Phase 3 adds read-only Wazuh alert polling, Suricata EVE JSON ingestion, canonical security events, deterministic behaviour baselines and explainable incident correlation.

## Safety boundary

- Wazuh polling is read-only and uses only the hard-coded `wazuh-alerts*/_search` endpoint.
- Wazuh credentials are dereferenced only by `telemetry-worker`, never by the browser or control API.
- `telemetry-worker` is the only service on the outbound `telemetry` network.
- Every Wazuh endpoint must resolve entirely inside the managed scope's `connector_cidrs` before OpenBao is read.
- Suricata is push-only in Phase 3; the platform does not connect back to a Suricata sensor.
- All source text, command lines, signatures, domains and log strings remain `trust=untrusted_evidence`.
- Phase 3 performs no endpoint isolation, firewall changes, account changes or other remediation.

## 1. Start the appliance

```bash
docker compose up -d --build
```

Check both workers:

```bash
docker compose ps discovery-worker telemetry-worker
```

## 2. Store a read-only Wazuh indexer credential

The development Compose profile uses the deliberately non-secret local OpenBao dev token. Do not use that pattern in production.

Example with a bearer/JWT token:

```bash
docker compose exec -e BAO_ADDR=http://127.0.0.1:8200 \
  -e BAO_TOKEN=anm-development-root-token-not-for-production \
  openbao bao kv put -mount=secret telemetry/wazuh/lab token='<READ_ONLY_TOKEN>'
```

Basic-auth credentials may instead use `username` and `password` fields. The Wazuh account should have the minimum index-search permissions required for alert reads.

## 3. Create a managed scope

The `cidrs` list describes managed assets. `connector_cidrs` is a separate outbound allowlist for management systems such as the Wazuh indexer.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/scopes \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"lab",
    "cidrs":["10.10.0.0/16"],
    "connector_cidrs":["10.20.0.0/24"],
    "allowed_connector_types":["netbox","librenms"],
    "max_requests_per_minute":30,
    "enabled":true
  }'
```

## 4. Register Wazuh as a telemetry source

Use an origin only: no path, query string, embedded credentials or fragment.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/telemetry/sources \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"wazuh-lab",
    "source_type":"wazuh",
    "scope_id":"<SCOPE_UUID>",
    "base_url":"https://10.20.0.20:9200",
    "secret_ref":"openbao://telemetry/wazuh/lab",
    "config":{"batch_size":250,"verify_tls":true}
  }'
```

For a lab with a self-signed certificate, `verify_tls=false` is available but should not become a production default. Prefer a valid internal PKI chain.

## 5. Queue a Wazuh poll

```bash
curl -sS -X POST \
  http://127.0.0.1:8080/api/v1/telemetry/sources/<SOURCE_UUID>/poll
```

The API writes a durable outbox event. `telemetry-worker` consumes it, validates the resolved endpoint against `connector_cidrs`, then retrieves the secret and performs the bounded index search.

## 6. Register a Suricata push source

Suricata requires no outbound URL or credential:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/telemetry/sources \
  -H 'Content-Type: application/json' \
  -d '{"name":"suricata-lab","source_type":"suricata","config":{}}'
```

## 7. Push EVE JSON

Phase 3 accepts batches of EVE objects. A collector can tail `eve.json` and submit bounded batches.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/telemetry/suricata/eve \
  -H 'Content-Type: application/json' \
  -d '{
    "source_instance":"suricata-lab",
    "events":[{
      "timestamp":"2026-08-16T20:00:00Z",
      "flow_id":123,
      "event_type":"alert",
      "src_ip":"10.10.20.23",
      "dest_ip":"203.0.113.55",
      "alert":{"signature_id":2100498,"signature":"Possible C2 beacon","severity":1}
    }]
  }'
```

For a production deployment, place authenticated TLS ingress in front of this API and restrict who can submit telemetry. Sensor identity/authentication is a later hardening item; do not expose an unauthenticated development appliance directly to untrusted networks.

## 8. Inspect canonical events

```bash
curl -sS 'http://127.0.0.1:8080/api/v1/events?limit=50'
```

Every returned event uses `schemas/event-envelope.schema.json` and is labelled `trust=untrusted_evidence`.

## 9. Inspect incidents and correlation reasons

```bash
curl -sS http://127.0.0.1:8080/api/v1/incidents
curl -sS http://127.0.0.1:8080/api/v1/incidents/<INCIDENT_UUID>/evidence
curl -sS http://127.0.0.1:8080/api/v1/incidents/<INCIDENT_UUID>/timeline
```

Phase-3 correlation is deterministic. Reasons can include:

- `initial_detection`
- `same_asset`
- `bounded_time_window:15m`
- `cross_source_corroboration`
- `shared_indicator:<field>`

AI does not silently merge incidents.

## 10. Move an incident through the state machine

```bash
curl -sS -X PATCH http://127.0.0.1:8080/api/v1/incidents/<INCIDENT_UUID> \
  -H 'Content-Type: application/json' \
  -d '{"state":"TRIAGE","reason":"Analyst accepted incident for triage"}'
```

Invalid transitions are rejected with HTTP 409 and cannot be bypassed by log/evidence text.

## 11. Behaviour baselines

```bash
curl -sS http://127.0.0.1:8080/api/v1/baselines
curl -sS http://127.0.0.1:8080/api/v1/anomalies
```

The initial baseline is intentionally simple and explainable: deterministic running mean/variance with a versioned z-score threshold. It is infrastructure for later richer features, not an LLM-based anomaly detector.
