# Phase 3 security architecture summary

Phase 3 adds canonical security telemetry and deterministic incident correlation on top of the Phase-2 asset graph.

- Wazuh: bounded read-only indexer polling through an isolated telemetry worker.
- Suricata: push ingestion of EVE JSON; no control connection back to the sensor.
- Canonical events: vendor-independent envelope with `trust=untrusted_evidence`.
- Dedupe: stable source/event or payload digest key.
- Behaviour: deterministic versioned running baselines and anomaly findings.
- Incidents: deterministic correlation with explicit reasons and an enforced state machine.
- No AI decisioning or remediation is part of Phase 3.
