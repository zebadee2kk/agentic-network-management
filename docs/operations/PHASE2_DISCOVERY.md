# Phase 2 discovery operations

Phase 2 adds read-only NetBox and LibreNMS inventory discovery. Discovery does **not** run in the HTTP API process. The API queues a durable `discovery.run.requested` event and an isolated `discovery-worker` performs the upstream GET requests.

## Security boundary

- The browser can reach only the UI/nginx host port.
- `control-api` has no discovery egress network.
- `discovery-worker` is the only service attached to the `discovery` egress network.
- Connector credentials are stored in OpenBao and the database stores only `openbao://` references.
- A managed scope must define `connector_cidrs`; every resolved connector address must fall inside those CIDRs **before** the worker dereferences the connector credential.
- Connector base URLs must be origins only. Paths, query strings, fragments, embedded credentials, loopback/link-local targets, and platform service names are rejected.
- Connectors expose only `assets.discover` / `assets.read`; there is no generic command or write method.
- HTTP redirects are not followed.
- Each run has a bounded request budget.

Production deployments should reinforce `connector_cidrs` with host/firewall egress rules. Application validation is a safety control, not a substitute for network policy.

## Development OpenBao warning

The Compose development profile uses OpenBao dev mode and a deliberately obvious development-only root token from `config/development/openbao-token`. This token is committed only to make the local disposable stack reproducible. It must never be reused outside local development.

Production must replace dev mode with durable OpenBao storage, TLS, initialization/unseal procedures, scoped workload identities and non-root policies.

## 1. Start the appliance

```bash
docker compose up -d --build
curl --fail http://127.0.0.1:8080/health/ready
```

Check the isolated worker:

```bash
docker compose ps discovery-worker
```

## 2. Store a connector token in development OpenBao

The development server mounts a KV v2 engine at `secret/`. Store a NetBox token without putting it in the Agentic Network Management database:

```bash
docker compose exec \
  -e BAO_ADDR=http://127.0.0.1:8200 \
  -e BAO_TOKEN=anm-development-root-token-not-for-production \
  openbao \
  bao kv put -mount=secret connectors/netbox/lab token='REPLACE_ME'
```

For LibreNMS:

```bash
docker compose exec \
  -e BAO_ADDR=http://127.0.0.1:8200 \
  -e BAO_TOKEN=anm-development-root-token-not-for-production \
  openbao \
  bao kv put -mount=secret connectors/librenms/lab token='REPLACE_ME'
```

The corresponding platform references are:

```text
openbao://secret/connectors/netbox/lab
openbao://secret/connectors/librenms/lab
```

## 3. Create a managed scope

`cidrs` controls which discovered management addresses may become observations. `connector_cidrs` separately controls where connector credentials may be sent.

```bash
curl --fail -X POST http://127.0.0.1:8080/api/v1/scopes \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "lab",
    "cidrs": ["10.20.0.0/24"],
    "connector_cidrs": ["10.10.0.0/24"],
    "allowed_connector_types": ["netbox", "librenms"],
    "max_requests_per_minute": 30,
    "enabled": true
  }'
```

Save the returned scope UUID.

## 4. Register a connector

The `base_url` is the origin only; do not append `/api/...`.

NetBox example:

```bash
curl --fail -X POST http://127.0.0.1:8080/api/v1/connectors \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "lab-netbox",
    "connector_type": "netbox",
    "base_url": "https://10.10.0.10",
    "scope_id": "REPLACE_SCOPE_UUID",
    "config": {},
    "secret_ref": "openbao://secret/connectors/netbox/lab"
  }'
```

LibreNMS example:

```bash
curl --fail -X POST http://127.0.0.1:8080/api/v1/connectors \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "lab-librenms",
    "connector_type": "librenms",
    "base_url": "https://10.10.0.11",
    "scope_id": "REPLACE_SCOPE_UUID",
    "config": {},
    "secret_ref": "openbao://secret/connectors/librenms/lab"
  }'
```

Use read-only API tokens in both upstream products.

## 5. Queue discovery

```bash
curl --fail -X POST http://127.0.0.1:8080/api/v1/discovery/runs \
  -H 'Content-Type: application/json' \
  -d '{"connector_instance_id":"REPLACE_CONNECTOR_UUID"}'
```

The API returns HTTP `202` with a durable run record. Poll it:

```bash
curl --fail http://127.0.0.1:8080/api/v1/discovery/runs/REPLACE_RUN_UUID
```

Terminal states are `succeeded` or `failed`. Failure records contain a bounded/redacted error category and detail; credentials and upstream response bodies are never copied into the run.

## 6. Inspect canonical assets

```bash
curl --fail http://127.0.0.1:8080/api/v1/assets
curl --fail http://127.0.0.1:8080/api/v1/assets/REPLACE_ASSET_UUID
curl --fail http://127.0.0.1:8080/api/v1/assets/REPLACE_ASSET_UUID/topology
```

Source IDs remain identifiers such as `netbox:7` and `librenms:42`; the platform UUID remains the canonical identity.

## 7. Review identity conflicts

```bash
curl --fail 'http://127.0.0.1:8080/api/v1/reconciliation/candidates?candidate_status=conflict'
```

The UI also shows the review queue. An operator may:

- `attach` an observation to the candidate asset;
- `new_asset` / **Keep separate**;
- `reject` the candidate.

An `attach` request is still rejected if immutable identifiers conflict. Human review cannot bypass the immutable-identity safety rule.

## Reconciliation order

Phase 2 intentionally favours identity evidence in this order:

1. existing NetBox/LibreNMS source mapping;
2. immutable serial/device UUID evidence;
3. unique MAC evidence;
4. FQDN/hostname evidence for review;
5. IP address as weak evidence only.

An IP change therefore adds/updates an observed address and does not create destructive identity churn.
