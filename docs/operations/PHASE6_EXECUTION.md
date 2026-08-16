# Phase 6 — Deterministic execution, verification and rollback

Phase 6 closes the first controlled remediation loop. It does **not** give an LLM, agent, browser session or API caller arbitrary command authority.

## Safety model

```text
AUTHORIZED proposal
      |
      v
control-api dispatch re-check
  - kill switch
  - current OPA decision
  - current approvals
  - current asset/protected roles
  - capability + implementation digests
  - target execution binding
  - capability-specific prechecks
      |
      v
QUEUED execution + stable idempotency key
      |
      v
executor worker pre-side-effect re-check
      |
      v
atomic QUEUED -> RUNNING row-lock claim
      |
      v
JIT OpenBao secret resolution
      |
      v
reviewed deterministic adapter
      |
      +--> definite failure -> FAILED
      |
      +--> timeout/crash/unknown -> AMBIGUOUS -> verifier
      |
      `--> executor success -> independent verifier
                               |
                               +--> observed desired state -> SUCCEEDED
                               `--> not observed -> VERIFICATION_FAILED
```

The executor and verifier are separate runtime roles. The verifier has no OpenBao network, no mounted OpenBao token and no execution network.

## Non-negotiable boundaries

- no `shell.exec`, `ssh.run`, `powershell.run`, arbitrary HTTP or arbitrary playbook endpoint
- no model provider or AI dependency in the executor
- no AI/model network attached to the executor
- no secrets network attached to the verifier
- proposal parameters never choose a playbook path, URL path, HTTP method or raw command
- credentials are stored only as `CredentialReference` -> `openbao://...` references
- executor resolves credential data immediately before execution and clears the in-process mapping afterwards
- executor stdout/stderr is discarded instead of persisted
- secret contents are never written to execution/audit/model records
- a remote timeout is `AMBIGUOUS`, never a retry signal
- success requires independent verification
- rollback is another typed proposal and follows normal OPA/approval policy

## Execution kill switch

The persistent setting `execution.control` defaults to:

```json
{
  "enabled": false,
  "reason": "safe default: operator has not enabled execution"
}
```

Endpoints:

- `GET /api/v1/execution-control`
- `PUT /api/v1/execution-control` (`platform_admin` only)

Disabling the switch prevents new dispatch and also stops queued work during the executor's final pre-side-effect check. It does not disable monitoring, incident correlation or read-only AI investigation.

## Execution bindings

A capability never accepts connection details or credentials as action parameters. Operators create a target-specific execution binding:

```json
{
  "asset_id": "...",
  "adapter": "ansible_windows",
  "endpoint": "10.20.30.40",
  "credential_reference_id": "...",
  "config": {
    "allowed_services": ["W32Time", "Spooler"],
    "port": 5986,
    "winrm_transport": "ntlm",
    "server_cert_validation": "validate",
    "verification": {
      "strategy": "tcp_probe",
      "port": 443
    }
  },
  "enabled": true
}
```

The binding owns operational connectivity. The proposal contains only semantic action parameters such as `service_name` or `address`.

## Executable catalogue in this phase

Phase 6 makes these reviewed capabilities executable:

- `windows.restart_service` -> `ansible_windows`
- `linux.restart_service` -> `ansible_linux`
- `endpoint.isolate` -> `reference_endpoint`
- `endpoint.unisolate` -> `reference_endpoint`
- `firewall.block_ip` -> `reference_firewall`
- `firewall.unblock_ip` -> `reference_firewall`

`inventory.refresh` and `endpoint.security_scan` remain `reserved_phase6` until their deterministic downstream integrations are implemented. Reserved capabilities can still be proposed/policy-evaluated but cannot be dispatched.

## Reviewed implementation digest

Phase 5 bound approvals to an implementation digest. Phase 6 strengthens the digest so it includes SHA-256 hashes of the actual shipped adapter/playbook/verifier artifacts listed in each executable manifest.

Example:

```json
{
  "execution": {
    "adapter": "ansible_windows",
    "implementation": "execution_artifacts/windows_restart_service.yml"
  },
  "artifacts": [
    "executors/ansible_adapter.py",
    "execution_artifacts/windows_restart_service.yml",
    "services/verification.py"
  ]
}
```

Changing any reviewed artifact changes `implementation_digest`, then `capability_digest`. Dispatch and the executor both re-evaluate the proposal, so an approval bound to the old implementation cannot authorize the new code.

## Idempotency and ambiguity

Every execution derives one stable idempotency key from:

```text
proposal_digest + capability_digest + implementation_digest
```

The database enforces uniqueness. Repeated dispatch of the same exact proposal returns the existing execution.

JetStream is at-least-once. Therefore duplicate messages are expected. Immediately before external I/O, the executor obtains a database row lock and refreshes the execution row. Only one transaction may change `QUEUED` to `RUNNING`.

`RUNNING` is committed **before** remote I/O. After this point the platform deliberately refuses blind retry semantics. If the worker dies or a remote timeout occurs, state is `AMBIGUOUS`. A replacement worker converts stale `RUNNING` records to `AMBIGUOUS` after `ANM_EXECUTION_STALE_SECONDS` and requests verification.

## Ansible adapter

The executor image installs `ansible-core` and `pywinrm`. The caller cannot supply a playbook path.

Windows and Linux restart-service capabilities point to packaged, reviewed playbooks. The service name must pass both:

1. capability JSON Schema
2. the target binding's `allowed_services`

The executor creates ephemeral 0600 inventory/key/variable files under `/run/anm-executor` tmpfs, invokes `ansible-playbook` with an argument array and discards stdout/stderr. The root filesystem is read-only and the container drops all Linux capabilities.

## Reference endpoint/firewall adapters

These are intentionally narrow reference contracts for the first end-to-end remediation loop; they are not generic HTTP adapters.

Endpoint control uses only:

```text
GET/PUT <binding-origin>/v1/endpoints/{canonical_asset_id}/isolation
GET     <binding-origin>/v1/observer/endpoints/{canonical_asset_id}/isolation
```

Firewall control uses only:

```text
GET/PUT/DELETE <binding-origin>/v1/firewall/blocks/{schema-validated-address}
GET            <binding-origin>/v1/observer/firewall/blocks/{schema-validated-address}
```

The proposal cannot change the origin, route or HTTP method. Production vendor adapters can replace these contracts while preserving the same typed capability interface.

## Independent verification

The verifier worker receives only an execution ID. It has database + NATS access and the separate `verification` egress network. It does not receive execution credentials.

For Ansible service restart, the binding must configure an independent `tcp_probe` or `http_probe`. Without one, the action is **not** marked successful.

For the reference endpoint/firewall adapters, the verifier uses the read-only observer route rather than the authenticated execution route.

State semantics:

- `EXECUTOR_SUCCEEDED` + verified -> `SUCCEEDED`
- `EXECUTOR_SUCCEEDED` + not verified -> `VERIFICATION_FAILED`
- `AMBIGUOUS` + desired state observed -> `SUCCEEDED`
- `AMBIGUOUS` + inconclusive verification -> remains `AMBIGUOUS`

An executor exit code alone can never produce `SUCCEEDED`.

## Rollback

Rollback is not an executor command. `POST /api/v1/executions/{id}/rollback-proposal` creates the inverse typed proposal defined by the original capability manifest.

Current inverse mappings:

```text
endpoint.isolate   -> endpoint.unisolate
firewall.block_ip  -> firewall.unblock_ip
```

The rollback proposal receives a new proposal digest, current OPA evaluation and normal human approval requirements. When eventually dispatched it receives its own execution/idempotency/verification lifecycle and records `rollback_of_execution_id`.

## Execution API

- `GET /api/v1/execution-control`
- `PUT /api/v1/execution-control`
- `POST /api/v1/execution-bindings`
- `GET /api/v1/execution-bindings`
- `POST /api/v1/action-proposals/{id}/dispatch`
- `GET /api/v1/executions`
- `GET /api/v1/executions/{id}`
- `POST /api/v1/executions/{id}/rollback-proposal`

## Runtime network boundaries

```text
ai-worker
  control + data + ai
  NO secrets / execution / verification

model-relay
  ai + data + secrets + model-local + model-egress
  NO execution / verification

executor-worker
  control + data + secrets + execution
  NO ai / model networks / browser networks

verifier-worker
  control + data + verification
  NO secrets / execution / ai / model networks
```

CI validates those sets exactly.

## Production hardening still required

The development Compose file uses the existing OpenBao development server/token. A production profile must replace this with TLS, durable storage, initialization/unseal procedures and narrow workload identities. The executor identity should be able to read only execution credentials required by enabled bindings; the model relay identity should remain separate.

Reference HTTP adapters also need replacement by reviewed vendor adapters before they are claimed as integrations for any specific firewall/EDR product.
