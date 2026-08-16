# Action Capability Specification

## 1. Purpose

Capabilities are the only way ANM changes managed infrastructure. A capability is a named, versioned, schema-constrained operation with defined risk, prechecks, executor implementation, verification and rollback semantics.

Agents may propose capabilities. They may not define or execute new production commands at runtime.

## 2. Manifest

Example:

```yaml
id: windows.restart_service
version: 1.0.0
description: Restart an approved Windows service on a managed endpoint.
risk: 2
reversible: false
protected_roles:
  default_policy: require_approval
parameters_schema: schemas/capabilities/windows.restart_service.json
requires:
  - executor.ansible
  - transport.winrm
prechecks:
  - asset.online
  - service.exists
  - service.allowlisted
execution:
  adapter: ansible
  implementation: playbooks/windows/restart_service.yml
verification:
  strategy: service_health
  timeout_seconds: 120
rollback: null
```

The release pipeline computes a digest of the manifest and implementation artefacts. Policy/approval records bind to this digest.

## 3. Risk scale

### Risk 0 — read only

No managed-state change.

Examples: query status, collect evidence, refresh read-only inventory.

### Risk 1 — non-disruptive controlled activity

Examples: request a security scan, refresh inventory, collect forensic artefacts.

### Risk 2 — limited reversible/low-blast-radius change

Examples: isolate a standard workstation, block a clearly malicious external IP, restart an approved non-critical service.

### Risk 3 — disruptive operational change

Examples: patch/reboot endpoint or server, disable user, disable switch access port.

Human approval by default.

### Risk 4 — critical infrastructure change

Examples: core network, firewall architecture, hypervisor, identity/control plane.

Human approval mandatory in v1, normally with stronger approver role.

### Risk 5 — destructive/irreversible

Examples: wipe, delete backups, destroy VM, destructive filesystem operations.

Denied by baseline v1 policy.

## 4. Capability lifecycle

```text
DRAFT -> REVIEWED -> ENABLED -> DEPRECATED -> DISABLED
```

Only enabled versions can be proposed/executed.

A new implementation that changes side effects requires a new capability version or implementation digest and invalidates previous approvals.

## 5. Required prechecks

Before execution the platform checks:

- target still resolves to the intended canonical asset
- current external connector mapping is valid
- asset is not newly protected/critical
- capability implementation remains enabled
- required connector health is acceptable
- required secret reference exists and can be requested
- idempotency key has not already completed
- any capability-specific safety condition

## 6. Verification

Every write capability declares verification.

Verification should prefer a source independent from the execution mechanism.

Examples:

| Capability | Executor | Preferred verification |
|---|---|---|
| restart service | Ansible | Wazuh/service probe + TCP/HTTP probe |
| isolate endpoint | Wazuh/vendor endpoint action | Suricata/connection state + agent state |
| block IP | firewall adapter | firewall read-back + traffic observation |
| patch Windows | Ansible | OS patch inventory + service health |
| VLAN change | network adapter | observed switch state/LibreNMS + reachability |

## 7. Rollback

Rollback is itself a capability and follows normal policy rules.

The original capability records sufficient pre-state before executing when rollback needs it.

Example:

```text
firewall.block_ip
  pre-state: rule absent
  execute: create rule with ANM execution tag
  verify: rule present + flow ceased
  rollback: firewall.unblock_ip using recorded rule identity
```

If rollback cannot be guaranteed, `reversible: false` and risk is increased appropriately.

## 8. Initial v1 catalogue

Proposed implementation order:

1. `inventory.refresh`
2. `endpoint.security_scan`
3. `windows.restart_service`
4. `linux.restart_service`
5. `endpoint.isolate`
6. `endpoint.unisolate`
7. `firewall.block_ip`
8. `firewall.unblock_ip`
9. `windows.install_security_updates`
10. `linux.install_security_updates`

Patching should be introduced only after the non-patching catalogue proves the complete propose -> policy -> approval -> execute -> verify loop.

## 9. Forbidden generic capabilities

The following must not exist in the production AI-accessible catalogue:

```text
shell.exec
ssh.run
powershell.run
ansible.run_arbitrary_playbook
http.request_arbitrary
sql.execute_arbitrary
firewall.apply_raw_config
network.run_cli
```

Vendor-specific low-level commands may exist inside reviewed connector implementations, but never as model-selectable parameters.
