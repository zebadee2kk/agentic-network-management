from typing import Any
from urllib.parse import quote

import httpx

from anm.executors.base import ExecutionContext, ExecutionOutcome


def _headers(secret: dict[str, Any] | None) -> dict[str, str]:
    if secret is None:
        raise ValueError("credential unavailable")
    token = secret.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("reference adapter credential requires token")
    return {"Authorization": f"Bearer {token}"}


class ReferenceEndpointExecutor:
    async def execute(self, context: ExecutionContext) -> ExecutionOutcome:
        try:
            headers = _headers(context.secret)
        except ValueError:
            return ExecutionOutcome(outcome="failed", category="credential_unavailable")
        desired = context.capability == "endpoint.isolate"
        if context.capability not in {"endpoint.isolate", "endpoint.unisolate"}:
            return ExecutionOutcome(outcome="failed", category="unsupported_capability")
        timeout = float(context.binding_config.get("timeout_seconds", 15))
        state_url = f"{context.endpoint}/v1/endpoints/{context.target_asset_id}/isolation"
        was_isolated = False
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                before = await client.get(state_url, headers=headers)
                before.raise_for_status()
                payload = before.json()
                was_isolated = bool(payload.get("isolated", False))
                response = await client.put(
                    state_url,
                    headers=headers,
                    json={
                        "isolated": desired,
                        "execution_id": context.execution_id,
                    },
                )
                response.raise_for_status()
        except httpx.TimeoutException:
            return ExecutionOutcome(
                outcome="ambiguous",
                category="remote_execution_timeout",
                pre_state={"isolated": was_isolated},
            )
        except (httpx.HTTPError, ValueError, TypeError):
            return ExecutionOutcome(outcome="failed", category="endpoint_adapter_failure")
        return ExecutionOutcome(
            outcome="success",
            pre_state={"isolated": was_isolated},
            result={"isolated_requested": desired},
        )


class ReferenceFirewallExecutor:
    async def execute(self, context: ExecutionContext) -> ExecutionOutcome:
        try:
            headers = _headers(context.secret)
        except ValueError:
            return ExecutionOutcome(outcome="failed", category="credential_unavailable")
        if context.capability not in {"firewall.block_ip", "firewall.unblock_ip"}:
            return ExecutionOutcome(outcome="failed", category="unsupported_capability")
        address = context.parameters.get("address")
        if not isinstance(address, str):
            return ExecutionOutcome(outcome="failed", category="invalid_ip_parameter")
        timeout = float(context.binding_config.get("timeout_seconds", 15))
        encoded_address = quote(address, safe="")
        state_url = f"{context.endpoint}/v1/firewall/blocks/{encoded_address}"
        existed = False
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                before = await client.get(state_url, headers=headers)
                if before.status_code not in {200, 404}:
                    before.raise_for_status()
                existed = before.status_code == 200
                if context.capability == "firewall.block_ip":
                    response = await client.put(
                        state_url,
                        headers=headers,
                        json={
                            "execution_id": context.execution_id,
                            "reason_code": context.parameters.get("reason_code"),
                        },
                    )
                else:
                    response = await client.delete(
                        state_url,
                        headers=headers,
                        params={"execution_id": context.execution_id},
                    )
                response.raise_for_status()
        except httpx.TimeoutException:
            return ExecutionOutcome(
                outcome="ambiguous",
                category="remote_execution_timeout",
                pre_state={"block_existed": existed},
            )
        except (httpx.HTTPError, ValueError, TypeError):
            return ExecutionOutcome(outcome="failed", category="firewall_adapter_failure")
        return ExecutionOutcome(
            outcome="success",
            pre_state={"block_existed": existed},
            result={
                "address": address,
                "blocked_requested": context.capability == "firewall.block_ip",
            },
        )
