import asyncio
from typing import Any
from urllib.parse import quote

import httpx

from anm.execution_models import ActionExecution, ExecutionBinding


async def _tcp_probe(
    config: dict[str, Any],
    binding: ExecutionBinding,
) -> tuple[bool, dict[str, Any]]:
    host = str(config.get("host") or binding.endpoint)
    port = config.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return False, {"strategy": "tcp_probe", "reason": "verification_port_not_configured"}
    timeout = float(config.get("timeout_seconds", 5))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        del reader
        writer.close()
        await writer.wait_closed()
        return True, {"strategy": "tcp_probe", "host": host, "port": port}
    except (OSError, TimeoutError):
        return False, {"strategy": "tcp_probe", "host": host, "port": port}


async def _http_probe(config: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    url = config.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return False, {"strategy": "http_probe", "reason": "verification_url_not_configured"}
    expected = config.get("expected_status", [200])
    if not isinstance(expected, list) or not all(isinstance(item, int) for item in expected):
        return False, {"strategy": "http_probe", "reason": "expected_status_invalid"}
    timeout = float(config.get("timeout_seconds", 5))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
        return response.status_code in expected, {
            "strategy": "http_probe",
            "status_code": response.status_code,
        }
    except httpx.HTTPError:
        return False, {"strategy": "http_probe", "reason": "probe_failed"}


async def _reference_observer(
    execution: ActionExecution,
    binding: ExecutionBinding,
) -> tuple[bool, dict[str, Any]]:
    timeout = float(binding.config.get("verification_timeout_seconds", 5))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if execution.capability in {"endpoint.isolate", "endpoint.unisolate"}:
                desired = execution.capability == "endpoint.isolate"
                url = (
                    f"{binding.endpoint}/v1/observer/endpoints/"
                    f"{execution.target_asset_id}/isolation"
                )
                response = await client.get(url)
                response.raise_for_status()
                observed = bool(response.json().get("isolated", False))
                return observed == desired, {
                    "strategy": "reference_endpoint_observer",
                    "isolated": observed,
                    "desired": desired,
                }
            if execution.capability in {"firewall.block_ip", "firewall.unblock_ip"}:
                address = execution.executor_result.get("address")
                if not isinstance(address, str):
                    return False, {
                        "strategy": "reference_firewall_observer",
                        "reason": "execution_result_missing_address",
                    }
                desired = execution.capability == "firewall.block_ip"
                encoded_address = quote(address, safe="")
                url = f"{binding.endpoint}/v1/observer/firewall/blocks/{encoded_address}"
                response = await client.get(url)
                if response.status_code not in {200, 404}:
                    response.raise_for_status()
                observed = response.status_code == 200
                return observed == desired, {
                    "strategy": "reference_firewall_observer",
                    "blocked": observed,
                    "desired": desired,
                }
    except (httpx.HTTPError, ValueError, TypeError):
        return False, {"strategy": "reference_observer", "reason": "observer_failed"}
    return False, {"strategy": "reference_observer", "reason": "unsupported_capability"}


async def verify_execution(
    execution: ActionExecution,
    binding: ExecutionBinding,
) -> tuple[bool, dict[str, Any]]:
    if execution.capability in {
        "endpoint.isolate",
        "endpoint.unisolate",
        "firewall.block_ip",
        "firewall.unblock_ip",
    }:
        return await _reference_observer(execution, binding)

    config = binding.config.get("verification", {})
    if not isinstance(config, dict):
        return False, {"strategy": "binding_probe", "reason": "verification_config_invalid"}
    strategy = config.get("strategy")
    if strategy == "tcp_probe":
        return await _tcp_probe(config, binding)
    if strategy == "http_probe":
        return await _http_probe(config)
    return False, {"strategy": "binding_probe", "reason": "independent_probe_required"}
