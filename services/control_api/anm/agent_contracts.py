from typing import Final

AGENT_TOOL_ALLOWLISTS: Final[dict[str, tuple[str, ...]]] = {
    "supervisor": (
        "incident.read",
        "asset.read",
        "evidence.read",
        "agent.delegate",
        "investigation.record",
    ),
    "soc_analyst": (
        "incident.read",
        "asset.read",
        "wazuh.alerts.read",
        "wazuh.endpoint_events.read",
        "suricata.events.read",
        "behaviour.findings.read",
        "evidence.attach",
        "hypothesis.create",
    ),
    "network_analyst": (
        "asset.read",
        "topology.read",
        "netbox.read",
        "librenms.read",
        "network_connector.read_allowlisted",
        "suricata.events.read",
        "hypothesis.create",
    ),
}

FORBIDDEN_TOOL_PREFIXES: Final[tuple[str, ...]] = (
    "secret.",
    "shell.",
    "action.execute",
    "action.approve",
    "policy.",
    "approval.",
    "network.raw_connect",
)


def tools_for_role(role: str) -> tuple[str, ...]:
    try:
        tools = AGENT_TOOL_ALLOWLISTS[role]
    except KeyError as exc:
        raise ValueError("unknown agent role") from exc
    for tool in tools:
        if tool.startswith(FORBIDDEN_TOOL_PREFIXES):
            raise RuntimeError(f"privileged tool leaked into {role} allowlist")
    return tools


def validate_tool_for_role(role: str, tool: str) -> bool:
    return tool in tools_for_role(role)
