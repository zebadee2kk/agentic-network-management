import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"compose boundary validation failed: {message}")


def network_names(service: dict) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, list):
        return set(networks)
    return set(networks.keys())


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate_compose_boundaries.py <compose-json>")

    model = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    services = model["services"]
    networks = model["networks"]

    published = {name for name, service in services.items() if service.get("ports")}
    if published != {"ui"}:
        fail(f"only ui may publish host ports, got {sorted(published)}")

    expected_ui_networks = {"edge", "api"}
    if network_names(services["ui"]) != expected_ui_networks:
        fail("ui must attach only to edge and api networks")

    control_networks = network_names(services["control-api"])
    required_control_networks = {"api", "control", "data", "secrets"}
    if not required_control_networks.issubset(control_networks):
        fail("control-api is missing a required internal network")
    if control_networks & {"discovery", "telemetry"}:
        fail("control-api must not have management egress networks")

    discovery_networks = network_names(services["discovery-worker"])
    required_discovery = {"control", "data", "secrets", "discovery"}
    if discovery_networks != required_discovery:
        fail("discovery-worker network set is not least privilege")

    telemetry_networks = network_names(services["telemetry-worker"])
    required_telemetry = {"control", "data", "secrets", "telemetry"}
    if telemetry_networks != required_telemetry:
        fail("telemetry-worker network set is not least privilege")

    for worker in ("discovery-worker", "telemetry-worker"):
        if network_names(services[worker]) & {"api", "edge"}:
            fail(f"{worker} must not share browser-facing networks")

    discovery_members = {
        name for name, service in services.items() if "discovery" in network_names(service)
    }
    if discovery_members != {"discovery-worker"}:
        fail(f"only discovery-worker may use discovery egress, got {sorted(discovery_members)}")

    telemetry_members = {
        name for name, service in services.items() if "telemetry" in network_names(service)
    }
    if telemetry_members != {"telemetry-worker"}:
        fail(f"only telemetry-worker may use telemetry egress, got {sorted(telemetry_members)}")

    protected = ("nats", "opa", "postgres", "openbao", "discovery-worker", "telemetry-worker")
    for protected_service in protected:
        if network_names(services["ui"]) & network_names(services[protected_service]):
            fail(f"ui must not share a network with {protected_service}")

    for internal_network in ("api", "control", "data", "secrets"):
        if not networks[internal_network].get("internal", False):
            fail(f"{internal_network} must be internal")
    for egress_network in ("discovery", "telemetry"):
        if networks[egress_network].get("internal", False):
            fail(f"{egress_network} network must provide scoped read-only egress")

    print("compose trust boundaries validated")


if __name__ == "__main__":
    main()
