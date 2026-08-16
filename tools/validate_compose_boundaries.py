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

    for protected_service in ("nats", "opa", "postgres", "openbao"):
        if network_names(services["ui"]) & network_names(services[protected_service]):
            fail(f"ui must not share a network with {protected_service}")

    for internal_network in ("api", "control", "data", "secrets"):
        if not networks[internal_network].get("internal", False):
            fail(f"{internal_network} must be internal")

    print("compose trust boundaries validated")


if __name__ == "__main__":
    main()
