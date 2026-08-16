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

    if network_names(services["ui"]) != {"edge", "api"}:
        fail("ui must attach only to edge and api networks")

    control_networks = network_names(services["control-api"])
    required_control_networks = {"api", "control", "data", "secrets"}
    if not required_control_networks.issubset(control_networks):
        fail("control-api is missing a required internal network")
    if control_networks & {"discovery", "telemetry", "model-egress", "ai"}:
        fail("control-api must not have worker/provider egress networks")

    discovery_networks = network_names(services["discovery-worker"])
    if discovery_networks != {"control", "data", "secrets", "discovery"}:
        fail("discovery-worker network set is not least privilege")

    telemetry_networks = network_names(services["telemetry-worker"])
    if telemetry_networks != {"control", "data", "secrets", "telemetry"}:
        fail("telemetry-worker network set is not least privilege")

    # INV-001/002: the reasoning worker has no OpenBao network and no non-internal
    # egress network. It reaches providers only through model-relay on `ai`.
    ai_worker_networks = network_names(services["ai-worker"])
    if ai_worker_networks != {"control", "data", "ai"}:
        fail("ai-worker must attach only to control, data and internal ai networks")
    if ai_worker_networks & {"secrets", "discovery", "telemetry", "model-egress", "edge", "api"}:
        fail("ai-worker gained a privileged or egress network")

    relay_networks = network_names(services["model-relay"])
    if relay_networks != {"ai", "data", "secrets", "model-egress"}:
        fail("model-relay network set is not least privilege")
    if relay_networks & {"discovery", "telemetry", "edge", "api", "control"}:
        fail("model-relay must not share managed/browser/control networks")

    for worker in ("discovery-worker", "telemetry-worker", "ai-worker", "model-relay"):
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

    model_egress_members = {
        name for name, service in services.items() if "model-egress" in network_names(service)
    }
    if model_egress_members != {"model-relay"}:
        fail(f"only model-relay may use model egress, got {sorted(model_egress_members)}")

    ai_members = {name for name, service in services.items() if "ai" in network_names(service)}
    if ai_members != {"ai-worker", "model-relay"}:
        fail(f"internal ai network membership is unexpected: {sorted(ai_members)}")

    protected = (
        "nats",
        "opa",
        "postgres",
        "openbao",
        "discovery-worker",
        "telemetry-worker",
        "ai-worker",
        "model-relay",
    )
    for protected_service in protected:
        if network_names(services["ui"]) & network_names(services[protected_service]):
            fail(f"ui must not share a network with {protected_service}")

    for internal_network in ("api", "control", "data", "secrets", "ai"):
        if not networks[internal_network].get("internal", False):
            fail(f"{internal_network} must be internal")
    for egress_network in ("discovery", "telemetry", "model-egress"):
        if networks[egress_network].get("internal", False):
            fail(f"{egress_network} network must provide scoped egress")

    print("compose trust boundaries validated")


if __name__ == "__main__":
    main()
