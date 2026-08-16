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


def require_hardened(service_name: str, service: dict) -> None:
    if not service.get("read_only", False):
        fail(f"{service_name} must use a read-only root filesystem")
    cap_drop = service.get("cap_drop", [])
    if "ALL" not in cap_drop:
        fail(f"{service_name} must drop all Linux capabilities")
    security_opt = service.get("security_opt", [])
    if "no-new-privileges:true" not in security_opt:
        fail(f"{service_name} must set no-new-privileges")


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
    if control_networks & {
        "discovery",
        "telemetry",
        "model-egress",
        "model-local",
        "ai",
        "execution",
        "verification",
    }:
        fail("control-api must not have worker/provider/managed execution egress networks")

    discovery_networks = network_names(services["discovery-worker"])
    if discovery_networks != {"control", "data", "secrets", "discovery"}:
        fail("discovery-worker network set is not least privilege")

    telemetry_networks = network_names(services["telemetry-worker"])
    if telemetry_networks != {"control", "data", "secrets", "telemetry"}:
        fail("telemetry-worker network set is not least privilege")

    # INV-001/002: the reasoning worker has no OpenBao, execution, verification,
    # provider-local or internet egress. Providers remain behind model-relay.
    ai_worker_networks = network_names(services["ai-worker"])
    if ai_worker_networks != {"control", "data", "ai"}:
        fail("ai-worker must attach only to control, data and internal ai networks")
    if ai_worker_networks & {
        "secrets",
        "discovery",
        "telemetry",
        "execution",
        "verification",
        "model-egress",
        "model-local",
        "edge",
        "api",
    }:
        fail("ai-worker gained a privileged or egress network")

    relay_networks = network_names(services["model-relay"])
    expected_relay = {"ai", "data", "secrets", "model-local", "model-egress"}
    if relay_networks != expected_relay:
        fail("model-relay network set is not least privilege")
    if relay_networks & {
        "discovery",
        "telemetry",
        "execution",
        "verification",
        "edge",
        "api",
        "control",
    }:
        fail("model-relay must not share managed/browser/control networks")

    executor_networks = network_names(services["executor-worker"])
    if executor_networks != {"control", "data", "secrets", "execution"}:
        fail("executor-worker network set is not least privilege")
    if executor_networks & {"ai", "model-egress", "model-local", "api", "edge"}:
        fail("executor-worker must not have AI/provider/browser networks")
    require_hardened("executor-worker", services["executor-worker"])

    verifier_networks = network_names(services["verifier-worker"])
    if verifier_networks != {"control", "data", "verification"}:
        fail("verifier-worker network set is not least privilege")
    if verifier_networks & {"secrets", "execution", "ai", "model-egress", "model-local"}:
        fail("verifier-worker must not have secret, executor or model access")
    if services["verifier-worker"].get("volumes"):
        fail("verifier-worker must not mount credential material")
    require_hardened("verifier-worker", services["verifier-worker"])

    workers = (
        "discovery-worker",
        "telemetry-worker",
        "ai-worker",
        "model-relay",
        "executor-worker",
        "verifier-worker",
    )
    for worker in workers:
        if network_names(services[worker]) & {"api", "edge"}:
            fail(f"{worker} must not share browser-facing networks")

    exclusive_egress = {
        "discovery": {"discovery-worker"},
        "telemetry": {"telemetry-worker"},
        "model-egress": {"model-relay"},
        "execution": {"executor-worker"},
        "verification": {"verifier-worker"},
    }
    for network, expected in exclusive_egress.items():
        members = {
            name for name, service in services.items() if network in network_names(service)
        }
        if members != expected:
            fail(f"{network} membership is unexpected: {sorted(members)}")

    model_local_members = {
        name for name, service in services.items() if "model-local" in network_names(service)
    }
    if model_local_members != {"model-relay"}:
        fail(
            "core compose model-local network must contain only model-relay; "
            "optional local providers attach separately"
        )

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
        "executor-worker",
        "verifier-worker",
    )
    for protected_service in protected:
        if network_names(services["ui"]) & network_names(services[protected_service]):
            fail(f"ui must not share a network with {protected_service}")

    for internal_network in ("api", "control", "data", "secrets", "ai", "model-local"):
        if not networks[internal_network].get("internal", False):
            fail(f"{internal_network} must be internal")
    for egress_network in (
        "discovery",
        "telemetry",
        "model-egress",
        "execution",
        "verification",
    ):
        if networks[egress_network].get("internal", False):
            fail(f"{egress_network} network must provide scoped egress")

    print("compose trust boundaries validated")


if __name__ == "__main__":
    main()
