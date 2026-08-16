from anm.executors.ansible_adapter import AnsibleExecutor
from anm.executors.base import DeterministicExecutor
from anm.executors.reference_adapters import (
    ReferenceEndpointExecutor,
    ReferenceFirewallExecutor,
)


def get_executor(adapter: str) -> DeterministicExecutor:
    if adapter == "ansible_windows":
        return AnsibleExecutor(platform="windows")
    if adapter == "ansible_linux":
        return AnsibleExecutor(platform="linux")
    if adapter == "reference_endpoint":
        return ReferenceEndpointExecutor()
    if adapter == "reference_firewall":
        return ReferenceFirewallExecutor()
    raise ValueError("capability adapter is not executable")
