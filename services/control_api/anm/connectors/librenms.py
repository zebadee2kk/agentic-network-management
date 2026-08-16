import ipaddress
from datetime import UTC, datetime
from typing import Any

from anm.connectors.base import ConnectorError, ReadOnlyDiscoveryConnector
from anm.schemas import ObservationCreate, ObservationIdentifier, TopologyHint


class LibreNMSConnector(ReadOnlyDiscoveryConnector):
    connector_type = "librenms"

    @staticmethod
    def _management_ip(device: dict[str, Any]) -> str | None:
        for field in ("ip", "ip_address", "hostname"):
            value = device.get(field)
            if not value:
                continue
            candidate = str(value).split("/", 1)[0]
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
        return None

    @staticmethod
    def _asset_type(device: dict[str, Any]) -> str:
        haystack = " ".join(
            str(device.get(field, "")) for field in ("type", "hardware", "os", "sysDescr")
        ).lower()
        for needle, asset_type in (
            ("firewall", "firewall"),
            ("router", "router"),
            ("switch", "switch"),
            ("wireless", "wireless_ap"),
            ("access point", "wireless_ap"),
            ("hypervisor", "hypervisor"),
            ("server", "server"),
        ):
            if needle in haystack:
                return asset_type
        return "network_device"

    @staticmethod
    def _parent_ids(device: dict[str, Any]) -> list[str]:
        value = device.get("dependency_parent_id")
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [item.strip() for item in str(value).split(",") if item.strip()]

    @classmethod
    def normalize_device(
        cls,
        connector_instance_id: Any,
        device: dict[str, Any],
        config: dict[str, Any],
    ) -> ObservationCreate:
        device_id = device.get("device_id")
        if device_id is None:
            raise ConnectorError("invalid_response", "LibreNMS device did not include device_id")
        hostname = device.get("sysName") or device.get("hostname") or f"librenms-{device_id}"
        identifiers = [
            ObservationIdentifier(namespace="librenms", value=str(device_id), confidence=1.0)
        ]
        serial = device.get("serial")
        if serial:
            identifiers.append(
                ObservationIdentifier(namespace="serial", value=str(serial), confidence=1.0)
            )
        if hostname:
            namespace = "fqdn" if "." in str(hostname) else "hostname"
            identifiers.append(
                ObservationIdentifier(
                    namespace=namespace,
                    value=str(hostname).lower(),
                    confidence=0.8,
                )
            )
        topology = [
            TopologyHint(
                relationship="depends_on",
                target_namespace="librenms",
                target_value=parent_id,
                confidence=0.9,
                metadata={"source_field": "dependency_parent_id"},
            )
            for parent_id in cls._parent_ids(device)
            if parent_id != str(device_id)
        ]
        protected_role = config.get("protected_role")
        protected_roles = [str(protected_role)] if protected_role else []
        return ObservationCreate(
            connector_instance_id=connector_instance_id,
            observed_at=datetime.now(UTC),
            attributes={
                "display_name": str(hostname),
                "hostname": str(hostname).lower(),
                "management_ip": cls._management_ip(device),
                "asset_type": cls._asset_type(device),
                "status": "active" if bool(device.get("status", True)) else "inactive",
                "protected_roles": protected_roles,
                "hardware": device.get("hardware"),
                "os": device.get("os"),
            },
            identifiers=identifiers,
            topology=topology,
        )

    async def discover(self, cidrs: list[str]) -> list[ObservationCreate]:
        headers = {"X-Auth-Token": self._token, "Accept": "application/json"}
        response = await self._get("/api/v0/devices", headers=headers)
        try:
            payload = response.json()
            devices = payload["devices"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ConnectorError(
                "invalid_response",
                "LibreNMS returned invalid device data",
            ) from exc
        if not isinstance(devices, list):
            raise ConnectorError("invalid_response", "LibreNMS device results were not a list")
        observations: list[ObservationCreate] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            observation = self.normalize_device(
                self.connector_instance_id,
                device,
                self.config,
            )
            management_ip = observation.attributes.get("management_ip")
            if self.management_ip_in_scope(
                str(management_ip) if management_ip else None,
                cidrs,
            ):
                observations.append(observation)
        return observations
