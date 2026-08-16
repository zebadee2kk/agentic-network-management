from datetime import UTC, datetime
from typing import Any

from anm.connectors.base import ConnectorError, ReadOnlyDiscoveryConnector
from anm.schemas import ObservationCreate, ObservationIdentifier


class NetBoxConnector(ReadOnlyDiscoveryConnector):
    connector_type = "netbox"
    _allowed_filters = {"site", "site_id", "role", "status", "tenant_id", "tag"}

    @staticmethod
    def _nested_value(value: Any, key: str) -> Any:
        return value.get(key) if isinstance(value, dict) else None

    @classmethod
    def _primary_ip(cls, device: dict[str, Any]) -> str | None:
        for field in ("primary_ip4", "primary_ip6", "primary_ip"):
            value = device.get(field)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, dict):
                address = value.get("address") or value.get("display")
                if isinstance(address, str) and address:
                    return address
        return None

    @classmethod
    def _asset_type(cls, device: dict[str, Any], config: dict[str, Any]) -> str:
        role = device.get("role") or device.get("device_role")
        role_slug = cls._nested_value(role, "slug") or cls._nested_value(role, "name") or ""
        configured = config.get("asset_type_map", {}).get(str(role_slug))
        if configured:
            return str(configured)
        lowered = str(role_slug).lower()
        for needle, asset_type in (
            ("firewall", "firewall"),
            ("router", "router"),
            ("switch", "switch"),
            ("wireless", "wireless_ap"),
            ("access-point", "wireless_ap"),
            ("server", "server"),
            ("hypervisor", "hypervisor"),
        ):
            if needle in lowered:
                return asset_type
        return "network_device"

    @classmethod
    def normalize_device(
        cls,
        connector_instance_id: Any,
        device: dict[str, Any],
        config: dict[str, Any],
    ) -> ObservationCreate:
        device_id = device.get("id")
        if device_id is None:
            raise ConnectorError("invalid_response", "NetBox device did not include id")
        name = device.get("name") or device.get("display") or f"netbox-{device_id}"
        primary_ip = cls._primary_ip(device)
        identifiers = [
            ObservationIdentifier(namespace="netbox", value=str(device_id), confidence=1.0)
        ]
        serial = device.get("serial")
        if serial:
            identifiers.append(
                ObservationIdentifier(namespace="serial", value=str(serial), confidence=1.0)
            )
        asset_tag = device.get("asset_tag")
        if asset_tag:
            identifiers.append(
                ObservationIdentifier(namespace="asset_tag", value=str(asset_tag), confidence=0.95)
            )
        if name:
            identifiers.append(
                ObservationIdentifier(namespace="hostname", value=str(name).lower(), confidence=0.8)
            )

        role = device.get("role") or device.get("device_role")
        role_slug = cls._nested_value(role, "slug") or cls._nested_value(role, "name")
        protected_role = config.get("protected_role_map", {}).get(str(role_slug))
        protected_roles = [str(protected_role)] if protected_role else []
        custom_fields = device.get("custom_fields") if isinstance(device.get("custom_fields"), dict) else {}
        zone_field = str(config.get("network_zone_field", "anm_network_zone"))
        network_zone = custom_fields.get(zone_field)

        status_value = cls._nested_value(device.get("status"), "value") or device.get("status")
        status = "active" if str(status_value).lower() == "active" else "unknown"
        return ObservationCreate(
            connector_instance_id=connector_instance_id,
            observed_at=datetime.now(UTC),
            attributes={
                "display_name": str(name),
                "hostname": str(name).lower(),
                "management_ip": primary_ip,
                "asset_type": cls._asset_type(device, config),
                "status": status,
                "network_zone": network_zone,
                "protected_roles": protected_roles,
                "source_role": role_slug,
                "source_site": cls._nested_value(device.get("site"), "name"),
            },
            identifiers=identifiers,
        )

    async def discover(self, cidrs: list[str]) -> list[ObservationCreate]:
        auth_scheme = str(self.config.get("auth_scheme", "Bearer"))
        if auth_scheme not in {"Bearer", "Token"}:
            raise ConnectorError("unsupported", "NetBox auth_scheme must be Bearer or Token")
        headers = {"Authorization": f"{auth_scheme} {self._token}", "Accept": "application/json"}
        page_size = min(int(self.config.get("page_size", 100)), 500)
        filters = self.config.get("filters", {})
        safe_filters = {
            key: value
            for key, value in filters.items()
            if key in self._allowed_filters and value is not None
        }
        observations: list[ObservationCreate] = []
        offset = 0

        while True:
            params = {"limit": page_size, "offset": offset, **safe_filters}
            response = await self._get("/api/dcim/devices/", headers=headers, params=params)
            try:
                payload = response.json()
                devices = payload["results"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ConnectorError("invalid_response", "NetBox returned invalid device data") from exc
            if not isinstance(devices, list):
                raise ConnectorError("invalid_response", "NetBox device results were not a list")
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
            offset += len(devices)
            count = payload.get("count")
            if not devices or not isinstance(count, int) or offset >= count:
                break

        return observations
