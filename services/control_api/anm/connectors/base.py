import ipaddress
import uuid
from abc import ABC, abstractmethod
from typing import Any

import httpx

from anm.schemas import ObservationCreate


class ConnectorError(RuntimeError):
    def __init__(self, category: str, detail: str) -> None:
        super().__init__(detail)
        self.category = category
        self.detail = detail


class ReadOnlyDiscoveryConnector(ABC):
    """HTTP GET-only connector with a per-run request budget and CIDR scope helper."""

    connector_type: str

    def __init__(
        self,
        *,
        connector_instance_id: uuid.UUID,
        base_url: str,
        token: str,
        config: dict[str, Any],
        request_budget: int,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.connector_instance_id = connector_instance_id
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.config = config
        self.request_budget = request_budget
        self.timeout_seconds = timeout_seconds
        self._request_count = 0
        self._transport = transport

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("assets.discover", "assets.read")

    async def _get(
        self,
        path: str,
        *,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        if not path.startswith("/") or "://" in path:
            raise ConnectorError("unsupported", "connector path must be a relative API path")
        if self._request_count >= self.request_budget:
            raise ConnectorError("rate_limited", "discovery request budget exceeded")
        self._request_count += 1
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = await client.get(path, headers=headers, params=params)
            if response.status_code in {401, 403}:
                category = (
                    "authentication_failed"
                    if response.status_code == 401
                    else "authorization_failed"
                )
                raise ConnectorError(category, f"{self.connector_type} rejected read credentials")
            if response.status_code == 429:
                raise ConnectorError("rate_limited", f"{self.connector_type} rate limited discovery")
            response.raise_for_status()
            return response
        except ConnectorError:
            raise
        except httpx.TimeoutException as exc:
            raise ConnectorError("timeout", f"{self.connector_type} discovery timed out") from exc
        except httpx.HTTPError as exc:
            raise ConnectorError(
                "connection_failed",
                f"{self.connector_type} discovery request failed",
            ) from exc

    @staticmethod
    def management_ip_in_scope(value: str | None, cidrs: list[str]) -> bool:
        if not cidrs:
            return True
        if not value:
            return False
        candidate = value.split("/", 1)[0]
        try:
            address = ipaddress.ip_address(candidate)
            return any(address in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)
        except ValueError:
            return False

    @abstractmethod
    async def discover(self, cidrs: list[str]) -> list[ObservationCreate]:
        raise NotImplementedError
