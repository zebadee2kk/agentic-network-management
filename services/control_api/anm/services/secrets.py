from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from anm.config import Settings


class OpenBaoClient:
    def __init__(self, settings: Settings) -> None:
        self._url = settings.openbao_url.rstrip("/")
        self._token_file = Path(settings.openbao_token_file)
        self._timeout = settings.dependency_timeout_seconds

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(f"{self._url}/v1/sys/health")
                return response.status_code in {200, 429, 472, 473, 501, 503}
        except httpx.HTTPError:
            return False

    def _read_token(self) -> str:
        # Tokens are read from a mounted file, never from the platform database or model context.
        return self._token_file.read_text(encoding="utf-8").strip()

    @staticmethod
    def parse_reference(reference: str) -> tuple[str, str]:
        parsed = urlparse(reference)
        if parsed.scheme != "openbao" or not parsed.netloc or not parsed.path.strip("/"):
            raise ValueError("invalid OpenBao reference")
        return parsed.netloc, parsed.path.strip("/")

    async def read_kv_v2(self, reference: str) -> dict[str, Any]:
        """Resolve an OpenBao KV v2 reference for trusted executor/connector services only.

        This method deliberately has no API route in Phase 1. The control API stores references;
        future privileged workloads receive a narrower service identity and use this primitive.
        """
        mount, path = self.parse_reference(reference)
        token = self._read_token()
        headers = {"X-Vault-Token": token}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(f"{self._url}/v1/{mount}/data/{path}", headers=headers)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", {}).get("data")
            if not isinstance(data, dict):
                raise ValueError("OpenBao response did not contain KV data")
            return data
