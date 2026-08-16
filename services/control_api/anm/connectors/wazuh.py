from typing import Any

import httpx


class WazuhConnectorError(RuntimeError):
    def __init__(self, category: str, detail: str) -> None:
        super().__init__(detail)
        self.category = category
        self.detail = detail


class WazuhIndexerConnector:
    """Read-only Wazuh alert poller using one hard-coded index search endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        secret: dict[str, Any],
        timeout_seconds: float = 10.0,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.transport = transport

    def _auth(self) -> tuple[dict[str, str], httpx.Auth | None]:
        token = self.secret.get("token") or self.secret.get("bearer_token")
        if isinstance(token, str) and token.strip():
            return {"Authorization": f"Bearer {token.strip()}"}, None
        username = self.secret.get("username")
        password = self.secret.get("password")
        if isinstance(username, str) and isinstance(password, str) and username and password:
            return {}, httpx.BasicAuth(username, password)
        raise WazuhConnectorError(
            "authentication_failed",
            "Wazuh secret must contain token/bearer_token or username/password",
        )

    async def poll(
        self,
        *,
        search_after: list[Any] | None = None,
        size: int = 250,
    ) -> tuple[list[dict[str, Any]], list[Any] | None]:
        headers, auth = self._auth()
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        safe_size = max(1, min(int(size), 500))
        body: dict[str, Any] = {
            "size": safe_size,
            "track_total_hits": False,
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "query": {"match_all": {}},
            "_source": [
                "timestamp",
                "id",
                "agent",
                "rule",
                "data",
                "full_log",
                "location",
            ],
        }
        if search_after:
            body["search_after"] = search_after
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                follow_redirects=False,
                verify=self.verify_tls,
                transport=self.transport,
                auth=auth,
            ) as client:
                response = await client.post(
                    "/wazuh-alerts*/_search",
                    headers=headers,
                    json=body,
                )
            if response.status_code in {401, 403}:
                category = (
                    "authentication_failed"
                    if response.status_code == 401
                    else "authorization_failed"
                )
                raise WazuhConnectorError(category, "Wazuh indexer rejected read credentials")
            if response.status_code == 429:
                raise WazuhConnectorError(
                    "rate_limited",
                    "Wazuh indexer rate limited alert polling",
                )
            response.raise_for_status()
            payload = response.json()
            hits = payload["hits"]["hits"]
            if not isinstance(hits, list):
                raise TypeError("hits must be a list")
        except WazuhConnectorError:
            raise
        except httpx.TimeoutException as exc:
            raise WazuhConnectorError("timeout", "Wazuh alert polling timed out") from exc
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise WazuhConnectorError("upstream_error", "Wazuh alert polling failed") from exc

        documents = [hit for hit in hits if isinstance(hit, dict)]
        next_cursor: list[Any] | None = None
        if documents:
            sort_value = documents[-1].get("sort")
            if isinstance(sort_value, list):
                next_cursor = sort_value
        return documents, next_cursor
