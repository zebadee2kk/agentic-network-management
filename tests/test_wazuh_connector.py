import httpx
import pytest

from anm.connectors.wazuh import WazuhConnectorError, WazuhIndexerConnector


@pytest.mark.asyncio
async def test_wazuh_connector_only_queries_hard_coded_alert_search() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/wazuh-alerts*/_search"
        assert request.headers["Authorization"] == "Bearer read-only-token"
        body = __import__("json").loads(request.content)
        assert body["size"] == 500
        assert body["track_total_hits"] is False
        return httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_id": "evt-1",
                            "sort": ["2026-08-16T19:00:00Z", "evt-1"],
                            "_source": {"timestamp": "2026-08-16T19:00:00Z"},
                        }
                    ]
                }
            },
        )

    connector = WazuhIndexerConnector(
        base_url="https://wazuh.example",
        secret={"token": "read-only-token"},
        transport=httpx.MockTransport(handler),
    )
    documents, cursor = await connector.poll(size=9999)
    assert len(documents) == 1
    assert cursor == ["2026-08-16T19:00:00Z", "evt-1"]
    assert not hasattr(connector, "execute")


@pytest.mark.asyncio
async def test_wazuh_auth_failure_never_echoes_secret() -> None:
    secret = "never-echo-wazuh-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": f"invalid {secret}"})

    connector = WazuhIndexerConnector(
        base_url="https://wazuh.example",
        secret={"token": secret},
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(WazuhConnectorError) as exc:
        await connector.poll()
    assert exc.value.category == "authentication_failed"
    assert secret not in exc.value.detail
