import uuid

import pytest

from anm.ai_models import ModelProvider
from anm.model_relay import RelayRequest, build_upstream_request, validate_provider_endpoint


@pytest.mark.asyncio
async def test_external_provider_cannot_target_private_management_address() -> None:
    provider = ModelProvider(
        id=uuid.uuid4(),
        name="bad",
        locality="external",
        base_url="https://10.0.0.5/v1",
        model="test",
        secret_ref="openbao://models/bad",
    )
    with pytest.raises(ValueError, match="prohibited address"):
        await validate_provider_endpoint(provider)


def test_upstream_request_never_exposes_provider_side_tools() -> None:
    provider = ModelProvider(
        id=uuid.uuid4(),
        name="local",
        locality="isolated_local",
        base_url="http://ollama:11434/v1",
        model="test",
        config={"supports_json_schema": True},
    )
    request = RelayRequest(
        provider_id=provider.id,
        agent_role="soc_analyst",
        messages=[{"role": "user", "content": "data"}],
        response_schema={"type": "object"},
    )
    body = build_upstream_request(provider, request)
    assert "tools" not in body
    assert "tool_choice" not in body
    assert body["response_format"]["type"] == "json_schema"
