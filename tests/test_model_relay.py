import uuid

import pytest
from pydantic import ValidationError

from anm.ai_models import ModelProvider
from anm.ai_schemas import ModelProviderCreate
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


def test_external_provider_configuration_requires_https() -> None:
    with pytest.raises(ValidationError, match="require HTTPS"):
        ModelProviderCreate(
            name="plaintext",
            locality="external",
            base_url="http://example.com/v1",
            model="test",
            secret_ref="openbao://models/plaintext",
        )


@pytest.mark.asyncio
async def test_relay_rejects_plaintext_external_provider_even_if_db_is_corrupted() -> None:
    provider = ModelProvider(
        id=uuid.uuid4(),
        name="plaintext",
        locality="external",
        base_url="http://example.com/v1",
        model="test",
        secret_ref="openbao://models/plaintext",
    )
    with pytest.raises(ValueError, match="require HTTPS"):
        await validate_provider_endpoint(provider)


def test_isolated_local_provider_may_use_http() -> None:
    provider = ModelProviderCreate(
        name="local",
        locality="isolated_local",
        base_url="http://ollama:11434/v1",
        model="test",
    )
    assert provider.base_url == "http://ollama:11434/v1"


def test_openai_compatible_base_paths_may_include_prefix_before_v1() -> None:
    openrouter = ModelProviderCreate(
        name="openrouter",
        locality="external",
        base_url="https://openrouter.ai/api/v1",
        model="test/model",
        secret_ref="openbao://models/openrouter",
    )
    groq = ModelProviderCreate(
        name="groq",
        locality="external",
        base_url="https://api.groq.com/openai/v1",
        model="test-model",
        secret_ref="openbao://models/groq",
    )
    assert openrouter.base_url.endswith("/api/v1")
    assert groq.base_url.endswith("/openai/v1")


def test_base_path_must_still_end_with_v1() -> None:
    with pytest.raises(ValidationError, match="end with /v1"):
        ModelProviderCreate(
            name="bad-path",
            locality="external",
            base_url="https://example.com/api/v2",
            model="test",
            secret_ref="openbao://models/bad-path",
        )


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
