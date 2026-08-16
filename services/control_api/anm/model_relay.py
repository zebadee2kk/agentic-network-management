import asyncio
import ipaddress
import socket
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from anm.ai_models import ModelProvider
from anm.config import get_settings
from anm.db import SessionLocal
from anm.services.secrets import OpenBaoClient

settings = get_settings()
app = FastAPI(title="ANM Model Relay", version="0.4.0")
secrets = OpenBaoClient(settings)


class RelayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: uuid.UUID
    agent_role: str = Field(pattern="^(soc_analyst|network_analyst|supervisor)$")
    messages: list[dict[str, str]] = Field(min_length=1, max_length=8)
    response_schema: dict[str, Any]
    max_output_tokens: int = Field(default=1600, ge=64, le=8192)


class RelayResponse(BaseModel):
    content: str
    model: str
    input_tokens: int
    output_tokens: int


def _is_public_address(address: str) -> bool:
    candidate = ipaddress.ip_address(address)
    return not (
        candidate.is_private
        or candidate.is_loopback
        or candidate.is_link_local
        or candidate.is_multicast
        or candidate.is_unspecified
        or candidate.is_reserved
    )


async def validate_provider_endpoint(provider: ModelProvider) -> None:
    parsed = urlsplit(provider.base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("provider base URL must use HTTP or HTTPS")
    if parsed.path.rstrip("/") != "/v1" or not parsed.hostname:
        raise ValueError("provider base URL must end with /v1")
    if provider.locality not in {"external", "isolated_local"}:
        raise ValueError("unknown model provider locality")

    hostname = parsed.hostname.lower().rstrip(".")
    if provider.locality == "isolated_local":
        if hostname not in settings.local_provider_hosts:
            raise ValueError("local provider host is not in ANM_AI_LOCAL_PROVIDER_HOSTS")
        return

    if parsed.scheme != "https":
        raise ValueError("external model providers require HTTPS")
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {str(literal)}
    except ValueError:
        try:
            results = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                None,
                0,
                socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError("model provider hostname could not be resolved") from exc
        addresses = {str(item[4][0]) for item in results}
    if not addresses or not all(_is_public_address(address) for address in addresses):
        raise ValueError("external model provider resolved to a prohibited address")


def _provider_api_key(secret: dict[str, Any]) -> str:
    value = secret.get("api_key") or secret.get("token") or secret.get("bearer_token")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("model provider secret must contain api_key, token or bearer_token")
    return value.strip()


def build_upstream_request(provider: ModelProvider, request: RelayRequest) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": provider.model,
        "messages": request.messages,
        "temperature": float(provider.config.get("temperature", 0.1)),
        "max_tokens": min(
            request.max_output_tokens,
            int(provider.config.get("max_output_tokens", request.max_output_tokens)),
        ),
    }
    if bool(provider.config.get("supports_json_schema", False)):
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "anm_investigation_result",
                "strict": True,
                "schema": request.response_schema,
            },
        }
    # No provider-side tools/functions are ever sent in Phase 4.
    return body


@app.get("/health/live")
def health_live() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/v1/generate", response_model=RelayResponse)
async def generate(request: RelayRequest) -> RelayResponse:
    with SessionLocal() as db:
        provider = db.get(ModelProvider, request.provider_id)
        if provider is None or not provider.enabled:
            raise HTTPException(status_code=404, detail="model provider unavailable")
        if provider.provider_type != "openai_compatible":
            raise HTTPException(status_code=400, detail="unsupported model provider type")
        try:
            await validate_provider_endpoint(provider)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if provider.secret_ref:
            try:
                secret = await secrets.read_kv_v2(provider.secret_ref)
                headers["Authorization"] = f"Bearer {_provider_api_key(secret)}"
            except (httpx.HTTPError, OSError, ValueError) as exc:
                raise HTTPException(
                    status_code=502,
                    detail="model provider credential unavailable",
                ) from exc
        elif provider.locality != "isolated_local":
            raise HTTPException(status_code=400, detail="external provider has no credential")

        upstream = f"{provider.base_url.rstrip('/')}/chat/completions"
        body = build_upstream_request(provider, request)
        try:
            async with httpx.AsyncClient(
                timeout=settings.model_timeout_seconds,
                follow_redirects=False,
            ) as client:
                response = await client.post(upstream, headers=headers, json=body)
            if response.status_code in {401, 403}:
                raise HTTPException(status_code=502, detail="model provider rejected credentials")
            response.raise_for_status()
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage", {})
            if not isinstance(content, str):
                raise TypeError("model response content was not text")
        except HTTPException:
            raise
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail="model provider request failed") from exc

        return RelayResponse(
            content=content,
            model=str(payload.get("model") or provider.model),
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
        )
