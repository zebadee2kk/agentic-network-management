import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from anm.config import Settings


@dataclass(frozen=True)
class ModelRequest:
    provider_id: uuid.UUID
    agent_role: str
    messages: list[dict[str, str]]
    response_schema: dict[str, Any]
    max_output_tokens: int = 1600


@dataclass(frozen=True)
class ModelResponse:
    content: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int


class ModelGateway(Protocol):
    async def generate(self, request: ModelRequest) -> ModelResponse: ...


class RelayModelGateway:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = settings.model_relay_url.rstrip("/")
        self._timeout = settings.model_timeout_seconds
        self._transport = transport

    async def generate(self, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()
        payload = {
            "provider_id": str(request.provider_id),
            "agent_role": request.agent_role,
            "messages": request.messages,
            "response_schema": request.response_schema,
            "max_output_tokens": request.max_output_tokens,
        }
        async with httpx.AsyncClient(
            timeout=self._timeout,
            transport=self._transport,
            follow_redirects=False,
        ) as client:
            response = await client.post(f"{self._url}/internal/v1/generate", json=payload)
            response.raise_for_status()
            body = response.json()
        latency_ms = int((time.monotonic() - started) * 1000)
        return ModelResponse(
            content=str(body["content"]),
            model=str(body["model"]),
            input_tokens=int(body.get("input_tokens", 0)),
            output_tokens=int(body.get("output_tokens", 0)),
            latency_ms=latency_ms,
        )
