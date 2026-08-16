from typing import Any

import httpx

from anm.config import Settings
from anm.policy_types import ActionPolicyDecision


class PolicyClient:
    def __init__(self, settings: Settings) -> None:
        self._url = settings.opa_url.rstrip("/")
        self._timeout = settings.opa_timeout_seconds

    async def evaluate_action(self, input_document: dict[str, Any]) -> ActionPolicyDecision:
        """Evaluate action policy. Any transport/schema/policy failure denies the action."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._url}/v1/data/anm/action/decision",
                    json={"input": input_document},
                )
                response.raise_for_status()
                payload = response.json()
                result = payload.get("result")
                if not isinstance(result, dict):
                    raise ValueError("OPA returned no decision object")
                return ActionPolicyDecision.model_validate({**result, "source": "opa"})
        except (httpx.HTTPError, ValueError, TypeError):
            return ActionPolicyDecision(
                decision="deny",
                reasons=["policy_engine_unavailable_or_invalid"],
                required_roles=[],
                source="fail_closed",
                policy_version="fail-closed",
            )

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(f"{self._url}/health")
                return response.is_success
        except httpx.HTTPError:
            return False
