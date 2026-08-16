import pytest

from anm.config import Settings
from anm.services.policy import PolicyClient


def complete_input() -> dict:
    return {
        "action": {
            "capability": "endpoint.isolate",
            "capability_version": "1.0.0",
            "risk": 2,
            "write": True,
            "reversible": True,
            "capability_digest": "a" * 64,
            "implementation_digest": "b" * 64,
            "proposal_digest": "c" * 64,
        },
        "target": {"asset_id": "test", "protected_roles": []},
        "incident": {"confidence": 0.99},
        "requester": {"type": "agent", "id": "test", "roles": []},
        "environment": {"autonomy_level": 3},
    }


@pytest.mark.asyncio
async def test_opa_transport_failure_denies() -> None:
    settings = Settings(opa_url="http://127.0.0.1:1", opa_timeout_seconds=0.1)
    decision = await PolicyClient(settings).evaluate_action(complete_input())

    assert decision.decision == "deny"
    assert decision.source == "fail_closed"
    assert decision.policy_version == "fail-closed"
    assert "policy_engine_unavailable_or_invalid" in decision.reasons


@pytest.mark.asyncio
async def test_opa_response_without_policy_version_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "result": {
                    "decision": "allow",
                    "reasons": ["should_not_be_accepted"],
                    "required_roles": [],
                }
            }

    class FakeClient:
        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, *_args: object, **_kwargs: object) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(
        "anm.services.policy.httpx.AsyncClient",
        lambda **_kwargs: FakeClient(),
    )
    decision = await PolicyClient(Settings()).evaluate_action(complete_input())

    assert decision.decision == "deny"
    assert decision.source == "fail_closed"
    assert decision.policy_version == "fail-closed"
    assert "policy_engine_unavailable_or_invalid" in decision.reasons
