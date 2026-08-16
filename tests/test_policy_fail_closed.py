import pytest

from anm.config import Settings
from anm.services.policy import PolicyClient


def complete_input() -> dict:
    return {
        "action": {"capability": "endpoint.isolate", "risk": 2},
        "target": {"asset_id": "test", "protected_roles": []},
        "incident": {"confidence": 0.99},
        "requester": {"type": "agent", "id": "test"},
        "environment": {"autonomy_level": 3},
    }


@pytest.mark.asyncio
async def test_opa_transport_failure_denies() -> None:
    settings = Settings(opa_url="http://127.0.0.1:1", opa_timeout_seconds=0.1)
    decision = await PolicyClient(settings).evaluate_action(complete_input())

    assert decision.decision == "deny"
    assert decision.source == "fail_closed"
    assert "policy_engine_unavailable_or_invalid" in decision.reasons
