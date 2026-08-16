package anm.action_test

import rego.v1

base_input := {
    "action": {"capability": "endpoint.isolate", "risk": 2},
    "target": {"asset_id": "asset-1", "protected_roles": []},
    "incident": {"confidence": 0.97},
    "requester": {"type": "agent", "id": "remediation-planner"},
    "environment": {"autonomy_level": 3},
}

test_invalid_input_denied if {
    result := data.anm.action.decision with input as {"action": {"risk": 1}}
    result.decision == "deny"
    result.reasons == ["invalid_or_incomplete_policy_input"]
}

test_destructive_risk_denied if {
    candidate := object.union(base_input, {"action": {"capability": "dangerous", "risk": 5}})
    result := data.anm.action.decision with input as candidate
    result.decision == "deny"
    result.reasons == ["destructive_risk_class_denied"]
}

test_protected_asset_requires_approval if {
    candidate := object.union(base_input, {
        "target": {"asset_id": "dc-1", "protected_roles": ["domain_controller"]},
    })
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["protected_asset_role"]
}

test_level_two_requires_human if {
    candidate := object.union(base_input, {"environment": {"autonomy_level": 2}})
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["autonomy_level_requires_human"]
}

test_low_confidence_requires_approval if {
    candidate := object.union(base_input, {"incident": {"confidence": 0.5}})
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["insufficient_incident_confidence"]
}

test_low_risk_guarded_autonomy_allowed if {
    result := data.anm.action.decision with input as base_input
    result.decision == "allow"
    result.reasons == ["low_risk_guarded_autonomy"]
}
