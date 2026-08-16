package anm.action_test

import rego.v1

base_input := {
    "action": {
        "capability": "endpoint.isolate",
        "capability_version": "1.0.0",
        "risk": 2,
        "write": true,
        "capability_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "implementation_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "proposal_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    },
    "target": {"asset_id": "asset-1", "protected_roles": []},
    "incident": {"confidence": 0.97},
    "requester": {"type": "agent", "id": "remediation-planner", "roles": []},
    "environment": {"autonomy_level": 3},
}

test_invalid_input_denied if {
    result := data.anm.action.decision with input as {"action": {"risk": 1}}
    result.decision == "deny"
    result.reasons == ["invalid_or_incomplete_policy_input"]
    result.policy_version == "baseline-v1.1"
}

test_destructive_risk_denied if {
    action := object.union(base_input.action, {"capability": "dangerous", "risk": 5})
    candidate := object.union(base_input, {"action": action})
    result := data.anm.action.decision with input as candidate
    result.decision == "deny"
    result.reasons == ["destructive_risk_class_denied"]
}

test_read_only_allowed_at_level_two if {
    action := object.union(base_input.action, {"write": false, "risk": 0})
    candidate := object.union(base_input, {
        "action": action,
        "environment": {"autonomy_level": 2},
    })
    result := data.anm.action.decision with input as candidate
    result.decision == "allow"
    result.reasons == ["read_only_capability"]
}

test_protected_asset_requires_platform_approval if {
    candidate := object.union(base_input, {
        "target": {"asset_id": "dc-1", "protected_roles": ["identity"]},
    })
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["protected_asset_role"]
    result.required_roles == ["platform_approver"]
}

test_level_two_write_requires_human if {
    candidate := object.union(base_input, {"environment": {"autonomy_level": 2}})
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["autonomy_level_requires_human"]
    result.required_roles == ["operator_approver"]
}

test_low_confidence_requires_security_approval if {
    candidate := object.union(base_input, {"incident": {"confidence": 0.5}})
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.reasons == ["insufficient_incident_confidence"]
    result.required_roles == ["security_approver"]
}

test_low_risk_guarded_autonomy_allowed if {
    result := data.anm.action.decision with input as base_input
    result.decision == "allow"
    result.reasons == ["low_risk_guarded_autonomy"]
}

test_risk_four_requires_platform_approval if {
    action := object.union(base_input.action, {"risk": 4})
    candidate := object.union(base_input, {"action": action})
    result := data.anm.action.decision with input as candidate
    result.decision == "require_approval"
    result.required_roles == ["platform_approver"]
}
