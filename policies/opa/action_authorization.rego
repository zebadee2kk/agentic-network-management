package anm.action

import rego.v1

policy_version := "baseline-v1.1"

valid_input if {
    is_string(input.action.capability)
    is_string(input.action.capability_version)
    is_number(input.action.risk)
    input.action.risk >= 0
    input.action.risk <= 5
    is_boolean(input.action.write)
    is_string(input.action.capability_digest)
    is_string(input.action.implementation_digest)
    is_string(input.action.proposal_digest)
    is_array(input.target.protected_roles)
    is_number(input.incident.confidence)
    input.incident.confidence >= 0
    input.incident.confidence <= 1
    is_number(input.environment.autonomy_level)
    input.environment.autonomy_level >= 0
    input.environment.autonomy_level <= 4
}

decision := {
    "decision": "deny",
    "reasons": ["invalid_or_incomplete_policy_input"],
    "required_roles": [],
    "policy_version": policy_version,
} if {
    not valid_input
} else := {
    "decision": "deny",
    "reasons": ["destructive_risk_class_denied"],
    "required_roles": [],
    "policy_version": policy_version,
} if {
    input.action.risk >= 5
} else := {
    "decision": "allow",
    "reasons": ["read_only_capability"],
    "required_roles": [],
    "policy_version": policy_version,
} if {
    input.action.write == false
} else := {
    "decision": "require_approval",
    "reasons": ["protected_asset_role"],
    "required_roles": ["platform_approver"],
    "policy_version": policy_version,
} if {
    count(input.target.protected_roles) > 0
} else := {
    "decision": "require_approval",
    "reasons": ["critical_risk_action"],
    "required_roles": ["platform_approver"],
    "policy_version": policy_version,
} if {
    input.action.risk >= 4
} else := {
    "decision": "require_approval",
    "reasons": ["high_risk_action"],
    "required_roles": ["security_approver"],
    "policy_version": policy_version,
} if {
    input.action.risk >= 3
} else := {
    "decision": "require_approval",
    "reasons": ["autonomy_level_requires_human"],
    "required_roles": ["operator_approver"],
    "policy_version": policy_version,
} if {
    input.environment.autonomy_level <= 2
} else := {
    "decision": "require_approval",
    "reasons": ["insufficient_incident_confidence"],
    "required_roles": ["security_approver"],
    "policy_version": policy_version,
} if {
    input.incident.confidence < 0.90
} else := {
    "decision": "allow",
    "reasons": ["low_risk_guarded_autonomy"],
    "required_roles": [],
    "policy_version": policy_version,
} if {
    input.action.risk <= 2
    input.environment.autonomy_level >= 3
    input.incident.confidence >= 0.90
} else := {
    "decision": "deny",
    "reasons": ["no_policy_rule_authorized_action"],
    "required_roles": [],
    "policy_version": policy_version,
}
