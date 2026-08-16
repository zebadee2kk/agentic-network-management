package anm.action

import rego.v1

# Baseline v1 policy. Production deployments are expected to layer site-specific
# policy on top of this baseline, not bypass it.
#
# Input contract is documented in docs/architecture/LLD.md.

valid_input if {
    is_number(input.action.risk)
    is_array(input.target.protected_roles)
    is_number(input.incident.confidence)
    is_number(input.environment.autonomy_level)
}

decision := {
    "decision": "deny",
    "reasons": ["invalid_or_incomplete_policy_input"],
    "required_roles": [],
} if {
    not valid_input
} else := {
    "decision": "deny",
    "reasons": ["destructive_risk_class_denied"],
    "required_roles": [],
} if {
    input.action.risk >= 5
} else := {
    "decision": "require_approval",
    "reasons": ["protected_asset_role"],
    "required_roles": ["platform_approver"],
} if {
    count(input.target.protected_roles) > 0
} else := {
    "decision": "require_approval",
    "reasons": ["high_risk_action"],
    "required_roles": ["security_approver"],
} if {
    input.action.risk >= 3
} else := {
    "decision": "require_approval",
    "reasons": ["autonomy_level_requires_human"],
    "required_roles": ["operator_approver"],
} if {
    input.environment.autonomy_level <= 2
} else := {
    "decision": "require_approval",
    "reasons": ["insufficient_incident_confidence"],
    "required_roles": ["security_approver"],
} if {
    input.incident.confidence < 0.90
} else := {
    "decision": "allow",
    "reasons": ["low_risk_guarded_autonomy"],
    "required_roles": [],
} if {
    input.action.risk <= 2
    input.environment.autonomy_level >= 3
    input.incident.confidence >= 0.90
} else := {
    "decision": "deny",
    "reasons": ["no_policy_rule_authorized_action"],
    "required_roles": [],
}
