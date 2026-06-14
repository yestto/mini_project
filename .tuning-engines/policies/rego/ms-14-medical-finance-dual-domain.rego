import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

sensitive_term if {
  regex.match(".*(ssn|dob|patient|account number|routing number).*", lower(sprintf("%v", [input.arguments])))
}

allow := {"allowed": false, "action": "needs_approval", "reason": "Medical/finance endpoint tool traffic requires approval", "matched_rule": "approve_medfin_endpoint"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "Medical/finance MCP arguments contain sensitive terms", "matched_rule": "deny_medfin_sensitive_args"} if {
  input.action_type == "mcp_tool"
  sensitive_term
} else := {"allowed": false, "action": "needs_approval", "reason": "Medical/finance agents require approval", "matched_rule": "approve_medfin_agents"} if {
  input.action_type == "agent"
  regex.match("(?i).*(clinical|medical|finance|billing).*", input.agent_name)
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Medical/finance skills require approval", "matched_rule": "approve_medfin_skills"} if {
  input.action_type == "skill"
  regex.match("(?i).*(clinical|medical|finance|billing).*", input.skill_name)
  non_admin
}
