import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

pii_query if {
  q := lower(sprintf("%v", [input.arguments.query]))
  regex.match(".*(patient|ssn|dob|date of birth|social security).*", q)
}

allow := {"allowed": false, "action": "deny", "reason": "Clinical/medical MCP queries with PII terms are blocked", "matched_rule": "deny_clinical_pii_queries"} if {
  input.action_type == "mcp_tool"
  regex.match("(?i).*(pubmed|clinical|trial).*", input.mcp_server_name)
  pii_query
} else := {"allowed": false, "action": "needs_approval", "reason": "Clinical agents require approval for non-admin users", "matched_rule": "approve_clinical_agents"} if {
  input.action_type == "agent"
  regex.match("(?i).*(clinical|patient|medical).*", input.agent_name)
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Clinical skills require approval for non-admin users", "matched_rule": "approve_clinical_skills_non_admin"} if {
  input.action_type == "skill"
  regex.match("(?i).*(clinical|patient|medical).*", input.skill_name)
  non_admin
}
