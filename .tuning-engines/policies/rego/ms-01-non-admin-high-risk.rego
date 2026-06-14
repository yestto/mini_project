# METADATA
# title: MS-01 Non-Admin High-Risk Runtime Gate
# description: Blocks dangerous MCP tools, gates large endpoint calls, search/signal agents, and high-risk skills for non-admin users.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

allow := {"allowed": false, "action": "deny", "reason": "Dangerous MCP tools are blocked for non-admin users", "matched_rule": "deny_dangerous_mcp_non_admin"} if {
  input.action_type == "mcp_tool"
  input.tool_name in {"exec", "shell", "rm", "sudo", "drop_table", "delete_all"}
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Large tool-enabled endpoint calls require admin approval", "matched_rule": "approve_large_endpoint_tool_call"} if {
  input.action_type == "endpoint_request"
  input.endpoint == "/v1/messages"
  input.tools_present == true
  input.requested_max_tokens > 16000
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Search and signal agents require approval for non-admin users", "matched_rule": "approve_search_signal_agents"} if {
  input.action_type == "agent"
  regex.match("(?i).*(search|signal).*", input.agent_name)
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "High-risk skills are blocked for non-admin users", "matched_rule": "deny_high_risk_skills"} if {
  input.action_type == "skill"
  regex.match("(?i).*(export|delete|override|admin).*", input.skill_name)
  non_admin
}
