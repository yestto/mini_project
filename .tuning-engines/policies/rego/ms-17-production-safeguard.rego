# METADATA
# title: MS-17 Production Safeguard Pack
# description: Blocks viewers from prod endpoints, gates non-admin tool use, blocks dangerous MCP, gates ops/admin agents.
# custom:
#   enforcement_mode: enforce
#   enabled: true
#   scope: all_actions

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

allow := {"allowed": false, "action": "deny", "reason": "Viewers are blocked from production endpoints", "matched_rule": "deny_viewer_prod_endpoints"} if {
  input.action_type == "endpoint_request"
  input.user_role == "viewer"
} else := {"allowed": false, "action": "needs_approval", "reason": "Non-admin production tool use requires approval", "matched_rule": "approve_nonadmin_prod_tools"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "Dangerous production MCP tools are blocked", "matched_rule": "deny_prod_dangerous_mcp"} if {
  input.action_type == "mcp_tool"
  input.tool_name in {"exec", "shell", "rm", "sudo"}
} else := {"allowed": false, "action": "needs_approval", "reason": "Ops/admin agents and skills require approval", "matched_rule": "approve_ops_admin_runtime"} if {
  input.action_type in {"agent", "skill"}
  regex.match("(?i).*(ops|admin|override|prod).*", sprintf("%v", [input.resource_name]))
}
