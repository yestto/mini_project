# METADATA
# title: MS-19 Member Everything But Plain Chat Needs Review
# description: Gates all member tool-enabled traffic and runtime invocations; blocks unknown schemas.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

member if {
  input.user_role == "member"
}

allow := {"allowed": false, "action": "needs_approval", "reason": "Member tool-enabled endpoint traffic requires approval", "matched_rule": "approve_member_tool_endpoint"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  member
} else := {"allowed": false, "action": "deny", "reason": "Member unknown tool schemas are blocked", "matched_rule": "deny_member_unknown_schema"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "unknown_client_tool_schema"
  member
} else := {"allowed": false, "action": "needs_approval", "reason": "Member MCP, agent, and skill usage requires approval", "matched_rule": "approve_member_runtime"} if {
  input.action_type in {"mcp_tool", "agent", "skill"}
  member
}
