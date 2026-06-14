# METADATA
# title: MS-11 Member Research Isolation
# description: Gates all member tool-enabled endpoints, MCP, agent, and skill invocations; blocks unknown schemas.
# custom:
#   mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

member if {
  input.user_role == "member"
}

allow := {"allowed": false, "action": "needs_approval", "reason": "Member tool-enabled endpoint calls require approval", "matched_rule": "approve_member_endpoint_tools"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  member
} else := {"allowed": false, "action": "deny", "reason": "Unknown tool schemas are blocked for members", "matched_rule": "deny_member_unknown_tool_schema"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "unknown_client_tool_schema"
  member
} else := {"allowed": false, "action": "needs_approval", "reason": "All member MCP invocations require approval", "matched_rule": "approve_all_member_mcp"} if {
  input.action_type == "mcp_tool"
  member
} else := {"allowed": false, "action": "needs_approval", "reason": "All member agent and skill invocations require approval", "matched_rule": "approve_all_member_agent_skill"} if {
  input.action_type in {"agent", "skill"}
  member
}
