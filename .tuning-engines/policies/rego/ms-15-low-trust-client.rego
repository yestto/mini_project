import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

missing_client if {
  sprintf("%v", [input.client_name]) == ""
}

allow := {"allowed": false, "action": "deny", "reason": "Unknown tool schemas from low-trust clients are blocked", "matched_rule": "deny_unknown_lowtrust_client"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "unknown_client_tool_schema"
  missing_client
} else := {"allowed": false, "action": "needs_approval", "reason": "MCP invocations without client identity require approval", "matched_rule": "approve_clientless_mcp"} if {
  input.action_type == "mcp_tool"
  missing_client
} else := {"allowed": false, "action": "needs_approval", "reason": "Agent and skill calls without client identity require approval", "matched_rule": "approve_clientless_agent_skill"} if {
  input.action_type in {"agent", "skill"}
  missing_client
}
