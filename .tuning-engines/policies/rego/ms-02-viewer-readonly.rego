import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

viewer if {
  input.user_role == "viewer"
}

allow := {"allowed": false, "action": "deny", "reason": "Viewers cannot access chat or messages endpoints", "matched_rule": "deny_viewer_endpoints"} if {
  input.action_type == "endpoint_request"
  input.endpoint in {"/v1/messages", "/v1/chat/completions"}
  viewer
} else := {"allowed": false, "action": "deny", "reason": "Viewers cannot offer tool schemas", "matched_rule": "deny_viewer_tool_schemas"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  viewer
} else := {"allowed": false, "action": "deny", "reason": "Viewers cannot invoke MCP tools, agents, or skills", "matched_rule": "deny_viewer_runtime_invocations"} if {
  input.action_type in {"mcp_tool", "agent", "skill"}
  viewer
}
