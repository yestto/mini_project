import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

off_corp if {
  input.network_zone != "corp"
}

allow := {"allowed": false, "action": "needs_approval", "reason": "Tool-enabled endpoint calls outside corp require approval", "matched_rule": "approve_offcorp_endpoint_tools"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  off_corp
} else := {"allowed": false, "action": "deny", "reason": "Provider-hosted tools are blocked outside corp", "matched_rule": "deny_offcorp_provider_tools"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "provider_hosted_tool"
  off_corp
} else := {"allowed": false, "action": "needs_approval", "reason": "Agent invocations outside corp require approval", "matched_rule": "approve_offcorp_agents"} if {
  input.action_type == "agent"
  off_corp
} else := {"allowed": false, "action": "deny", "reason": "Dangerous MCP tools are blocked outside corp", "matched_rule": "deny_offcorp_dangerous_mcp"} if {
  input.action_type == "mcp_tool"
  input.tool_name in {"exec", "shell", "rm", "sudo"}
  off_corp
}
