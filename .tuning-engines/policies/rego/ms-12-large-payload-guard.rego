# METADATA
# title: MS-12 Large Payload And Long Tail Guard
# description: Gates large token requests, large schemas, large MCP queries; blocks oversized tool outputs.
# custom:
#   enforcement_mode: enforce
#   enabled: true
#   scope: all_actions

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "needs_approval", "reason": "Very large endpoint token requests require approval", "matched_rule": "approve_large_endpoint_tokens"} if {
  input.action_type == "endpoint_request"
  input.requested_max_tokens > 32000
} else := {"allowed": false, "action": "needs_approval", "reason": "Large tool schema payloads require approval", "matched_rule": "approve_large_tool_schema_bytes"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.tool_schema_bytes > 20000
} else := {"allowed": false, "action": "needs_approval", "reason": "Large MCP query payloads require approval", "matched_rule": "approve_large_mcp_query"} if {
  input.action_type == "mcp_tool"
  count(sprintf("%v", [input.arguments])) > 400
} else := {"allowed": false, "action": "deny", "reason": "Very large tool outputs are blocked", "matched_rule": "deny_large_tool_output"} if {
  input.action_type == "tool_output"
  count(sprintf("%v", [input.tool_output])) > 2000
}
