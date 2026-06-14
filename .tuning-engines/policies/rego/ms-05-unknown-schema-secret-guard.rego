# METADATA
# title: MS-05 Unknown Schema And Secret Output Guard
# description: Blocks unknown tool schemas, unregistered model tool calls, and outputs containing secret-like patterns.
# custom:
#   mode: enforce

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

secretish(text) if {
  regex.match(".*(api[_-]?key|secret|token|password|passwd).*", lower(sprintf("%v", [text])))
}

allow := {"allowed": false, "action": "deny", "reason": "Unknown client tool schemas are blocked", "matched_rule": "deny_unknown_request_tool_schema"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "unknown_client_tool_schema"
} else := {"allowed": false, "action": "deny", "reason": "Unregistered model-emitted tool calls are blocked", "matched_rule": "deny_unknown_response_tool_call"} if {
  input.action_type == "response_tool_call"
  input.registered_resource != true
} else := {"allowed": false, "action": "deny", "reason": "Secret-looking tool output is blocked", "matched_rule": "deny_secret_tool_output"} if {
  input.action_type == "tool_output"
  secretish(input.tool_output)
}
