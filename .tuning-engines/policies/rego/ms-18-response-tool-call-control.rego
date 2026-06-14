# METADATA
# title: MS-18 Response Tool Call Control
# description: Blocks unregistered model tool calls, gates registered research tool calls, blocks secret-like tool outputs.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "deny", "reason": "Unknown model-emitted tool calls are blocked", "matched_rule": "deny_unknown_model_tool_call"} if {
  input.action_type == "response_tool_call"
  input.registered_resource != true
} else := {"allowed": false, "action": "needs_approval", "reason": "Registered research tool calls emitted by the model require approval", "matched_rule": "approve_registered_model_tool_call"} if {
  input.action_type == "response_tool_call"
  input.registered_resource == true
  regex.match("(?i).*(pubmed|hn_|forecast|weather).*", input.tool_name)
} else := {"allowed": false, "action": "deny", "reason": "Secret-like tool outputs are blocked", "matched_rule": "deny_secret_tool_results"} if {
  input.action_type == "tool_output"
  regex.match(".*(api[_-]?key|secret|token|password).*", lower(sprintf("%v", [input.tool_output])))
}
