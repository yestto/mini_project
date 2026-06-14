# METADATA
# title: MS-08 Provider Tool Restriction Composite
# description: Blocks provider web search and computer-use for restricted roles, gates tool-enabled endpoints for members.
# custom:
#   enforcement_mode: enforce
#   enabled: true
#   scope: all_actions

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

restricted_role if {
  input.user_role in {"member", "viewer"}
}

allow := {"allowed": false, "action": "deny", "reason": "Provider web search is blocked for restricted roles", "matched_rule": "deny_provider_web_search"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.provider_tool_type == "web_search"
  restricted_role
} else := {"allowed": false, "action": "deny", "reason": "Provider computer-use tool calls are blocked for restricted roles", "matched_rule": "deny_provider_computer_call"} if {
  input.action_type == "response_tool_call"
  input.provider_tool_type == "computer"
  restricted_role
} else := {"allowed": false, "action": "needs_approval", "reason": "Any provider-hosted tool use on endpoint requests requires approval for members", "matched_rule": "approve_endpoint_with_tools"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  input.user_role == "member"
}
