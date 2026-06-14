# METADATA
# title: MS-03 Untrusted Device Zero-Trust Gate
# description: Blocks runtime invocations, gates tool-enabled endpoints, and blocks provider search on untrusted devices.
# custom:
#   mode: enforce

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

untrusted if {
  input.device_trusted != true
}

allow := {"allowed": false, "action": "deny", "reason": "Untrusted devices cannot use MCP tools, agents, or skills", "matched_rule": "deny_untrusted_runtime"} if {
  input.action_type in {"mcp_tool", "agent", "skill"}
  untrusted
} else := {"allowed": false, "action": "needs_approval", "reason": "Tool-enabled endpoint calls from untrusted devices require approval", "matched_rule": "approve_untrusted_endpoint_tools"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  untrusted
} else := {"allowed": false, "action": "deny", "reason": "Provider-hosted search tools are blocked on untrusted devices", "matched_rule": "deny_untrusted_provider_search"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.provider_tool_type == "web_search"
  untrusted
}
