# METADATA
# title: MS-16 Search Stack Everything Approval
# description: Gates all search-related endpoints, tool schemas, MCP tools, agents, and skills.
# custom:
#   mode: enforce

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "needs_approval", "reason": "Search-related endpoint calls require approval", "matched_rule": "approve_search_endpoint"} if {
  input.action_type == "endpoint_request"
  input.tools_present == true
  input.endpoint in {"/v1/messages", "/v1/chat/completions"}
} else := {"allowed": false, "action": "needs_approval", "reason": "Search-related tool schemas require approval", "matched_rule": "approve_search_tool_schema"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  regex.match("(?i).*(search|pubmed|hn_|forecast|weather).*", input.tool_name)
} else := {"allowed": false, "action": "needs_approval", "reason": "Search-related MCP tools require approval", "matched_rule": "approve_search_mcp"} if {
  input.action_type == "mcp_tool"
  regex.match("(?i).*(pubmed|hacker news|weather).*", input.mcp_server_name)
} else := {"allowed": false, "action": "needs_approval", "reason": "Search-related agents and skills require approval", "matched_rule": "approve_search_agent_skill"} if {
  input.action_type in {"agent", "skill"}
  regex.match("(?i).*(search|signal|clinical|weather).*", sprintf("%v", [input.resource_name]))
}
