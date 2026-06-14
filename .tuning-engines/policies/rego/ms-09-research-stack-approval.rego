# METADATA
# title: MS-09 Research Stack Approval And Tooloracle Deny
# description: Gates research tool schemas, MCP calls, and agents; blocks Tooloracle for non-admin.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "needs_approval", "reason": "Research tool schemas require approval", "matched_rule": "approve_research_tool_schemas"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.tool_name in {"pubmed_convert_ids", "hn_get_stories", "nws_get_forecast"}
  input.registered_resource == true
} else := {"allowed": false, "action": "needs_approval", "reason": "Research MCP calls require approval", "matched_rule": "approve_research_mcp_calls"} if {
  input.action_type == "mcp_tool"
  input.mcp_server_name in {"PubMed MCP", "Hacker News MCP", "Us Weather MCP"}
} else := {"allowed": false, "action": "needs_approval", "reason": "Research agents require approval", "matched_rule": "approve_research_agents"} if {
  input.action_type == "agent"
  input.agent_name in {"AgentSearch A2A", "GitDealFlow Signal Agent"}
} else := {"allowed": false, "action": "deny", "reason": "Tooloracle is blocked for non-admin users", "matched_rule": "deny_tooloracle_non_admin"} if {
  input.action_type == "agent"
  input.agent_name == "Tooloracle A2A"
  input.user_role != "admin"
  input.user_role != "owner"
}
