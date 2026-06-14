# METADATA
# title: MS-13 Data Export Governance Pack
# description: Blocks embeddings and export/delete skills for non-admin; gates export MCP tools and reporting agents.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

allow := {"allowed": false, "action": "deny", "reason": "Embeddings are blocked for non-admin export workflows", "matched_rule": "deny_embeddings_non_admin"} if {
  input.action_type == "endpoint_request"
  input.endpoint == "/v1/embeddings"
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Export-like MCP tools require approval", "matched_rule": "approve_export_mcp"} if {
  input.action_type == "mcp_tool"
  regex.match("(?i).*(export|download|dump|extract).*", input.tool_name)
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "Export/delete skills are blocked for non-admin users", "matched_rule": "deny_export_delete_skill"} if {
  input.action_type == "skill"
  regex.match("(?i).*(export|delete|archive).*", input.skill_name)
  non_admin
} else := {"allowed": false, "action": "needs_approval", "reason": "Reporting/export agents require approval", "matched_rule": "approve_reporting_agent"} if {
  input.action_type == "agent"
  regex.match("(?i).*(report|export|analytics).*", input.agent_name)
  non_admin
}
