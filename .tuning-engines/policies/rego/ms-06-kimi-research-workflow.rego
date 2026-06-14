# METADATA
# title: MS-06 Kimi Research Workflow Approval
# description: Gates Kimi model tool traffic, large schema bundles, PubMed convert-ids, and clinical skills.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "needs_approval", "reason": "Kimi tool-enabled endpoint traffic requires approval", "matched_rule": "approve_kimi_endpoint_tools"} if {
  input.action_type == "endpoint_request"
  input.model == "kimi-k2.5"
  input.tools_present == true
} else := {"allowed": false, "action": "needs_approval", "reason": "Large tool schema bundles require approval", "matched_rule": "approve_large_tool_schema_bundle"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.tool_schema_count > 8
} else := {"allowed": false, "action": "needs_approval", "reason": "PubMed convert-ids requires approval", "matched_rule": "approve_pubmed_convert_ids"} if {
  input.action_type == "mcp_tool"
  input.mcp_server_name == "PubMed MCP"
  input.tool_name == "pubmed_convert_ids"
} else := {"allowed": false, "action": "needs_approval", "reason": "Clinical skills require approval", "matched_rule": "approve_clinical_skills"} if {
  input.action_type == "skill"
  regex.match("(?i).*(clinical|trial|medical).*", input.skill_name)
}
