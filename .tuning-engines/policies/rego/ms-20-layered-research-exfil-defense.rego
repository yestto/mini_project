# METADATA
# title: MS-20 Layered Research And Exfiltration Defense
# description: Blocks unknown schemas, dangerous MCP, and secret outputs; gates research tool schemas, agents, and skills for non-admin.
# custom:
#   enforcement_mode: enforce
#   enabled: true

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

non_admin if {
  input.user_role != "admin"
  input.user_role != "owner"
}

allow := {"allowed": false, "action": "deny", "reason": "Unknown client tool schemas are blocked", "matched_rule": "deny_unknown_schema_layered"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.governance_subject_type == "unknown_client_tool_schema"
} else := {"allowed": false, "action": "needs_approval", "reason": "Registered research tool schemas require approval", "matched_rule": "approve_registered_research_schema"} if {
  input.action_type == "chat_tool"
  input.phase == "request_tool"
  input.registered_resource == true
  regex.match("(?i).*(pubmed|clinical|hn_|forecast|weather).*", input.tool_name)
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "Dangerous MCP tools are blocked", "matched_rule": "deny_dangerous_mcp_layered"} if {
  input.action_type == "mcp_tool"
  input.tool_name in {"exec", "shell", "rm", "sudo", "drop_table"}
} else := {"allowed": false, "action": "needs_approval", "reason": "Research agents and skills require approval", "matched_rule": "approve_research_agent_skill_layered"} if {
  input.action_type in {"agent", "skill"}
  regex.match("(?i).*(search|signal|clinical|trial|weather).*", sprintf("%v", [input.resource_name]))
  non_admin
} else := {"allowed": false, "action": "deny", "reason": "Secret-like tool outputs are blocked", "matched_rule": "deny_secret_output_layered"} if {
  input.action_type == "tool_output"
  regex.match(".*(api[_-]?key|secret|token|password).*", lower(sprintf("%v", [input.tool_output])))
}
