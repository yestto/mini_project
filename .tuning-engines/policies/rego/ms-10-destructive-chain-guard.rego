# METADATA
# title: MS-10 Destructive Chain Guard
# description: Blocks dangerous MCP, secret outputs, destructive skills for non-admin, and gates admin agents.
# custom:
#   enforcement_mode: enforce
#   enabled: true
#   scope: all_actions

import rego.v1

default allow := {"allowed": true, "action": "allow", "reason": "Allowed by default"}

allow := {"allowed": false, "action": "deny", "reason": "Dangerous MCP execution is blocked", "matched_rule": "deny_dangerous_mcp_chain"} if {
  input.action_type == "mcp_tool"
  input.tool_name in {"exec", "shell", "rm", "sudo"}
} else := {"allowed": false, "action": "deny", "reason": "Secret-looking tool outputs are blocked", "matched_rule": "deny_secret_outputs_chain"} if {
  input.action_type == "tool_output"
  regex.match(".*(api[_-]?key|secret|token|password).*", lower(sprintf("%v", [input.tool_output])))
} else := {"allowed": false, "action": "deny", "reason": "Destructive skills are blocked for non-admin users", "matched_rule": "deny_destructive_skills_chain"} if {
  input.action_type == "skill"
  input.user_role != "admin"
  input.user_role != "owner"
  regex.match("(?i).*(delete|override|wipe|admin).*", input.skill_name)
} else := {"allowed": false, "action": "needs_approval", "reason": "Administrative agents require approval", "matched_rule": "approve_admin_agents"} if {
  input.action_type == "agent"
  regex.match("(?i).*(admin|override|ops).*", input.agent_name)
}
