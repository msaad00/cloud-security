# Agent Integrations

This repo is a good fit for coding agents because each skill is already packaged
as a compact contract: `SKILL.md`, implementation code, tests, and infrastructure.
This document explains how to use that structure with Claude-oriented tooling,
Codex CLI, and generic AGENTS.md-aware agents.

## What Exists Today

- Root-level [AGENTS.md](../AGENTS.md) for repo-wide instructions
- Skill-level `SKILL.md` files that explain when a skill should be used
- JSON, console, and SARIF outputs that are easy for agents and CI systems to consume
- A native local MCP server under [`mcp-server/`](../mcp-server/README.md)
- Project-scoped MCP config in [`.mcp.json`](../.mcp.json) for Claude Code and similar clients

## What Does Not Exist Yet

- Hosted HTTP/SSE transport for remote MCP deployments
- Tight per-skill input schemas derived from each CLI instead of the current conservative `input` + `args` wrapper
- A direct MCP wrapper for the serverless remediation workflow

Document those gaps clearly. Describe the current implementation as a **thin local MCP wrapper** over the existing skills, not a separate execution model.

## Claude / Anthropic Usage

- Use the root `AGENTS.md` as the repo-level instruction file.
- Use each `SKILL.md` as the task-specific contract for the nearest skill directory.
- Treat the benchmark scripts as read-only assessment tools and the IAM departures
  automation as a controlled remediation workflow.

Example prompts:

- "Audit the AWS CIS skill and verify its checks against the official AWS docs."
- "Update the IAM departures docs to prefer Secrets Manager and preserve EventBridge as the trigger path."
- "Add regression tests for pagination in the AWS CIS benchmark skill."

## Codex CLI Usage

- Codex reads `AGENTS.md`, so keep repo-level commands and safety rules there.
- When working inside a skill, read that skill's `SKILL.md` before editing code.
- Use focused test commands for the touched skill instead of generic repo-wide commands when possible.

## Recommended MCP Setup

This repo now ships a project-scoped MCP config:

```json
{
  "mcpServers": {
    "cloud-security": {
      "command": "python3",
      "args": ["mcp-server/src/server.py"]
    }
  }
}
```

That config keeps the wrapper local to the repo and exposes only fixed repo-owned skills. Pair it with filesystem and Git/GitHub MCP servers in your client config if you also want repo editing and PR workflows.

## Recommended Next Step

If you want stronger Claude/Codex/Cortex integration, the next implementation steps are:

1. tighten tool input schemas beyond the current generic `input` + `args` shape
2. add hosted HTTP/SSE transport alongside stdio
3. wrap write-capable flows with explicit dry-run, approval boundaries, and audit outputs

## References

- AGENTS.md open format: https://agents.md/
- Anthropic skills guide: https://platform.claude.com/docs/en/build-with-claude/skills-guide?curius=1426
- Anthropic MCP docs: https://docs.anthropic.com/en/docs/mcp
- Anthropic Claude Code MCP docs: https://docs.anthropic.com/en/docs/claude-code/mcp
