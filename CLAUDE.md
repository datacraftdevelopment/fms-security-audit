@AGENTS.md

## Claude Code notes

- Skills in `.claude/skills/` load automatically. Start with fms-audit when someone asks what to do.
- Never use the `!` shell prefix for `audit.login`: its output lands in this conversation. Ask the consultant to run it in a separate terminal window.
