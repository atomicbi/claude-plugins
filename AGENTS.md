# Atomic BI coding skills

This repository distributes the same developer workflow skills to Claude Code and Codex. Claude Code metadata lives in `.claude-plugin/`; Codex metadata lives in `.codex-plugin/` and `.agents/plugins/`.

## Development

- Run `pnpm check` before committing changes.
- Keep `plugins/dev/skills/` portable: frontmatter must be limited to `name` and `description`, and instructions must not rely on a Claude-only runtime feature unless a Codex-safe alternative is stated.
- Do not remove or change the Claude hook configuration while adding Codex support. Codex plugins do not use that hook manifest.
- When plugin metadata or skills change, validate both distributions:

  ```bash
  claude plugin validate . --strict
  python3 /Users/atomic/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/dev
  ```
