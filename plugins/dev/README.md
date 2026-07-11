# dev

Developer workflow skills for Claude Code.

## Skills

| Skill | Type | Description |
|-------|------|-------------|
| `wrapup` | User-invoked | Session/feature wrap-up workflow — clean, validate, security gate, commit, version, push |
| `gatekeeper` | Auto/user-invoked | Security & packaging audit — secret-leak scan and published-package content check |

## Hooks

The plugin ships a **gatekeeper hook** (`hooks/hooks.json` → `scripts/gatekeeper.ts`) that runs automatically before every `git commit` and `npm`/`pnpm publish` executed through Claude Code:

- **Commit**: blocks if the files being committed contain high-confidence secrets (private keys, AWS/GitHub/GitLab/Slack/Anthropic/OpenAI/Stripe/Google/npm/SendGrid tokens, GCP service accounts, JWTs) or if sensitive files (`.env*`, `*.pem`, SSH keys, credential JSON, `.npmrc`) are tracked in git. This covers staged files *and* files that the command itself is about to stage (`git commit -a`, chained `git add … && git commit`). If [gitleaks](https://github.com/gitleaks/gitleaks) is installed, the staged-content scan is delegated to it (180+ maintained rules, entropy scoring); the built-in rules are the zero-dependency fallback.
- **Publish**: blocks if `npm pack --dry-run` shows non-build files in the tarball (`src/`, `docs/`, tests, `tsconfig*`, `*.tsbuildinfo`, `.mcp.json`, `.env*`, `CLAUDE.md`, editor/CI folders, …) or secrets in files about to be published (npm does not honor `.gitignore`).

When blocked, Claude is pointed at the `gatekeeper` skill for remediation. False positives: append a `gitleaks:allow` comment to a flagged line, or (with explicit user confirmation) bypass a whole command by prefixing it with `GATEKEEPER_SKIP=1`. Matched secret values are never echoed into the transcript — findings report file, line, and rule id only.

Requirements & behavior notes:
- **Node >= 22.18** on PATH — the hook is native TypeScript run via Node's type stripping. If Node is missing or too old the hook fails **open** (Claude Code treats hook errors as non-blocking).
- Blocks are emitted on both channels: a PreToolUse JSON deny *and* exit code 2 + stderr, so the gate still fires when Bash is broadly allowlisted (anthropics/claude-code#18312).
- The hook entries use the `if` field (Claude Code v2.1.85+) so the script is only spawned for matching commands. On older versions the `if` field is ignored and the script runs on every Bash call — it self-filters and exits instantly for non-matching commands.

## Installation

```
/plugin install dev@atomicbi
```
