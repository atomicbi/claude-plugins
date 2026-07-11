---
name: gatekeeper
description: Security and packaging audit before commit, push, or publish. Use when the gatekeeper hook blocks a command, before publishing a package, or when the user asks to check for leaked secrets or audit package contents.
---

# Gatekeeper

Deep audit companion to the gatekeeper hook. The hook (`scripts/gatekeeper.ts`) runs fast deterministic checks automatically on `git commit` and `npm/pnpm publish` (delegating to gitleaks when installed). This skill is the thorough version: run it when the hook blocks something, before a release, or on request.

## Audit 1 — Secret Leaks (git)

### Check tracked files

```bash
git ls-files | grep -E '(^|/)\.env(\..+)?$|\.(pem|p12|pfx)$|(^|/)\.npmrc$|id_rsa|id_ed25519|credentials.*\.json|service-account.*\.json'
```

Anything matching (except `.example`/`.sample`/`.template` variants) should not be in git:

1. `git rm --cached <file>` (keeps the local copy)
2. Add the pattern to `.gitignore`
3. Commit the removal

### Check content of outgoing changes

Scan staged changes (and, before a push, commits ahead of upstream) for high-confidence secret patterns:

- Private key blocks: `-----BEGIN ... PRIVATE KEY-----`
- AWS access keys: `AKIA[0-9A-Z]{16}`
- GitHub tokens: `ghp_`, `gho_`, `ghs_`, `github_pat_`
- Slack tokens: `xox[baprs]-`
- Anthropic / OpenAI / Stripe / Google API keys: `sk-ant-`, `sk-proj-`, `sk_live_`, `AIza`
- JWTs: `eyJ...eyJ...` three-part tokens
- Connection strings with inline credentials: `protocol://user:password@host`

Also look for generic assignments like `API_KEY = "..."`, `password: '...'` with real-looking values (long, high-entropy). Placeholders (`<your-key>`, `xxx`, `${VAR}`, `example`) are fine.

### If a real secret already got committed

1. **Rotate the credential first** — treat it as compromised. Removing it from git does not un-leak it.
2. If not yet pushed: `git reset` / amend / rebase to drop it from history.
3. If already pushed: history rewriting (`git filter-repo`) plus rotation; warn the user this affects collaborators.
4. Check history for other occurrences: `git log -S '<secret-fragment>' --oneline`

### .gitignore hygiene

Make sure `.gitignore` covers at minimum: `.env`, `.env.*`, `*.pem`, `*.key`, `.npmrc` (if it contains auth tokens), credential JSON files.

## Audit 2 — Published Package Contents

For each publishable package (in a monorepo, iterate every non-private `package.json`):

```bash
npm pack --dry-run --json | jq -r '.[0].files[].path'
```

The tarball should contain **only build-relevant files**: build output (`dist/`, `lib/`, `build/`), `package.json`, `README.md`, `LICENSE`, and type declarations. Flag anything else, especially:

| Category | Examples |
|----------|----------|
| Source & config | `src/`, `tsconfig*.json`, `*.tsbuildinfo`, bundler/test configs (`vite.config.*`, `vitest.config.*`, `jest.config.*`, `.eslintrc*`, `.prettierrc*`) |
| Docs & meta | `docs/`, `examples/`, `CLAUDE.md`, `.claude/`, `.mcp.json`, `.github/`, `.vscode/` |
| Tests | `test/`, `__tests__/`, `*.test.*`, `*.spec.*`, `coverage/` |
| Secrets | `.env*`, `*.pem`, `*.key`, `.npmrc`, credential JSON files |
| Junk | `.DS_Store`, editor swap files |

**Note:** `npm publish` ignores `.gitignore` — a file excluded from git can still be published. The `files` whitelist (or `.npmignore`) controls the tarball.

### Fix: prefer a `files` whitelist

```json
{
  "files": ["dist"]
}
```

A whitelist is safer than `.npmignore` (a blocklist silently includes anything you forgot to list). `package.json`, `README`, and `LICENSE` are always included automatically.

Exceptions: some packages intentionally ship `src/` for source maps or direct TS consumption — confirm with the user before flagging that as a problem.

### Also scan the tarball contents for secrets

Run the secret patterns from Audit 1 over every file that would be published.

## Reporting

Summarize as:

```
GATEKEEPER AUDIT
- Git secrets: ✓ clean (or: 2 findings, see below)
- Sensitive tracked files: ✓ none
- Package contents (my-pkg@1.2.0): ✗ 5 non-build files → recommend files: ["dist"]
- Tarball secret scan: ✓ clean
```

Fix what the user confirms, then re-run the blocked command. For a single false-positive line, append a `gitleaks:allow` comment to it (works for both the hook's built-in rules and real gitleaks). If a whole command is a confirmed false positive, re-run it prefixed with `GATEKEEPER_SKIP=1` — only with explicit user confirmation, never on your own judgment.
