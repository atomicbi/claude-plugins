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

**Exception — `.npmrc`:** a committable `.npmrc` is fine and common. Registry, `node-linker`/`hoist`/`shamefully-hoist`, `save-exact`, `@scope:registry`, and `${ENV_VAR}` token references carry no secret — the token lives in the environment, not the file. Only a **literal** credential value is a leak:

```bash
grep -nE '^(//[^:]*:)?(_authToken|_auth|_password|_secret)\s*=\s*[^$[:space:]]' .npmrc
```

If that matches, replace the literal with an env reference (`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`) — don't just delete the file. The hook applies exactly this content check, so a settings-only `.npmrc` passes automatically.

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

## Allowlist — `.claude/gatekeeper.json`

For exceptions that inline `gitleaks:allow` can't express (a whole fixtures tree, an intentionally tracked config, a package that ships `src/`), add a **narrow, reviewable** entry to `.claude/gatekeeper.json` — committed to the repo, so the diff is the audit trail. Prefer inline `gitleaks:allow` for a single secret line; reach for this only when a per-line escape doesn't fit.

```json
{
  "allow": [
    { "path": "config/.npmrc", "sensitiveFile": true, "reason": "registry + linker only, no creds" },
    { "path": "tests/fixtures/**", "rule": "*", "reason": "fake keys in fixtures" },
    { "path": "packages/sdk/src/**", "pack": true, "reason": "ships TS sources for consumers" }
  ]
}
```

Every entry needs a `path` glob (`*` and `?` stay within a path segment; `**` spans separators) **and** a non-empty `reason` — an entry missing either grants nothing (fail closed). What it allows depends on the field present:

| Field | Effect |
|-------|--------|
| `sensitiveFile: true` | let `path` be tracked in git despite matching a sensitive-file pattern |
| `rule: "<id>"` / `["a","b"]` / `"*"` | suppress that secret rule (or all rules) for files matching `path` |
| `pack: true` | let `path` ship in a publish tarball despite the non-build check |

**Safety model:** the file is committed, so any added exception shows up in review — that is the primary guard against a bad actor slipping one in. There is no blanket "disable" switch; entries can only widen one narrow, named thing. When an entry suppresses a finding the hook reports it to the user (it never suppresses silently). Because it's committed, keep it minimal and always fill in a real `reason`.

Note: `rule` suppression covers both the built-in fallback scanner and (by rule id / `"*"`) gitleaks findings, but gitleaks' own `.gitleaksignore` and inline `gitleaks:allow` remain the finer-grained tools it applies itself.

## Reporting

Summarize as:

```
GATEKEEPER AUDIT
- Git secrets: ✓ clean (or: 2 findings, see below)
- Sensitive tracked files: ✓ none
- Package contents (my-pkg@1.2.0): ✗ 5 non-build files → recommend files: ["dist"]
- Tarball secret scan: ✓ clean
```

Fix what the user confirms, then re-run the blocked command. Escape hatches, narrowest first:

1. **Inline** `gitleaks:allow` — one flagged line (built-in rules and real gitleaks).
2. **`.claude/gatekeeper.json`** — a committed, reviewable allowlist entry for a file/path-level exception (see above).
3. **`GATEKEEPER_SKIP=1 <command>`** — whole-command bypass, only with explicit user confirmation, never on your own judgment.
