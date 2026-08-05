---
name: wrapup
description: Session/feature wrap-up workflow. Use when finishing work, wrapping up a session, preparing to commit, or the user says "wrap up", "wrapup", "let's ship it", or "we're done".
---

# Wrapup

Structured wrap-up for coding sessions. Cleans up, validates, documents, commits, and optionally versions/publishes — guided by per-project config stored in CLAUDE.md.

## Process

```
/wrapup invoked
    │
    ├── Config found in CLAUDE.md?
    │   ├── No  → Run INIT FLOW (below)
    │   └── Yes → Load config
    │
    ├── 1. CLEAN UP changed files
    ├── 2. VALIDATE (lint, typecheck, tests)
    ├── 3. QUALITY CHECK (roam, advisory)
    ├── 4. SECURITY GATE (secrets + package contents)
    ├── 5. UPDATE DOCS (if architectural changes)
    ├── 6. COMMIT (meaningful message)
    ├── 7. CHANGELOG (if configured — reconcile before bumping)
    ├── 8. VERSION BUMP (if configured)
    ├── 9. PUBLISH / PUSH (if configured)
    └── 10. SUMMARY
```

## Init Flow

If the project's CLAUDE.md has no `## Wrapup Config` section, follow [reference/init-flow.md](reference/init-flow.md) first — auto-detect, confirm with the user, write the config — then continue with the workflow below in the same invocation. If the config already exists, skip that file entirely; everything below reads from the config.

## Step-by-Step Workflow

### 1. Clean Up

Scope: files changed in this session (use `git diff --name-only` against the base).

- Remove `console.log`, `debugger`, `console.debug` statements added during development
- Remove commented-out code blocks that were part of debugging
- Remove unused imports in changed files
- If you spot pre-existing issues in changed files, fix them too (but don't deep-scan the whole repo)
- Do NOT remove `console.log` calls that are part of a logging system or intentional

### 2. Validate

Run the configured check/test commands:

```
1. Run the `check` command (lint + typecheck). Fix any errors.
2. If `test` is configured and not "skip": run tests. Fix failures.
3. If frontend_smoke is configured: follow the project's smoke test instructions.
   If frontend_smoke is "not configured" and the project has frontend code:
   first time only, recommend the user set up smoke tests, then move on.
```

If validation fails, fix issues and re-run. Do not proceed to commit with failing checks.

### 3. Quality Check (advisory)

Use `roam-code` MCP if available:
- Run a quality/health check scoped to changed files
- Report findings as a summary — do NOT block on minor issues
- If a critical flaw is found (security vulnerability, data loss risk), pause and ask the user
- If quality metrics are available, include a brief comparison (e.g. "health: 64% → 68%")

If roam-code is not available, leave a subtle suggestion to install it. If the user confirms, follow https://github.com/Cranot/roam-code/blob/main/skills/roam/SKILL.md

### 4. Security Gate

One command — it covers sensitive files tracked in git, secrets in outgoing changes, and `npm pack` contents plus a secret scan for every publishable package in the workspace:

```bash
gatekeeper --audit
```

Findings here are **blocking** — fix them (or get explicit user sign-off on false positives) before proceeding to commit. If a real secret was already committed, tell the user to rotate it; removing it from git does not un-leak it.

No `GATEKEEPER AUDIT` header in the output means the gate did not run — say so and resolve it; do not proceed as if it passed. A `not scanned:` section lists what the audit could not cover: submodule gitlinks are expected (they get their own run in their own repo), but an unreadable path or an `npm … is too old` line means a check was skipped — surface it rather than reading past it.

Do not hand-roll these checks (`git ls-files | grep`, per-package `npm pack` loops, pattern greps) — the script already does them, and reproducing it by hand pulls the whole scan through the conversation. Load the `gatekeeper` skill only when a finding actually needs remediation or judgment; a clean report needs nothing further.

### 5. Update Docs

Based on the configured `docs` strategy:

- **Single CLAUDE.md**: Update if architectural patterns, commands, or project structure changed
- **docs/ folder**: Update relevant docs if the changes affect documented architecture. Add new docs for significant new patterns. Keep CLAUDE.md as an index/overview.
- **Monorepo per-package docs/**: Update the specific package's docs. Keep root CLAUDE.md inventory current.

Only update docs for meaningful architectural or behavioral changes. Bug fixes and minor tweaks don't need doc updates. When in doubt, skip — don't create noise.

### 6. Commit

- Stage all relevant files (including the user's changes if working alongside them)
- Write a descriptive commit message: what changed and why, not just file names
- Use conventional commit style if the project already uses it, otherwise write natural language
- If there are logically separate changes, consider splitting into multiple commits
- Include user's parallel changes unless they conflict or have issues

**Co-Authored-By trailer** — controlled by `co_authored_by` in the Wrapup Config: `no` (or `no (global)`) means do NOT append the `Co-Authored-By: Claude ...` trailer; `yes` keeps default behavior. If the key is missing from the config, follow the decision procedure in [reference/init-flow.md](reference/init-flow.md) and persist the answer there so it's asked at most once per project.

### 7. Changelog (if configured)

Skip entirely unless `changelog:` is configured and not `no`. When it is, follow [reference/changelog.md](reference/changelog.md) — it reconciles against real git/PR history (not session memory) and runs before the version bump so its entry classifications can drive the bump.

### 8. Version Bump (if configured)

Only when `version_bump: yes` in config:

- Infer bump type — **from the reconciled changelog when step 7 ran** (any breaking entry → **major**; any feature/improvement → **minor**; only fixes → **patch**), otherwise from the session's changes:
  - Bug fix, patch-level change → **patch**
  - New feature, enhancement → **minor**
  - Breaking change → **major**
- Present the inferred bump to the user for confirmation: "Bump 1.2.3 → 1.3.0 (minor — new feature X)?"
- Prefer tool-driven bumps over hand-editing where one exists (`npm version <part> --no-git-tag-version`, `uv version --bump <part>`) — it keeps lockfiles in sync
- If `aligned`: bump ALL packages to the same version
- Stamp the changelog entry from step 7 with the chosen version, and commit it together with the bump: `chore: bump version to X.Y.Z`
- Tag: `vX.Y.Z`

### 9. Publish / Push (if configured)

**Push** (when `push: yes`):
- `git push` to the current branch's remote

**Publish** (when `publish: yes`):
- Since package registry auth typically requires browser interaction, do NOT run publish automatically
- Instead, tell the user: "Versions bumped and tagged. Run `! pnpm publish -r` to publish."
- If the project has a publish script in package.json, suggest that instead

### 10. Summary

End with a concise wrap-up summary:

```
WRAPUP COMPLETE
- Cleaned: 3 files (removed 2 console.logs, 1 unused import)
- Checks: lint ✓ typecheck ✓ tests ✓
- Security: no secrets ✓ package contents clean ✓
- Quality: roam health 64% → 68% (advisory)
- Docs: updated packages/core/docs/adapters.md
- Committed: "feat: add vercel adapter with stateless sessions"
- Changelog: 1.3.0 entry (2 features, 1 fix) — reconciled against v1.2.3..HEAD
- Version: 1.3.0 (minor) — all packages aligned
- Pushed: yes
- Publish: run `! pnpm publish -r` when ready
```

Adjust to only show relevant lines. If tests were skipped, don't show a test line. Keep it scannable.

## Config Overrides

The user can override config for a single run:
- `/wrapup --no-push` — skip push this time
- `/wrapup --no-version` — skip version bump
- `/wrapup --major` / `--minor` / `--patch` — force bump type

Parse these from the skill args if provided.

## Edge Cases

- **No changes**: If `git status` shows nothing to commit, say so and skip to summary
- **Merge conflicts**: Do not auto-resolve. Alert the user and stop
- **Dirty worktree with unrelated files**: Ask the user which files to include
- **First wrapup in a new project**: Run init flow, then proceed with wrapup in the same invocation
