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
    ├── 4. UPDATE DOCS (if architectural changes)
    ├── 5. COMMIT (meaningful message)
    ├── 6. VERSION BUMP (if configured)
    ├── 7. PUBLISH / PUSH (if configured)
    └── 8. SUMMARY
```

## Init Flow

Triggered when no `## Wrapup Config` section exists in the project's CLAUDE.md. Auto-detect what you can, ask the user to confirm.

### Step 1 — Auto-detect

Scan the project root for:
- **Package manager**: look for `pnpm-lock.yaml`, `yarn.lock`, `package-lock.json`, `bun.lockb`
- **Scripts**: read `package.json` `scripts` for `lint`, `check`, `typecheck`, `test`, `build`
- **Monorepo**: look for `pnpm-workspace.yaml`, `turbo.json`, `lerna.json`, `packages/` dir
- **Frontend**: look for `vite.config.*`, `next.config.*`, `src/App.*`, `src/pages/`
- **Docs structure**: check for `docs/` folder, per-package `docs/`, or just root CLAUDE.md

### Step 2 — Recommend & ask

Present findings and recommendations to the user:

```
WRAPUP INIT — detected:
- Package manager: pnpm
- Monorepo: yes (turbo + pnpm workspaces)
- Check command: `pnpm check` (lint + typecheck)
- Test command: `pnpm test` (or: none detected)
- Frontend: no (or: yes — vite/react)
- Docs: monorepo per-package docs/ + root CLAUDE.md

RECOMMENDATIONS:
- Push after commit? [yes/no]
- Version bump on wrapup? [yes/no]
  - If yes: aligned across all packages? [yes/no]
- Publish on wrapup? [yes/no]
  - Note: pnpm publish requires browser auth — wrapup will
    bump + commit + tag, then prompt you to publish manually.
- Smoke tests for frontend? [not set up — recommend adding]
```

Wait for user confirmation before proceeding.

### Step 3 — Write config

Add a `## Wrapup Config` section to the project's CLAUDE.md:

```markdown
## Wrapup Config

- check: `pnpm check`
- test: `pnpm test` (or: skip)
- push: yes
- version_bump: yes (aligned across all packages)
- publish: yes (manual — prompt after tag)
- docs: monorepo (per-package docs/ referenced in root CLAUDE.md)
- frontend_smoke: no (or: follow docs/smoke-tests.md)
```

Keep this section concise. It is the single source of truth for wrapup behavior.

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

If roam-code is not available, skip this step silently.

### 4. Update Docs

Based on the configured `docs` strategy:

- **Single CLAUDE.md**: Update if architectural patterns, commands, or project structure changed
- **docs/ folder**: Update relevant docs if the changes affect documented architecture. Add new docs for significant new patterns. Keep CLAUDE.md as an index/overview.
- **Monorepo per-package docs/**: Update the specific package's docs. Keep root CLAUDE.md inventory current.

Only update docs for meaningful architectural or behavioral changes. Bug fixes and minor tweaks don't need doc updates. When in doubt, skip — don't create noise.

### 5. Commit

- Stage all relevant files (including the user's changes if working alongside them)
- Write a descriptive commit message: what changed and why, not just file names
- Use conventional commit style if the project already uses it, otherwise write natural language
- If there are logically separate changes, consider splitting into multiple commits
- Include user's parallel changes unless they conflict or have issues

### 6. Version Bump (if configured)

Only when `version_bump: yes` in config:

- Infer bump type from changes:
  - Bug fix, patch-level change → **patch**
  - New feature, enhancement → **minor**
  - Breaking change → **major**
- Present the inferred bump to the user for confirmation: "Bump 1.2.3 → 1.3.0 (minor — new feature X)?"
- If `aligned`: bump ALL packages to the same version
- Commit the version bump separately: `chore: bump version to X.Y.Z`
- Tag: `vX.Y.Z`

### 7. Publish / Push (if configured)

**Push** (when `push: yes`):
- `git push` to the current branch's remote

**Publish** (when `publish: yes`):
- Since package registry auth typically requires browser interaction, do NOT run publish automatically
- Instead, tell the user: "Versions bumped and tagged. Run `! pnpm publish -r` to publish."
- If the project has a publish script in package.json, suggest that instead

### 8. Summary

End with a concise wrap-up summary:

```
WRAPUP COMPLETE
- Cleaned: 3 files (removed 2 console.logs, 1 unused import)
- Checks: lint ✓ typecheck ✓ tests ✓
- Quality: roam health 64% → 68% (advisory)
- Docs: updated packages/core/docs/adapters.md
- Committed: "feat: add vercel adapter with stateless sessions"
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
