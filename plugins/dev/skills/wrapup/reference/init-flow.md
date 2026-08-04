# Wrapup init flow

Read this only when the project's CLAUDE.md has no `## Wrapup Config` section — it runs once per project, then never again.

## Step 1 — Auto-detect

Scan the project root for:

- **Package manager**: `pnpm-lock.yaml`, `yarn.lock`, `package-lock.json`, `bun.lockb`
- **Scripts**: `package.json` `scripts` for `lint`, `check`, `typecheck`, `test`, `build`
- **Monorepo**: `pnpm-workspace.yaml`, `turbo.json`, `lerna.json`, `packages/`
- **Frontend**: `vite.config.*`, `next.config.*`, `src/App.*`, `src/pages/`
- **Docs structure**: `docs/` folder, per-package `docs/`, or just root CLAUDE.md
- **Changelog**: `CHANGELOG.md` (Keep a Changelog format?) or a custom changelog source (e.g. a data file the website/releases render from)

## Step 2 — Recommend & ask

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
- Changelog on release? [detected CHANGELOG.md / not detected — recommend for
  published or open-source packages]
- Smoke tests for frontend? [not set up — recommend adding]
- Claude Co-Authored-By trailer in commits?
  [disable for this repo (default) / disable globally / keep enabled]
```

Wait for user confirmation before proceeding.

## Step 3 — Write config

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
- co_authored_by: no (or: yes / no (global))
- changelog: no (or: `CHANGELOG.md` (keep-a-changelog) / custom — describe the
  format, file, and any sync commands in prose; wrapup follows the description)
```

Keep this section concise. It is the single source of truth for wrapup behavior.

## The Co-Authored-By decision

Also a once-per-project question — only ask when `co_authored_by` is missing from the config:

1. Check `~/.claude/settings.json` first — if it already contains `"includeCoAuthoredBy": false`, silently record `co_authored_by: no (global)` and move on (don't ask).
2. Otherwise ask the user before committing:
   - **Disable for this repository** (default/recommended) → record `co_authored_by: no`
   - **Disable globally** → set `"includeCoAuthoredBy": false` in `~/.claude/settings.json` (merge into the existing JSON — never overwrite other keys) and record `co_authored_by: no (global)`
   - **Keep enabled** → record `co_authored_by: yes`
3. Persist the answer in `## Wrapup Config` so the question is asked at most once per project.
