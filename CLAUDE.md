# claude-plugins

Atomic BI's Claude Code plugin marketplace. Plugins live under `plugins/<name>/`, each with `.claude-plugin/plugin.json`, `skills/`, and optionally `hooks/` + `scripts/`. The marketplace manifest is `.claude-plugin/marketplace.json`.

## Structure

```
.claude-plugin/marketplace.json   # marketplace manifest (plugin list)
plugins/dev/                      # "dev" plugin
  .claude-plugin/plugin.json      # name, description, version (bump to ship updates)
  skills/wrapup/                  # session wrap-up workflow
  skills/gatekeeper/              # security & packaging audit (companion to the hook)
  hooks/hooks.json                # PreToolUse gate on git commit / npm|pnpm publish
  scripts/gatekeeper.ts           # the hook implementation (native TS, run by node)
tests/                            # node --test suites (repo-only, not shipped)
docs/                             # deep-dives (see below)
```

## Commands

- `pnpm check` — typecheck (TS7 native tsc) + oxlint + tests; run before committing
- `pnpm test` — gatekeeper end-to-end tests (`node --test`, throwaway git repos)
- `pnpm lint` / `pnpm lint:fix` — oxlint
- `claude plugin validate .` — schema-validate marketplace + plugins

## Toolchain notes

- **TypeScript 7 only** (native Go compiler). Hook scripts run as native TS via Node's type stripping — requires Node >= 22.18 and *erasable syntax only* (no enums/namespaces/parameter properties; `erasableSyntaxOnly` in tsconfig enforces this). Do not add a JS-line TypeScript 5/6 dependency.
- **oxlint, not eslint** — typescript-eslint needs the TS JS compiler API, which typescript@7 doesn't ship. Style convention (not enforced): no semicolons, single quotes, 2-space indent.
- VSCode uses the "TypeScript 7" extension (`TypeScriptTeam.native-preview`); workspace settings in `.vscode/settings.json` pin it to the repo's typescript package.

## Plugin development

See [docs/plugin-development.md](docs/plugin-development.md) for the full workflow. The short version:

- **Live-tree development** ("pnpm link" equivalent): `claude --plugin-dir /path/to/claude-plugins/plugins/dev` — from any project. Skills hot-reload on edit; after changing hooks run `/reload-plugins`.
- **Ship an update**: bump the plugin's `plugin.json` version, commit, push. Teammates get it via `/plugin marketplace update atomicbi` (or auto-update if enabled).
- The gatekeeper hook's design decisions are documented in [docs/gatekeeper.md](docs/gatekeeper.md).

## Wrapup Config

- check: `pnpm check`
- test: included in check
- push: yes
- version_bump: yes (per-plugin `plugin.json` of changed plugins; infer type, confirm with user)
- publish: no (distribution is git push; teammates update via `/plugin marketplace update`)
- docs: docs/ folder, CLAUDE.md as index
- frontend_smoke: no
- co_authored_by: no (global)
