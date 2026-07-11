# Plugin Development Workflow

How to develop, test, and distribute plugins in this marketplace.

## Local development — work off the live working tree

Installed plugins are **copied** into a version-keyed cache (`~/.claude/plugins/cache/atomicbi/<plugin>/<version>/`) — an installed plugin never sees your working-tree edits, and re-installing without a version bump serves the stale cache. The "pnpm link" equivalent is the `--plugin-dir` flag, which loads a plugin directly from a directory with no caching:

```bash
# from this repo or ANY other project:
claude --plugin-dir /path/to/claude-plugins/plugins/dev

# multiple plugins: repeat the flag
claude --plugin-dir …/plugins/dev --plugin-dir …/plugins/other
```

Suggested shell alias so every project can opt into the dev build:

```bash
alias claude-dev='claude --plugin-dir "/path/to/claude-plugins/plugins/dev"'
```

Reload behavior inside a `--plugin-dir` session:

| Component | Applies |
|---|---|
| Skills (`SKILL.md`) | Immediately on edit (hot-reload) |
| Hooks (`hooks.json`, scripts) | After `/reload-plugins` (or new session) |
| MCP/LSP servers | After `/reload-plugins` (or new session) |

Caveat: if the released plugin is *also installed* in the same session, its hooks register alongside the `--plugin-dir` copy and fire twice. Uninstall the released copy (or don't enable it in projects where you develop with `--plugin-dir`).

## Testing

Three layers, fastest first:

1. **Unit/e2e tests for hook scripts** — `pnpm test` runs `tests/gatekeeper.test.ts` via `node --test`: each case builds a throwaway git repo, pipes a real PreToolUse JSON payload into `scripts/gatekeeper.ts`, and asserts on the allow/deny decision and exit code. Add a case here for every new gate behavior.
2. **Schema validation** — `claude plugin validate .` checks marketplace.json, plugin.json, hooks.json, and SKILL.md frontmatter (`--strict` for CI).
3. **Live exercise** — headless one-shot with the working tree:
   ```bash
   claude --plugin-dir plugins/dev -p "commit my changes"
   ```
   Hooks fire normally in `-p` mode, so a blocked `git commit` surfaces as the deny message. Usable in CI.

## Team distribution

One-time setup per teammate:

```
/plugin marketplace add atomicbi/claude-plugins
/plugin install dev@atomicbi
```

Or zero-touch per project — commit this to any project's `.claude/settings.json` and Claude Code prompts everyone who opens the project to install:

```json
{
  "extraKnownMarketplaces": {
    "atomicbi": {
      "source": { "source": "github", "repo": "atomicbi/claude-plugins" }
    }
  },
  "enabledPlugins": {
    "dev@atomicbi": true
  }
}
```

Staying current:

- Auto-update is **off by default** for third-party marketplaces. Teammates can enable it in `/plugin` → Marketplaces → "Enable auto-update" (or `autoUpdate: true` on the marketplace entry in managed settings).
- Manual: `/plugin marketplace update atomicbi`.
- Either way, **updates only ship when the plugin's `plugin.json` version is bumped** — the cache is keyed by version. An unbumped push is invisible to installs.

## Release checklist

1. `pnpm check` (typecheck + lint + tests) — the wrapup skill runs this
2. `claude plugin validate . --strict`
3. Bump `plugins/<name>/.claude-plugin/plugin.json` version (patch/minor/major by change type)
4. Commit + push to `master`
5. Teammates: `/plugin marketplace update atomicbi` (or auto-update)
