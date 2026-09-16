# Atomic BI Developer Skills

Developer workflow skills by [Atomic BI](https://github.com/atomicbi), distributed for both Claude Code and Codex.

## Plugins

| Plugin | Description | Claude Code | Codex |
|--------|-------------|-------------|-------|
| [dev](./plugins/dev) | Developer workflow skills — wrapup, gatekeeper (secret-leak & package hygiene), and more | `/plugin install dev@atomicbi` | `codex plugin add dev@atomicbi` |

## Setup

Add this marketplace to Claude Code:

```
claude plugin marketplace add atomicbi/claude-plugins
```

Then install any plugin:

```
claude plugin install dev@atomicbi
```

Plugins auto-update when the marketplace is refreshed.

## Codex setup

Codex discovers the repo-local marketplace at `.agents/plugins/marketplace.json`. Clone this repository, then register its root as a marketplace and install the plugin:

```bash
git clone https://github.com/atomicbi/claude-plugins.git
cd claude-plugins
codex plugin marketplace add .
codex plugin add dev@atomicbi
```

Start a new Codex thread after installing or updating the plugin so its skills are loaded. The `gatekeeper` skill is available in both clients; its automatic pre-command hook is Claude Code-only, so use the skill or `gatekeeper --audit` explicitly in Codex when the executable is available.

## Contributing

Add new skills to an existing plugin under `plugins/<name>/skills/`, keep their frontmatter portable (`name` and `description`), and update both `.claude-plugin/` and `.codex-plugin/` metadata when creating a plugin.
