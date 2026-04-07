# Atomic BI Claude Plugins

A marketplace of Claude Code plugins by [Atomic BI](https://github.com/atomicbi).

## Plugins

| Plugin | Description | Install |
|--------|-------------|---------|
| [dev](./plugins/dev) | Developer workflow skills — wrapup, and more | `/plugin install dev@atomicbi` |

## Setup

Add this marketplace to Claude Code:

```
/plugin marketplace add atomicbi https://github.com/atomicbi/claude-plugins
```

Then install any plugin:

```
/plugin install dev@atomicbi
```

Plugins auto-update when the marketplace is refreshed.

## Contributing

Add new skills to an existing plugin under `plugins/<name>/skills/`, or create a new plugin directory following the structure in `plugins/dev/`.
