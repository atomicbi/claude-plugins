# `.claude/gatekeeper.json` — allowlist reference

Read this only when an exception actually needs writing. For a single flagged line, inline `gitleaks:allow` is the better tool and needs nothing from this file.

The allowlist is committed to the repo, so every entry shows up in review — that is the primary guard against a bad exception slipping in. Keep entries narrow and always fill in a real `reason`.

```json
{
  "allow": [
    { "path": "config/.npmrc", "sensitiveFile": true, "reason": "registry + linker only, no creds" },
    { "path": "tests/fixtures/**", "rule": "*", "reason": "fake keys in fixtures" },
    { "path": "packages/sdk/src/**", "pack": true, "reason": "ships TS sources for consumers" }
  ]
}
```

Every entry needs a `path` glob **and** a non-empty `reason` — an entry missing either grants nothing (fail closed). What it allows depends on the field present:

| Field | Effect |
|-------|--------|
| `sensitiveFile: true` | let `path` be tracked in git despite matching a sensitive-file pattern |
| `rule: "<id>"` / `["a","b"]` / `"*"` | suppress that secret rule (or all rules) for files matching `path` |
| `pack: true` | let `path` ship in a publish tarball despite the non-build check |

Globs: `*` and `?` stay within a path segment, `**` spans separators. No brace or bracket expansion.

**Paths are relative to the directory holding the config's `.claude/`** — the same paths you would see sitting next to the file. In a monorepo, a repo-root config writes `packages/sdk/src/**`; a `packages/sdk/.claude/gatekeeper.json` writes `src/**` and can never match outside `packages/sdk/`.

Two configs are read: the one at the repo root, and the one in the directory the command runs from (they are the same file for a single-package repo). A publish from `packages/sdk` therefore picks up both; `gatekeeper --audit` runs from the repo root, so put workspace-wide exceptions in the root config.

**Safety properties worth preserving when you edit this file:** there is no blanket "disable" switch — entries can only widen one narrow, named thing. When an entry suppresses a finding, the hook still reports it to the user, so a suppression is never silent.

`rule` suppression covers both the built-in fallback scanner and (by rule id / `"*"`) gitleaks findings. gitleaks' own `.gitleaksignore` and inline `gitleaks:allow` remain the finer-grained tools it applies itself.

**Scope a `pack` entry to the package that needs it.** A glob broad enough to silence a noisy audit (`"**/src/**"`) also masks real leaks in every other package — prefer `packages/<name>/src/**`.
