# Gatekeeper — Design Notes

Deep-dive for `plugins/dev/scripts/gatekeeper.ts` and `plugins/dev/hooks/hooks.json`. For user-facing behavior see the [plugin README](../plugins/dev/README.md); for the remediation workflow see the [gatekeeper skill](../plugins/dev/skills/gatekeeper/SKILL.md).

## What it gates

A PreToolUse hook on the Bash tool. Claude Code pipes the pending tool call (JSON: `tool_input.command`, `cwd`) to the script on stdin **before** the command runs. Gated commands:

- `git commit` — secrets in files being committed; sensitive files tracked in git
- `npm publish` / `pnpm publish` — non-build files or secrets in the tarball (`npm pack --dry-run --json --ignore-scripts`)

`hooks.json` uses the `if` field (Claude Code ≥ 2.1.85) with both bare and wildcard patterns per command (`Bash(git commit)` + `Bash(git commit *)` — a bare pattern only matches the exact argless command, and `if` doesn't support pipe alternation, hence six entries). The script re-checks the command itself as a fallback for older Claude Code versions where `if` is ignored.

## Design decisions

- **Fail open.** Missing node, unreadable payload, pack failure, non-git dir → exit 0. A hook that can error closed trains people to disable it. Blocking is reserved for actual findings.
- **Block on two channels.** JSON `permissionDecision: deny` on stdout *and* exit code 2 with findings on stderr. The exit-2 path survives the known issue where JSON denies are ignored when Bash is broadly allowlisted (anthropics/claude-code#18312).
- **Never echo matched values.** Findings report file, line, and rule id only — printing the match would leak the secret into the transcript and the API. (A popular community hook gets this wrong.)
- **Predict staging.** Because the hook runs pre-command, `git diff --cached` alone misses `git commit -a` and chained `git add … && git commit`. The script stages nothing itself: `-a`/`--all` → scan modified tracked files; `git add` segments → `git add --dry-run --ignore-missing` with the same args to learn what *would* be staged.
- **Delegate to gitleaks when installed** (`gitleaks git --pre-commit --staged --redact`), 180+ maintained rules and entropy scoring for free; our ~15 prefix-anchored rules are the zero-dependency fallback. Filename checks (tracked `.env` etc.) always run locally — gitleaks won't flag an empty tracked `.env`.
- **Tight rules over broad rules.** No generic `KEY=value` or entropy detection in the fallback — gitleaks needs a ~2,000-word stoplist to make that usable; grep-grade tooling can't. A noisy gate gets bypassed.
- **Skip false-positive-heavy files** in content scans: lockfiles, `*.min.js`, sourcemaps, binaries (NUL sniff in first 4KB) — the main sources of JWT-shaped noise.
- **Publish blocklist omits what npm hard-excludes** (`.git`, `.npmrc`, `node_modules`, lockfiles can never be packed) and uses `--ignore-scripts` so `prepare` output can't corrupt the pack JSON (npm/cli#7354). npm does **not** honor `.gitignore`, which is why the tarball secret scan exists.
- **`.npmrc` is content-gated, not filename-gated.** A committable `.npmrc` (registry, `node-linker`/`hoist`, `@scope:registry`, and `${ENV}` token references) is the common, recommended case — the token lives in the environment, not the file. Only a *literal* value assigned to an auth key (`_authToken`/`_auth`/`_password`/`_secret`) is flagged. `${ENV}` and `$ENV` values are treated as references, not secrets. This replaces the old blanket "any tracked `.npmrc` is sensitive" rule, which was a frequent false positive.

## Allowlist — `.claude/gatekeeper.json`

A committed, review-visible allowlist for exceptions that inline `gitleaks:allow` can't express. Kept under `.claude/` (not the repo root) to avoid another root-level dotfile. Loaded from both the git top-level and the current dir (publish runs from the package dir), after the `GATEKEEPER_SKIP` check.

Each entry is `{ path, reason, … }`. **Both `path` (a glob) and a non-empty `reason` are mandatory — a malformed entry grants nothing (fail closed).** The allowed action is inferred from the field present: `sensitiveFile: true` (track a sensitive file), `rule` (a secret-rule id, list, or `"*"` — suppress for the path), `pack: true` (ship a non-build file). Globs: `*`/`?` stay within a segment, `**` spans separators; no brace/bracket expansion (patterns are meant to be narrow).

Trust model (the user's explicit concern was a bad actor planting exceptions):

- **Committed ⇒ reviewable.** Every entry lands in a diff — the same trust model as inline `gitleaks:allow`. That review is the primary guard.
- **No blanket disable.** The schema can only widen one narrow, named thing (a path + one action). There is no "off" switch and no way to allow-all-rules-everywhere without enumerating a path.
- **Reason required, suppression surfaced.** Empty/missing reason ⇒ ignored. When an entry suppresses a finding the hook still emits a `systemMessage` naming what was suppressed and why — a suppression is never silent.
- `rule` suppression also filters gitleaks findings by rule id / `"*"`; gitleaks' own `.gitleaksignore` and inline `gitleaks:allow` remain its finer-grained tools.
- A user-local (outside-repo) allowlist was considered for PR-proofing but not built: it wouldn't be shared with the team or work in CI, and the committed-and-reviewed model already bounds the blast radius. It's the documented upgrade path if per-machine exceptions are ever needed.

## Escape hatches (in order of preference)

1. `// gitleaks:allow` comment on a flagged line — per-line, ecosystem-standard, compatible with real gitleaks.
2. `.claude/gatekeeper.json` allowlist entry — committed and reviewable, for file/path-level exceptions inline allow can't express (see above).
3. `GATEKEEPER_SKIP=1 <command>` — whole-command bypass; the deny text instructs Claude to use it only with explicit user confirmation. Known limitation: Claude could type it unprompted; a transcript-verified human-only bypass (à la sensitive-canary) is the designed upgrade path if that becomes a problem.

## Known limitations

- `pnpm -r publish` at a workspace root packs the root package, not each workspace package — the check is meaningless there (and `publishConfig.directory` isn't resolved). Monorepo publishes should rely on per-package `files` whitelists; a `-r`-aware iteration is future work.
- Push is not gated (team decision: commit gating suffices).
- No entry-point existence check yet (tarball could be junk-free but missing `dist/` if the build didn't run).

## Runtime requirements

Native TypeScript via Node type stripping: **Node ≥ 22.18**, erasable syntax only (`erasableSyntaxOnly` enforced by the repo tsconfig). On older Node the hook errors → non-blocking → **silent fail-open**; acceptable for our team (everyone is on Node 24), documented in the plugin README.

## Testing

`pnpm test` → `tests/gatekeeper.test.ts` (20 cases: staged/predicted-staging/tracked-file/inline-allow/lockfile-skip/bypass/publish matrix, plus `.npmrc` content-awareness and the `.claude/gatekeeper.json` allowlist — sensitiveFile/rule/pack and fail-closed on a malformed entry). Assertions target decisions, not finding text, so they pass with or without gitleaks installed.
