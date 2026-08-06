# Gatekeeper — Design Notes

Deep-dive for `plugins/dev/scripts/gatekeeper.ts` and `plugins/dev/hooks/hooks.json`. For user-facing behavior see the [plugin README](../plugins/dev/README.md); for the remediation workflow see the [gatekeeper skill](../plugins/dev/skills/gatekeeper/SKILL.md).

## What it gates

A PreToolUse hook on the Bash tool. Claude Code pipes the pending tool call (JSON: `tool_input.command`, `cwd`) to the script on stdin **before** the command runs. Gated commands:

- `git commit` — secrets in files being committed; sensitive files tracked in git
- `npm publish` / `pnpm publish` — non-build files or secrets in the tarball (`npm pack --dry-run --json --ignore-scripts`)

`hooks.json` uses the `if` field (Claude Code ≥ 2.1.85) with both bare and wildcard patterns per command (`Bash(git commit)` + `Bash(git commit *)` — a bare pattern only matches the exact argless command, and `if` doesn't support pipe alternation, hence six entries). The script re-checks the command itself as a fallback for older Claude Code versions where `if` is ignored.

## Command classification — parse, don't grep

What a command *is* comes from parsing it as shell, never from matching the command string. `parseSegments()` splits the command the way sh would: quoted strings, `$(…)`/backtick substitutions and heredoc bodies stay inside the token they belong to, so they can neither end a segment nor become a command name. A segment is then classified by position — leading `VAR=value` assignments, wrappers (`sudo`, `env`, …) and shell keywords (`if`, `do`, …) are skipped, flags that take a separate value (`git -C dir`, `pnpm --filter pkg`) are stepped over, and the first positional is the subcommand.

This replaced substring regexes (`/\b(npm|pnpm)\b[^;&|]*\spublish\b/` and friends) that ran against the *whole* command, heredoc included — and whose negated character class spanned newlines. Three real defects, all fixed by parsing:

- **Over-firing.** A commit whose message said "npm repository" on one line and "at publish time" a few lines down was classified as a publish, and `npm pack` then flagged the private root package. Rewording or an allowlist entry are both wrong answers: a `pack: true` glob broad enough to silence it would mask real leaks in the publishable packages.
- **Fail-open bypass.** `GATEKEEPER_SKIP=1` was checked with `command.includes()`, so a commit message merely *mentioning* it disarmed the gate entirely. It must now appear as an actual leading assignment.
- **Re-executed substitutions.** Staging prediction built a `sh -c "git add … ${args}"` string from the command text, which would evaluate a `$(…)` the user's command had only quoted. Parsed args go straight to `git` with no shell.

Under-firing is the other half: a real publish behind a subshell, a keyword, or `npm run publish` is still gated (the classification tests in `tests/gatekeeper.test.ts` pin both directions). Unparseable input degrades toward the old behavior in the safe direction — an unterminated quote swallows the rest of the command rather than inventing a command name.

## Audit mode — `gatekeeper --audit`

The same detection, run on demand instead of on a command: sensitive tracked files, secrets in outgoing changes (staged, unstaged *and* untracked), and `npm pack` contents plus a tarball secret scan for **every non-private package in the workspace**. Prints one compact report and always exits 0 — it reports, it never gates.

`plugins/dev/bin/gatekeeper` is a shim that runs it; Claude Code puts every plugin's `bin/` on PATH (verified: the entry is added even when the directory doesn't exist), so skills can call `gatekeeper --audit` without resolving a plugin path.

This exists for token economy, and the numbers came from the local transcripts. Across 32 recorded `dev:gatekeeper` runs the skills re-derived these checks by hand — 187 Bash calls, ~30k tokens of output, the largest bucket being per-package `npm pack` listings (11.3k tokens across 32 calls). All of it landed in the main conversation, where it is re-sent on every subsequent turn. One `--audit` call returns ~6 lines. The skills now call it and are forbidden from hand-rolling the equivalent greps.

Auditing the whole workspace also closes the `pnpm -r publish` blind spot noted under Known limitations: the hook packs only the directory the publish runs from, but the audit walks every tracked non-private `package.json`.

## Design decisions

- **Fail open.** Missing node, unreadable payload, pack failure, non-git dir → exit 0. A hook that can error closed trains people to disable it. Blocking is reserved for actual findings.
- **Block on two channels.** JSON `permissionDecision: deny` on stdout *and* exit code 2 with findings on stderr. The exit-2 path survives the known issue where JSON denies are ignored when Bash is broadly allowlisted (anthropics/claude-code#18312).
- **Never echo matched values.** Findings report file, line, and rule id only — printing the match would leak the secret into the transcript and the API. (A popular community hook gets this wrong.)
- **Predict staging.** Because the hook runs pre-command, `git diff --cached` alone misses `git commit -a` and chained `git add … && git commit`. The script stages nothing itself: `-a`/`--all` → scan modified tracked files; `git add` segments → `git add --dry-run --ignore-missing` with the same (parsed, unexpanded) args to learn what *would* be staged.
- **Delegate to gitleaks when installed** (`gitleaks git --pre-commit --staged --redact`), 180+ maintained rules and entropy scoring for free; our ~15 prefix-anchored rules are the zero-dependency fallback. Filename checks (tracked `.env` etc.) always run locally — gitleaks won't flag an empty tracked `.env`.
- **Tight rules over broad rules.** No generic `KEY=value` or entropy detection in the fallback — gitleaks needs a ~2,000-word stoplist to make that usable; grep-grade tooling can't. A noisy gate gets bypassed.
- **Skip false-positive-heavy files** in content scans: lockfiles, `*.min.js`, sourcemaps, binaries (NUL sniff in first 4KB) — the main sources of JWT-shaped noise.
- **Publish blocklist omits what npm hard-excludes** (`.git`, `.npmrc`, `node_modules`, lockfiles can never be packed) and uses `--ignore-scripts` so `prepare` output can't corrupt the pack JSON (npm/cli#7354). npm does **not** honor `.gitignore`, which is why the tarball secret scan exists.
- **Fail open, but never fail silent.** Failing open is only safe if the narrowing is visible, so anything the scan could not cover is collected and reported: the audit appends `(N not scanned — …)` to its `scope:` line, and the hook emits a `systemMessage` on the allow path. The two cases that motivated this both looked exactly like a clean result:
  - **A dirty submodule crashed the whole run.** `git diff --name-only HEAD` reports a modified submodule as a single path, and that path is a *directory* — `existsSync` says true and `readFileSync` throws `EISDIR`. Unguarded, that aborted the process: the audit printed no report at all, and the commit hook exited 1, which Claude Code treats as a non-blocking error, so the gate silently did not run on any repo with an out-of-sync submodule. The scan now guards on `statSync().isFile()` (not "exists") and wraps each file in its own try/catch, so one unreadable path degrades the report instead of killing it. Skipping a submodule is *correct* — its contents belong to another repository, which gets its own gatekeeper run when committed there — but it is recorded, not assumed. Staged gitlinks are detected the same way (mode `160000` in `git ls-files --stage`), because `git show :<gitlink>` returns nothing and would otherwise count as a scanned file.
  - **An npm major changed the pack JSON shape.** `npm pack --json` emits an array of pack results on npm ≤ 11 and an object keyed by package name on npm ≥ 12. Reading only the array shape yielded an empty file list — indistinguishable from a clean package, so the entire publish gate went blind with no error. The parser now targets the npm 12 shape only and checks `npm --version` first (see Runtime requirements); a real tarball always contains at least `package.json`, so an empty list is likewise reported as unscanned rather than passed.

  The reporting channel is a `not scanned:` section in the audit, emitted *after* every check has run — an earlier version appended the note to the `scope:` line, which is composed before the package pass, so a skip recorded while packing would never have appeared.
- **`.npmrc` is content-gated, not filename-gated.** A committable `.npmrc` (registry, `node-linker`/`hoist`, `@scope:registry`, and `${ENV}` token references) is the common, recommended case — the token lives in the environment, not the file. Only a *literal* value assigned to an auth key (`_authToken`/`_auth`/`_password`/`_secret`) is flagged. `${ENV}` and `$ENV` values are treated as references, not secrets. This replaces the old blanket "any tracked `.npmrc` is sensitive" rule, which was a frequent false positive.

## Allowlist — `.claude/gatekeeper.json`

A committed, review-visible allowlist for exceptions that inline `gitleaks:allow` can't express. Kept under `.claude/` (not the repo root) to avoid another root-level dotfile. Loaded from both the git top-level and the current dir (publish runs from the package dir), after the `GATEKEEPER_SKIP` check.

Each entry is `{ path, reason, … }`. **Both `path` (a glob) and a non-empty `reason` are mandatory — a malformed entry grants nothing (fail closed).** The allowed action is inferred from the field present: `sensitiveFile: true` (track a sensitive file), `rule` (a secret-rule id, list, or `"*"` — suppress for the path), `pack: true` (ship a non-build file). Globs: `*`/`?` stay within a segment, `**` spans separators; no brace/bracket expansion (patterns are meant to be narrow).

**Globs resolve against the directory holding that config's `.claude/`**, so a config is written in the paths you would see sitting next to it — repo-relative at the top level, package-relative inside a package — and an entry can never match outside its own root. That last property is what makes loading two configs safe. It was also a bug for one release: `npm pack` reports package-relative paths and `checkPackage` passed them straight to the pack check, so the documented repo-relative form (`packages/sdk/src/**`) matched nothing in a workspace, while the secret check one line below was already re-basing to repo-relative. Carrying the root on each loaded entry is what keeps every check honest about which base a path is in.

Trust model (the user's explicit concern was a bad actor planting exceptions):

- **Committed ⇒ reviewable.** Every entry lands in a diff — the same trust model as inline `gitleaks:allow`. That review is the primary guard.
- **No blanket disable.** The schema can only widen one narrow, named thing (a path + one action). There is no "off" switch and no way to allow-all-rules-everywhere without enumerating a path.
- **Reason required, suppression surfaced.** Empty/missing reason ⇒ ignored. When an entry suppresses a finding the hook still emits a `systemMessage` naming what was suppressed and why — a suppression is never silent.
- `rule` suppression also filters gitleaks findings by rule id / `"*"`; gitleaks' own `.gitleaksignore` and inline `gitleaks:allow` remain its finer-grained tools.
- A user-local (outside-repo) allowlist was considered for PR-proofing but not built: it wouldn't be shared with the team or work in CI, and the committed-and-reviewed model already bounds the blast radius. It's the documented upgrade path if per-machine exceptions are ever needed.

## Escape hatches (in order of preference)

1. `// gitleaks:allow` comment on a flagged line — per-line, ecosystem-standard, compatible with real gitleaks.
2. `.claude/gatekeeper.json` allowlist entry — committed and reviewable, for file/path-level exceptions inline allow can't express (see above).
3. `GATEKEEPER_SKIP=1 <command>` — whole-command bypass, recognized only as a leading environment assignment (or after `env`/`sudo`), not as text anywhere in the command. The deny text instructs Claude to use it only with explicit user confirmation. Known limitation: Claude could type it unprompted; a transcript-verified human-only bypass (à la sensitive-canary) is the designed upgrade path if that becomes a problem.

## Known limitations

- `pnpm -r publish` at a workspace root packs the root package, not each workspace package, so the *hook* check is weak there (and `publishConfig.directory` isn't resolved). `gatekeeper --audit` does iterate every non-private package, so a pre-publish audit covers what the hook can't.
- Push is not gated (team decision: commit gating suffices).
- No entry-point existence check yet (tarball could be junk-free but missing `dist/` if the build didn't run).

## Runtime requirements

Native TypeScript via Node type stripping: **Node ≥ 22.18**, erasable syntax only (`erasableSyntaxOnly` enforced by the repo tsconfig). On older Node the hook errors → non-blocking → **silent fail-open**; acceptable for our team (everyone is on Node 24), documented in the plugin README.

**npm ≥ 12** for the tarball check. Only the npm 12 `--json` shape is parsed; npm ≤ 11 support was dropped deliberately rather than kept as a compatibility branch, because the internal path is to upgrade. Unlike the Node floor this one is *detected*: `npm --version` is read before packing and an older npm is reported as an error, so it can't degrade into a silent pass. npm being absent entirely is not an error — there is nothing to publish-check.

## Testing

`pnpm test` → `tests/gatekeeper.test.ts` (41 cases: staged/predicted-staging/tracked-file/inline-allow/lockfile-skip/bypass/publish matrix, command classification in both directions, `--audit` mode across a workspace, `.npmrc` content-awareness, the `.claude/gatekeeper.json` allowlist — sensitiveFile/rule/pack, fail-closed on a malformed entry, and three root-scoping cases asserting a repo-root entry reaches one workspace package from both the audit and a publish run inside it while a sibling stays blocked — four submodule cases asserting the audit still prints a report, still finds secrets elsewhere, and names the gitlink as unscanned, and two npm-floor cases driven by a stub `npm` first on `PATH`). Assertions target decisions, not finding text, so they pass with or without gitleaks installed.

The classification cases work by fixture, not by inspecting internals: the repo they run in has no `files` whitelist, so a command misread as a publish denies with a packaging finding while a correctly-read commit stays clean.
