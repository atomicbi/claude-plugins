---
name: gatekeeper
description: Security and packaging audit before commit, push, or publish. Use when the gatekeeper hook blocks a command, before publishing a package, or when the user asks to check for leaked secrets or audit package contents.
model: sonnet
effort: medium
---

# Gatekeeper

Deep audit companion to the gatekeeper hook. `scripts/gatekeeper.ts` owns *detection*; this skill owns *judgment and remediation* — deciding what a finding means, fixing it, and handling the cases the script can't see.

## 1. Run the audit

```bash
gatekeeper --audit
```

(The dev plugin's `bin/` is on PATH automatically. If the command isn't found — live-tree development, or an older install — run `node <this skill's base dir>/../../scripts/gatekeeper.ts --audit`.)

One command, one compact report. It runs the same checks as the hook, across the whole workspace: sensitive files tracked in git, secrets in outgoing changes (staged, unstaged, and untracked), and `npm pack` contents plus a secret scan of every non-private package. It always exits 0 — it reports, it never gates.

Do not re-run these checks by hand. Hand-rolled `git ls-files | grep`, per-package `npm pack` loops, and pattern greps pull the entire scan through the conversation to reproduce a result the script already has.

## 2. Interpret and fix

**Sensitive file tracked in git** → `git rm --cached <file>` (keeps the local copy), add the pattern to `.gitignore`, commit the removal. Check `.gitignore` covers at least `.env`, `.env.*`, `*.pem`, `*.key`, credential JSON.

**`.npmrc` with a literal credential** → replace the value with an env reference (`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`); don't delete the file. A settings-only `.npmrc` (registry, `node-linker`/`hoist`, `save-exact`, `@scope:registry`, `${ENV_VAR}` refs) is fine and passes automatically.

**Non-build files in a tarball** → prefer a `files` whitelist in `package.json` (`{"files": ["dist"]}`) over `.npmignore`; a blocklist silently includes anything you forgot. `package.json`, `README`, and `LICENSE` are always included. Some packages intentionally ship `src/` for source maps or direct TS consumption — confirm with the user before treating that as a problem. Note that `npm publish` ignores `.gitignore`, so a file excluded from git can still be published.

**Possible secret** → judge it. Placeholders (`<your-key>`, `xxx`, `${VAR}`, `example`) are noise. A real-looking value is not:

1. **Rotate the credential first** — treat it as compromised. Removing it from git does not un-leak it.
2. Not yet pushed: `git reset` / amend / rebase to drop it from history.
3. Already pushed: `git filter-repo` plus rotation — warn the user this affects collaborators.
4. Check for other occurrences: `git log -S '<secret-fragment>' --oneline`

## 3. Checks the script does not do

Worth a look before a release, and the reason this skill isn't just the script:

- **Commits ahead of upstream.** The audit scans working-tree state, not the push range: `git diff origin/<branch>..HEAD` before a first push of a long branch.
- **Entry points resolve.** A tarball can be junk-free and still miss `dist/` if the build didn't run — check `main`/`exports` targets exist in the pack listing.
- **History.** If anything looks like it leaked earlier, `git log -S` over the fragment, not just the current tree.

## 4. Report

```
GATEKEEPER AUDIT
- Git secrets: ✓ clean (or: 2 findings, see below)
- Sensitive tracked files: ✓ none
- Package contents (my-pkg@1.2.0): ✗ 5 non-build files → recommend files: ["dist"]
- Tarball secret scan: ✓ clean
```

Fix what the user confirms, then re-run the blocked command. Escape hatches, narrowest first:

1. **Inline `gitleaks:allow`** on the flagged line — works with both the built-in rules and real gitleaks.
2. **`.claude/gatekeeper.json`** — a committed, reviewable allowlist entry for what a per-line escape can't express. Schema and safety rules: [reference/allowlist.md](reference/allowlist.md).
3. **`GATEKEEPER_SKIP=1 <command>`** — whole-command bypass, only with explicit user confirmation, never on your own judgment.
