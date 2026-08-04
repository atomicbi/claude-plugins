# Changelog reconciliation

Read this only when `changelog:` is configured and not `no`. Runs **before** the version bump so the reconciled entries can drive the bump decision.

**Reconcile first — never trust session memory.** The wrapup session may only cover part of what shipped since the last release. Ground the entry in what actually happened:

```bash
git describe --tags --abbrev=0          # last release tag
git log <last-tag>..HEAD --oneline      # everything since — not just this session
gh pr list --state merged --search "merged:>..." # if the repo uses PRs
```

Then update the changelog in the configured format:

- **`CHANGELOG.md` (keep-a-changelog)**: bring `## [Unreleased]` in line with the reconciled history — add missing entries under `Added` / `Changed` / `Fixed` / `Removed` / `Security`, drop entries that never merged. Once the version is chosen, promote `[Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and insert a fresh empty `[Unreleased]` above it.
- **Custom format**: follow the prose in the config (file, entry shape, sync commands to run and when). Same discipline: reconcile against git/PR history first, stamp the version once it's picked.

Keep entries short and user-facing — what changed for consumers, not which files moved.

**Classify each entry** (breaking / feature / improvement / fix) — the version bump reads the classification: any breaking entry → **major**; any feature/improvement → **minor**; only fixes → **patch**.
