# Skill Token Economy

How the dev plugin's skills are kept cheap, and how to re-measure when they drift. Written after a usage review attributed 16% of a day's usage to `/dev:gatekeeper` and 7% to `/dev:wrapup`.

## The cost model

A skill costs tokens in three places, and only the first is obvious:

1. **Its body**, injected once per invocation.
2. **The work it prescribes** — every tool result it causes lands in the conversation.
3. **Re-sending.** Both of the above sit in context for the rest of the session. In a session already past 150k, a token spent early is paid again on every subsequent request. This is what makes a chatty procedure far more expensive than a long file.

So: a big SKILL.md is a one-time cost, but a procedure that says "grep the repo and read the results" is a recurring one.

## What the measurement showed

From the local transcripts in `~/.claude/projects/**/*.jsonl` (see method below), across 32 `dev:gatekeeper` runs:

| | tokens | calls |
|---|---|---|
| `npm pack` / tarball listings | 11.3k | 32 |
| misc | 7.7k | 58 |
| `git diff`/`status`/`log` | 5.3k | 31 |
| `git ls-files` tracked-file scan | 2.7k | 32 |
| running `gatekeeper.ts` directly | 2.0k | 7 |
| secret greps | 1.0k | 25 |

The 7.2k-byte SKILL.md (≈1.8k tokens × 32 = ~58k) was *not* the problem. The problem was 187 Bash calls re-deriving, by hand and in main context, what `gatekeeper.ts` already computes deterministically.

Trigger mix mattered too: **21 of 32 invocations happened inside a wrapup** (13 chained via the Skill tool, 8 after a typed `/dev:wrapup`); only 1 followed an actual hook block. Optimizing the skill in isolation would have missed that the dominant caller was another skill.

## The three levers, in order of payoff

1. **Move detection into code.** Anything deterministic belongs in a script that returns a verdict, not in prose that tells the model to look. `gatekeeper --audit` replaced a multi-turn procedure with one call and ~6 lines of output. Skills that call it are explicitly told not to hand-roll the equivalent.
2. **Progressive disclosure.** Material needed rarely — a once-per-project init flow, an allowlist schema, a changelog format that most repos don't configure — moves to `reference/*.md` under the skill and is linked, not inlined. `wrapup` went 12.3k → 8.2k bytes, `gatekeeper` 7.2k → 4.2k, with nothing removed.
3. **Frontmatter.** `model:` and `effort:` (see below).

A fourth lever, `context: fork`, was considered and rejected: a fork pays its own system prompt, and the same usage review flagged subagent-heavy sessions separately. Shrinking the work beats relocating it.

## Verified harness behavior

Checked against the installed CLI (2.1.221) rather than assumed — worth re-checking after upgrades:

- **Skill frontmatter keys**: `name`, `description`, `model`, `allowed-tools`, `disallowed-tools`, `argument-hint`, `arguments`, `disable-model-invocation`, `user-invocable`, `effort`, `shell`, `version`, `when_to_use`, `paths`, `hooks`, `context`, `agent`. `model` accepts `haiku`/`sonnet`/`opus`/`fable`/a full ID/`inherit`; `effort` accepts `low`/`medium`/`high`/`max`/an integer.
- **`model:` does not switch the conversation.** Verified with a headless probe: a skill declaring `model: haiku` reported usage under `claude-haiku-4-5` while the main loop stayed on opus (and kept its cached context). The overridden skill can still run tools. The identifier `modelOverrideToAdoptAfterTurn` in the binary suggested otherwise, which is why this was tested rather than trusted.
- **`<plugin-root>/bin` is on PATH** for every installed plugin — the entry is added even when the directory doesn't exist. Hence `plugins/dev/bin/gatekeeper`, so a skill can say `gatekeeper --audit` instead of resolving a plugin path. `${CLAUDE_PLUGIN_ROOT}` is *not* exported to Bash tool calls (only hooks get it), so it must not be used in skill bodies.

## Re-measuring

Transcripts are JSONL under `~/.claude/projects/<project>/<session>.jsonl`. To attribute work to a skill, find the `tool_use` block with `name: "Skill"` and the right `input.skill`, then walk forward summing `tool_result` sizes.

The turn boundary is the part that's easy to get wrong. A genuine human turn is a `type: "user"` row with **no** `toolUseResult` and **no** `isMeta` — skill bodies and command expansions arrive as `isMeta` user rows, and tool results as `toolUseResult` rows. Breaking on "any user row" ends the window immediately; breaking on none of them swallows the rest of the session and reports 400-turn "runs".

Even with a correct boundary, attribution overstates: the model keeps working in the same turn after a skill finishes. Treat per-run totals as an upper bound and compare *between* skills rather than against the session.
