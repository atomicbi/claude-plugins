#!/usr/bin/env node
/**
 * Gatekeeper — PreToolUse hook for the Bash tool (wired up in hooks/hooks.json).
 *
 * Claude Code pipes the pending tool call to this script as JSON on stdin.
 * For `git commit` and `npm|pnpm publish` commands it checks:
 *
 *   commit   → no secrets in the files that will be committed (staged files,
 *              plus files that `git commit -a` or a chained `git add … &&`
 *              would stage), and no sensitive files tracked in git.
 *              Delegates the staged-content scan to gitleaks when installed.
 *   publish  → tarball (npm pack --dry-run) contains only build-relevant
 *              files, and none of them contain secrets.
 *
 * Which of those a command *is* is decided by parsing it as shell (see
 * "Command parsing"), not by matching the command string: text inside a commit
 * message, a heredoc or a substitution is data and never changes the verdict.
 *
 * On findings it blocks both ways: a "deny" decision as JSON on stdout AND
 * exit code 2 with the findings on stderr (the exit-2 path still works when
 * Bash is broadly allowlisted, see anthropics/claude-code#18312).
 *
 * A committable `.npmrc` (registry/linker/hoist settings, `${ENV}` token refs)
 * is allowed; only a literal credential value in it is flagged.
 *
 * False positives, narrowest first:
 *   - a line containing `gitleaks:allow` is never flagged (ecosystem-standard
 *     inline escape, compatible with real gitleaks)
 *   - `.claude/gatekeeper.json` — a committed, review-visible allowlist of
 *     narrow, reason-required exceptions (a secret rule for a path glob, a
 *     packaged non-build file, or a tracked sensitive file). Suppressions are
 *     reported to the user; it cannot express a blanket "disable" and a
 *     malformed entry grants nothing.
 *   - prefixing the command with GATEKEEPER_SKIP=1 bypasses the gate entirely
 *     (requires explicit user confirmation)
 *
 * Anything not gated → silent exit 0 (allow). Runtime errors also fail open.
 *
 * Runs as native TypeScript via Node's type stripping — requires Node >= 22.18
 * (erasable type syntax only: no enums, namespaces, or parameter properties).
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

interface HookPayload {
  tool_input?: { command?: string }
  cwd?: string
}

interface SecretRule {
  id: string
  re: RegExp
}

interface GitleaksLeak {
  RuleID: string
  File: string
  StartLine: number
}

// One allowlist entry from `.claude/gatekeeper.json`. `path` (a glob relative
// to the repo/package root) and a non-empty `reason` are mandatory; an entry
// missing either grants nothing (fail closed). What it allows is inferred from
// which field is present:
//   rule           → suppress that secret rule (id, list, or '*') for the path
//   pack: true     → let the path ship in a publish tarball (non-build check)
//   sensitiveFile  → let the path be tracked in git despite the sensitive-file
//                    pattern (e.g. an intentionally committed config)
interface AllowEntry {
  path: string
  reason: string
  rule?: string | string[]
  pack?: boolean
  sensitiveFile?: boolean
}

// --- Rules -------------------------------------------------------------------

// High-confidence secret tokens, mostly prefix-anchored (adapted from the
// gitleaks default ruleset). Deliberately tight — a noisy gate trains
// people to bypass it. No entropy/generic detection here; that's what the
// gitleaks delegation is for.
const SECRET_RULES: SecretRule[] = [
  { id: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: 'aws-access-key', re: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/ },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
  { id: 'github-pat', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: 'gitlab-pat', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'slack-token', re: /\bxox[baprse]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'slack-webhook', re: /hooks\.slack\.com\/(services|workflows|triggers)\/[A-Za-z0-9+/]{40,}/ },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{5,}T3BlbkFJ[A-Za-z0-9_-]{5,}/ }, // T3BlbkFJ = base64("OpenAI")
  { id: 'stripe-live-key', re: /\bsk_live_[0-9a-zA-Z]{24,}/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'sendgrid-key', re: /\bSG\.[A-Za-z0-9_.=-]{60,}/ },
  { id: 'gcp-service-account', re: /"private_key"\s*:\s*"-----BEGIN/ },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/ }
]

const INLINE_ALLOW = 'gitleaks:allow'

// Files that should never be tracked in git: env files, private keys,
// npm auth config, credential dumps. `.env.example` and friends are fine.
const SENSITIVE_FILE_RE = /(^|\/)\.env(\.[^/]+)?$|(^|\/)(id_rsa|id_ed25519|id_ecdsa)[^/]*$|\.(pem|p12|pfx)$|(^|\/)\.npmrc$|(^|\/)[^/]*(credentials|service-account)[^/]*\.json$/
const SENSITIVE_FILE_EXCEPTIONS = /\.(example|sample|template|dist)$/

// Skipped by the content scan: lockfiles and minified/binary assets are the
// top false-positive sources for JWT- and base64-shaped patterns.
const SCAN_SKIP_RE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|go\.sum|Cargo\.lock|poetry\.lock)$|\.min\.(js|css)$|\.(map|svg|png|jpe?g|gif|ico|woff2?|ttf|eot|pdf|zip|gz)$|(^|\/)(node_modules|vendor)\//

// Files that don't belong in a published package: sources, docs, tests, tool
// configs, editor/CI folders, secrets. No need to list what npm hard-excludes
// anyway (.git, .npmrc, node_modules, lockfiles) — those can never be packed.
const NON_BUILD_RE = /^(src|docs?|test|tests|__tests__|__mocks__|coverage|examples?|scripts|\.github|\.claude|\.vscode|\.idea)\/|^\.env|\.tsbuildinfo$|^\.mcp\.json$|^tsconfig[^/]*\.json$|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)CLAUDE\.md$|\.(pem|p12|pfx|key)$|(^|\/)\.DS_Store$|^\.editorconfig$|^(vitest|jest|eslint|prettier|webpack|rollup|babel)[^/.]*\.(config|rc)[^/]*$/
const NON_BUILD_EXCEPTIONS = /^\.env\.(example|sample|template)$/

// --- Helpers -----------------------------------------------------------------

function git(args: string[]): string {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trimEnd()
  } catch {
    return ''
  }
}

function lines(text: string): string[] {
  return text ? text.split('\n').filter(Boolean) : []
}

function looksBinary(buf: Buffer): boolean {
  return buf.subarray(0, 4096).includes(0)
}

// --- Command parsing -----------------------------------------------------------

// What gets gated is decided from the command's *syntax*, never from a substring
// match over the whole command string. A commit message is data, not shell: a
// message mentioning "npm … publish" (or "git commit", or "GATEKEEPER_SKIP=1")
// must not change what the hook does. So the command is split the way sh would
// split it — quoted strings, `$(…)`/backtick substitutions and heredoc bodies
// stay inside the token they belong to and can neither end a segment nor become
// a command name.

// Word-splitting/segmenting states. 'subst' covers `$(…)` and plain `(…)`
// nesting inside a word; inside it, separators are just characters.
type ParseCtx = 'top' | 'subst' | 'single' | 'double' | 'backtick'

// Consume heredoc bodies (`<<EOF … EOF`) starting at `start`, which must be the
// first index of a line. Returns the index just past the last body.
function skipHeredocBodies(text: string, start: number, pending: string[]): number {
  let i = start
  while (pending.length > 0) {
    const delim = pending.shift() as string
    while (i < text.length) {
      const nl = text.indexOf('\n', i)
      const end = nl < 0 ? text.length : nl
      const line = text.slice(i, end).trim()
      i = nl < 0 ? end : nl + 1
      if (line === delim) break
    }
  }
  return i
}

// Split a shell command into segments (one per simple command) of tokens.
function parseSegments(text: string): string[][] {
  const segments: string[][] = []
  const stack: ParseCtx[] = []
  const heredocs: string[] = []
  let tokens: string[] = []
  let token = ''
  let started = false // tracks an empty-but-present token, e.g. `-m ''`
  let i = 0

  const add = (s: string): void => {
    token += s
    started = true
  }
  const pushToken = (): void => {
    if (started) tokens.push(token)
    token = ''
    started = false
  }
  const endSegment = (): void => {
    pushToken()
    if (tokens.length > 0) segments.push(tokens)
    tokens = []
  }

  // At a `<<` operator: register the delimiter of `<<[-][']word[']` and advance
  // past it. Returns false for anything that isn't a heredoc after all.
  const readHeredocDelimiter = (): boolean => {
    let j = i + 2
    if (text[j] === '-') j++
    while (text[j] === ' ' || text[j] === '\t') j++
    const quote = text[j] === '"' || text[j] === '\'' ? text[j] : ''
    if (quote) j++
    let delim = ''
    while (j < text.length) {
      const c = text[j]
      if (quote ? c === quote : /[\s;&|<>()'"`]/.test(c)) break
      if (c === '\\') {
        j++ // `<<\EOF` — quotes the delimiter, same as `<<'EOF'`
        continue
      }
      delim += c
      j++
    }
    if (!delim) return false
    if (quote && text[j] === quote) j++
    heredocs.push(delim)
    i = j
    return true
  }

  while (i < text.length) {
    const ctx: ParseCtx = stack[stack.length - 1] ?? 'top'
    const c = text[i]

    if (ctx === 'single') {
      if (c === '\'') stack.pop()
      else add(c)
      i++
      continue
    }

    if (ctx === 'double' || ctx === 'backtick') {
      const closer = ctx === 'double' ? '"' : '`'
      if (c === '\\' && i + 1 < text.length) {
        add(text[i + 1])
        i += 2
        continue
      }
      if (c === closer) {
        stack.pop()
        i++
        continue
      }
      // A substitution inside quotes starts a fresh shell context, so its own
      // quoting and heredocs are parsed again from scratch.
      if (c === '$' && text[i + 1] === '(') {
        stack.push('subst')
        add('$(')
        i += 2
        continue
      }
      add(c)
      i++
      continue
    }

    // ctx is 'top' or 'subst'. Inside a substitution everything is part of the
    // surrounding word, so segments and tokens are never broken there.
    const inSubst = ctx === 'subst'

    if (c === '\\' && i + 1 < text.length) {
      if (text[i + 1] === '\n') i += 2 // line continuation
      else {
        add(text[i + 1])
        i += 2
      }
      continue
    }
    if (c === '\'' || c === '"' || c === '`') {
      stack.push(c === '\'' ? 'single' : c === '"' ? 'double' : 'backtick')
      if (inSubst) add(c)
      else started = true // quotes attach to the current word
      i++
      continue
    }
    if (c === '$' && text[i + 1] === '(') {
      stack.push('subst')
      add('$(')
      i += 2
      continue
    }
    if (c === '(') {
      if (inSubst) {
        stack.push('subst')
        add(c)
      } else endSegment()
      i++
      continue
    }
    if (c === ')') {
      if (inSubst) {
        stack.pop()
        add(c)
      } else endSegment()
      i++
      continue
    }
    if (c === '<' && text[i + 1] === '<' && text[i + 2] !== '<' && readHeredocDelimiter()) {
      if (!inSubst) pushToken() // the redirect ends the current word
      continue
    }
    if (c === '\n') {
      i++
      if (heredocs.length > 0) i = skipHeredocBodies(text, i, heredocs)
      if (inSubst) add(' ')
      else endSegment()
      continue
    }
    if (c === ' ' || c === '\t') {
      if (inSubst) add(c)
      else pushToken()
      i++
      continue
    }
    if (c === ';' || c === '&' || c === '|') {
      if (inSubst) {
        add(c)
        i++
        continue
      }
      endSegment()
      i++
      if (text[i] === c) i++ // `&&`, `||`
      continue
    }
    add(c)
    i++
  }
  endSegment()
  return segments
}

// Command wrappers that delegate to the real command in their trailing args,
// plus the shell keywords a real command can hide behind (`if git commit; then`,
// `for f in *; do git commit; done`).
const WRAPPERS = new Set([
  'sudo', 'doas', 'command', 'env', 'nohup', 'nice', 'time', 'stdbuf',
  'if', 'then', 'elif', 'else', 'while', 'until', 'do', '{', '!'
])

const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/

function commandName(token: string): string {
  return (token.split('/').pop() ?? '').toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '')
}

// Drop leading `VAR=value` assignments and wrappers to get at the real argv.
function argv(tokens: string[]): string[] {
  let i = 0
  while (i < tokens.length && (ENV_ASSIGN_RE.test(tokens[i]) || WRAPPERS.has(commandName(tokens[i])))) i++
  return tokens.slice(i)
}

// Flags whose value is a separate token — the value must not be mistaken for a
// subcommand (`git -C dir commit`, `pnpm --filter pkg publish`).
const VALUE_FLAGS = new Set([
  '-c', '-C', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env', // git
  '-w', '--workspace', '-F', '--filter', '--dir', '--prefix', '--registry', '--config', '--loglevel', '--reporter' // npm/pnpm
])

// Positional args of a segment, in order, with flags (and their values) removed.
// The first entry is the subcommand.
function positionals(tokens: string[]): string[] {
  const args = argv(tokens).slice(1)
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const t = args[i]
    if (t.startsWith('-') && t !== '-') {
      if (VALUE_FLAGS.has(t)) i++
      continue
    }
    out.push(t)
  }
  return out
}

function isCommand(tokens: string[], names: string[], sub: string): boolean {
  const args = argv(tokens)
  if (args.length === 0 || !names.includes(commandName(args[0]))) return false
  return positionals(tokens)[0] === sub
}

// Flags passed to a subcommand (everything after it, flags included).
function flagsAfter(tokens: string[], sub: string): string[] {
  const args = argv(tokens).slice(1)
  const at = args.indexOf(sub)
  return at < 0 ? [] : args.slice(at + 1)
}

const findings: string[] = []

// Findings that an allowlist entry suppressed. Surfaced to the user even on an
// allow verdict so a suppression is never silent (the review-visibility of the
// committed `.claude/gatekeeper.json` is the primary safety mechanism; this is
// the secondary one).
const suppressed: string[] = []

// --- Allowlist (`.claude/gatekeeper.json`) -----------------------------------

// Loaded after chdir. Kept in `.claude/` (not the repo root) at the user's
// request; committed and therefore reviewable — the diff is the audit trail.
let allowlist: AllowEntry[] = []

function loadAllowlist(): AllowEntry[] {
  const roots = new Set<string>()
  const top = git(['rev-parse', '--show-toplevel'])
  if (top) roots.add(top)
  roots.add(process.cwd()) // publish runs from the package dir, which may differ
  const entries: AllowEntry[] = []
  for (const root of roots) {
    const file = join(root, '.claude', 'gatekeeper.json')
    if (!existsSync(file)) continue
    try {
      const parsed: { allow?: unknown } = JSON.parse(readFileSync(file, 'utf8'))
      if (!Array.isArray(parsed.allow)) continue
      for (const e of parsed.allow as AllowEntry[]) {
        // A path and a non-empty reason are mandatory. Anything else grants
        // nothing — a malformed entry can only fail closed, never open.
        if (e && typeof e.path === 'string' && typeof e.reason === 'string' && e.reason.trim()) {
          entries.push(e)
        }
      }
    } catch {} // unreadable/invalid config → no allowances (fail closed)
  }
  return entries
}

// Minimal glob → RegExp: `**` spans path separators, `*`/`?` do not. No brace
// or bracket expansion — allow patterns are meant to be narrow and literal.
function globToRe(glob: string): RegExp {
  let re = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*'
        i++
        if (glob[i + 1] === '/') i++ // `**/` also matches zero leading segments
      } else {
        re += '[^/]*'
      }
    } else if (c === '?') {
      re += '[^/]'
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/, '\\$&')
    }
  }
  return new RegExp(`^${re}$`)
}

function pathMatches(entry: AllowEntry, path: string): boolean {
  try {
    return globToRe(entry.path).test(path)
  } catch {
    return false
  }
}

function secretAllowed(path: string, ruleId: string): boolean {
  return allowlist.some((e) => {
    if (e.rule === undefined) return false
    const rules = Array.isArray(e.rule) ? e.rule : [e.rule]
    if (!rules.includes('*') && !rules.includes(ruleId)) return false
    if (!pathMatches(e, path)) return false
    suppressed.push(`secret ${ruleId} in ${path} (reason: ${e.reason.trim()})`)
    return true
  })
}

function packAllowed(path: string): boolean {
  return allowlist.some((e) => {
    if (e.pack !== true || !pathMatches(e, path)) return false
    suppressed.push(`packaged ${path} (reason: ${e.reason.trim()})`)
    return true
  })
}

function sensitiveFileAllowed(path: string): boolean {
  return allowlist.some((e) => {
    if (e.sensitiveFile !== true || !pathMatches(e, path)) return false
    suppressed.push(`tracked sensitive file ${path} (reason: ${e.reason.trim()})`)
    return true
  })
}

// --- .npmrc --------------------------------------------------------------------

const NPMRC_RE = /(^|\/)\.npmrc$/

// A committable `.npmrc` (registry/linker/hoist config, `${ENV}` token refs) is
// safe; only a *literal* credential value is not. Returns the 1-based lines that
// assign a real value to an auth key.
function npmrcCredentialLines(content: string): number[] {
  const bad: number[] = []
  content.split('\n').forEach((raw, i) => {
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';')) return
    // key may carry a `//registry/:` scope prefix; `_authtoken` first so it
    // wins over the `_auth` alternative.
    const m = line.match(/^(?:\/\/\S+:)?(_authtoken|_auth|_password|_secret)\s*=\s*(.+)$/i)
    if (!m) return
    const value = m[2].trim().replace(/^["']|["']$/g, '').trim()
    if (!value) return // empty assignment
    if (/^\$\{[^}]*\}$/.test(value)) return // ${ENV} reference — secret lives in the environment
    if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value)) return // $ENV reference
    bad.push(i + 1)
  })
  return bad
}

// Index (staged) content of a tracked file, falling back to the working tree.
function committedContent(file: string): string {
  const staged = git(['show', `:${file}`])
  if (staged) return staged
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

// Scan text for secret rules; report per-file summary without ever echoing
// the matched value (that would leak the secret into the transcript). When a
// `path` is given, per-path allowlist rule entries can suppress a hit.
function scanContent(content: string, label: string, path?: string): void {
  const hits: string[] = []
  content.split('\n').forEach((line, i) => {
    if (line.includes(INLINE_ALLOW)) return
    const rule = SECRET_RULES.find((r) => r.re.test(line))
    if (!rule) return
    if (path && secretAllowed(path, rule.id)) return
    hits.push(`${rule.id} at line ${i + 1}`)
  })
  if (hits.length > 0) {
    const shown = hits.slice(0, 3).join(', ')
    const more = hits.length > 3 ? `, and ${hits.length - 3} more` : ''
    findings.push(`possible secret in ${label} (${shown}${more})`)
  }
}

function scanWorkingTreeFile(path: string, label: string): void {
  if (SCAN_SKIP_RE.test(path) || !existsSync(path)) return
  const buf = readFileSync(path)
  if (looksBinary(buf)) return
  scanContent(buf.toString('utf8'), label, path)
}

// --- Audit mode ------------------------------------------------------------------

// `node gatekeeper.ts --audit` runs every check against the current repo and
// prints one compact report, for the gatekeeper/wrapup skills to read. Same
// detection as the hook, so the skills never have to re-derive it by hand —
// scanning stays in the script instead of streaming through the conversation.
if (process.argv.slice(2).includes('--audit')) {
  runAudit()
  process.exit(0)
}

// --- Read the hook payload -----------------------------------------------------

let command = ''
let cwd: string | undefined
try {
  const payload: HookPayload = JSON.parse(readFileSync(0, 'utf8'))
  command = payload.tool_input?.command ?? ''
  cwd = payload.cwd
} catch {
  process.exit(0) // unreadable payload → allow
}

if (!command) process.exit(0)
if (cwd && existsSync(cwd)) process.chdir(cwd)

const segments = parseSegments(command)

// User-approved bypass. Only a real leading `VAR=value` assignment counts —
// the words appearing anywhere in a commit message must not disarm the gate.
const skipped = segments.some((tokens) => {
  for (const t of tokens) {
    if (t === 'GATEKEEPER_SKIP=1') return true
    if (!ENV_ASSIGN_RE.test(t) && !WRAPPERS.has(commandName(t))) return false
  }
  return false
})
if (skipped) process.exit(0)

allowlist = loadAllowlist()

// hooks.json already filters via `if` (Claude Code >= 2.1.85); this re-check
// is the fallback for older versions, where the hook fires on every Bash call.
// Package managers beyond npm/pnpm are recognized here for that fallback path.
const PUBLISHERS = ['npm', 'pnpm', 'yarn', 'bun']
const RUNNERS = ['run', 'run-script', 'exec']

const isCommit = segments.some((tokens) => isCommand(tokens, ['git'], 'commit'))
const isPublish = segments.some((tokens) => {
  if (isCommand(tokens, PUBLISHERS, 'publish')) return true
  // `npm run publish` — a package script that publishes.
  const pos = positionals(tokens)
  return RUNNERS.some((r) => isCommand(tokens, PUBLISHERS, r)) && pos[1] === 'publish'
})
if (!isCommit && !isPublish) process.exit(0)

// --- Commit checks -------------------------------------------------------------

// This hook runs BEFORE the command, so `git diff --cached` alone would miss
// files that the command itself is about to stage. Predict those: `-a`/`--all`
// stages all modified tracked files, and chained `git add … && git commit`
// stages whatever `git add --dry-run` reports for the same arguments.
function predictStagedFiles(): string[] {
  const files = new Set<string>()
  for (const tokens of segments) {
    if (isCommand(tokens, ['git'], 'commit')) {
      // -a / --all (and short-flag clusters like -am) stage modified tracked files
      const all = flagsAfter(tokens, 'commit').some(
        (f) => f === '--all' || (/^-[a-zA-Z]+$/.test(f) && f.includes('a'))
      )
      if (all) lines(git(['diff', '--name-only', '--diff-filter=ACM'])).forEach((f) => files.add(f))
    }
    if (isCommand(tokens, ['git'], 'add')) {
      // Pass the parsed args straight to git — no shell, so a pathspec can't
      // re-execute a substitution the user's command only quoted.
      const dryRun = spawnSync('git', ['add', '--dry-run', '--ignore-missing', ...flagsAfter(tokens, 'add')], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      })
      for (const line of lines(dryRun.stdout ?? '')) {
        const m = line.match(/^add '(.+)'$/)
        if (m) files.add(m[1])
      }
    }
  }
  return [...files]
}

// Delegate the staged-content scan to gitleaks (180+ maintained rules,
// entropy scoring, --redact). Returns false when gitleaks is unavailable or
// errors, in which case the caller falls back to our own rules.
function gitleaksStagedScan(): boolean {
  if (spawnSync('gitleaks', ['version'], { stdio: 'ignore' }).error) return false

  const reportDir = mkdtempSync(join(tmpdir(), 'gatekeeper-'))
  const reportPath = join(reportDir, 'report.json')
  try {
    const res = spawnSync(
      'gitleaks',
      ['git', '--pre-commit', '--staged', '--redact', '--no-banner', '--report-format', 'json', '--report-path', reportPath],
      { stdio: 'ignore' }
    )
    if (res.status === 0) return true // scanned, clean
    if (res.status === 1) {
      let leaks: GitleaksLeak[] = []
      try {
        leaks = JSON.parse(readFileSync(reportPath, 'utf8'))
      } catch {}
      // Honor per-path allowlist rule entries against gitleaks' own rule ids too
      // (inline `gitleaks:allow` and .gitleaksignore remain the finer-grained
      // escape hatches gitleaks applies itself).
      leaks = leaks.filter((leak) => !secretAllowed(leak.File, leak.RuleID))
      for (const leak of leaks.slice(0, 10)) {
        findings.push(`gitleaks: ${leak.RuleID} in ${leak.File}:${leak.StartLine}`)
      }
      if (leaks.length > 10) findings.push(`gitleaks: …and ${leaks.length - 10} more findings`)
      if (leaks.length === 0 && suppressed.length === 0) findings.push('gitleaks detected secrets in the staged changes')
      return true
    }
    return false // unexpected exit (old gitleaks?) → fall back to our rules
  } finally {
    rmSync(reportDir, { recursive: true, force: true })
  }
}

// Sensitive files (.env, keys, credential JSON) that are tracked in git.
function checkTrackedFiles(): void {
  for (const file of lines(git(['ls-files']))) {
    if (!SENSITIVE_FILE_RE.test(file) || SENSITIVE_FILE_EXCEPTIONS.test(file)) continue
    if (sensitiveFileAllowed(file)) continue
    // .npmrc is content-gated: registry/linker/hoist config and ${ENV} token
    // references are fine; only a literal credential value is a leak.
    if (NPMRC_RE.test(file)) {
      const credLines = npmrcCredentialLines(committedContent(file))
      if (credLines.length > 0) {
        findings.push(
          `.npmrc tracked in git assigns a literal credential (line ${credLines.join(', ')}) — reference the token via \${ENV_VAR} instead, or git rm --cached '${file}'`
        )
      }
      continue
    }
    findings.push(`sensitive file tracked in git: ${file} (git rm --cached '${file}' and add to .gitignore)`)
  }
}

// Secrets in the staged content. Returns the staged file list so callers can
// avoid scanning the same file twice.
function checkStagedContent(): string[] {
  const staged = lines(git(['diff', '--cached', '--name-only', '--diff-filter=ACM']))
  const delegated = staged.length > 0 && gitleaksStagedScan()
  if (!delegated) {
    for (const file of staged) {
      if (SCAN_SKIP_RE.test(file)) continue
      scanContent(git(['show', `:${file}`]), `staged file ${file}`, file)
    }
  }
  return staged
}

if (isCommit && git(['rev-parse', '--is-inside-work-tree']) === 'true') {
  checkTrackedFiles()
  const staged = checkStagedContent()
  for (const file of predictStagedFiles()) {
    if (staged.includes(file)) continue // already covered above
    scanWorkingTreeFile(file, `file to be committed: ${file}`)
  }
}

// --- Publish checks --------------------------------------------------------------

// What `npm pack` would put in the tarball, for the package rooted at `dir`.
// --ignore-scripts keeps prepare/prepack output from corrupting the JSON
// (npm/cli#7354); the leading-[ slice is a second guard for the same bug.
function packFiles(dir: string): string[] {
  try {
    const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    })
    const jsonStart = raw.indexOf('[')
    if (jsonStart < 0) return []
    const packInfo: Array<{ files?: Array<{ path: string }> }> = JSON.parse(raw.slice(jsonStart))
    return (packInfo[0]?.files ?? []).map((f) => f.path)
  } catch {
    return [] // pack failed (private package, no package.json, …) → nothing to check
  }
}

// `label` prefixes findings when several packages are audited in one run.
function checkPackage(dir: string, label: string): void {
  const tarballFiles = packFiles(dir)
  const nonBuild = tarballFiles.filter((f) => NON_BUILD_RE.test(f) && !NON_BUILD_EXCEPTIONS.test(f) && !packAllowed(f))
  if (nonBuild.length > 0) {
    const shown = nonBuild.slice(0, 8).join(', ')
    const more = nonBuild.length > 8 ? ', …' : ''
    findings.push(
      `${label}package tarball contains ${nonBuild.length} non-build file(s): ${shown}${more} — set a "files" whitelist in package.json (e.g. ["dist"]) or add .npmignore`
    )
  }

  // Secrets in files about to be published (npm ignores .gitignore!)
  for (const file of tarballFiles) {
    scanWorkingTreeFile(dir === '.' ? file : join(dir, file), `${label}file to be published: ${file}`)
  }
}

if (isPublish) checkPackage('.', '')

// --- Audit report ------------------------------------------------------------------

// Every non-private package.json tracked in the repo. Unlike the hook (which
// packs whatever directory the publish runs from), the audit covers a whole
// workspace — the `pnpm -r publish` blind spot.
function publishablePackages(): Array<{ dir: string, name: string }> {
  const tracked = lines(git(['ls-files', 'package.json', '*/package.json', '**/package.json']))
  const manifests = tracked.length > 0 ? tracked : existsSync('package.json') ? ['package.json'] : []
  const out: Array<{ dir: string, name: string }> = []
  for (const manifest of manifests) {
    if (manifest.includes('node_modules/')) continue
    try {
      const pkg: { name?: string, version?: string, private?: boolean } = JSON.parse(readFileSync(manifest, 'utf8'))
      if (pkg.private === true || !pkg.name) continue
      out.push({ dir: dirname(manifest), name: pkg.version ? `${pkg.name}@${pkg.version}` : pkg.name })
    } catch {} // unparseable manifest → not something we can pack anyway
  }
  return out
}

function runAudit(): void {
  allowlist = loadAllowlist()
  const scope: string[] = []

  if (git(['rev-parse', '--is-inside-work-tree']) === 'true') {
    checkTrackedFiles()
    // Outgoing changes, which for an audit means everything not yet in HEAD —
    // staged, modified-but-unstaged, and untracked-but-not-ignored.
    const staged = checkStagedContent()
    const pending = new Set([
      ...lines(git(['diff', '--name-only', '--diff-filter=ACM', 'HEAD'])),
      ...lines(git(['ls-files', '--others', '--exclude-standard']))
    ])
    for (const file of pending) {
      if (staged.includes(file)) continue // already scanned from the index
      scanWorkingTreeFile(file, `uncommitted change: ${file}`)
    }
    for (const file of staged) pending.add(file)
    scope.push(`${pending.size} outgoing file(s)`)
  } else {
    scope.push('not a git repo — skipped the git checks')
  }

  const packages = publishablePackages()
  for (const pkg of packages) checkPackage(pkg.dir, packages.length > 1 ? `${pkg.name}: ` : '')
  scope.push(
    packages.length > 0
      ? `${packages.length} publishable package(s): ${packages.map((p) => p.name).join(', ')}`
      : 'no publishable package (private or absent package.json)'
  )

  const report = ['GATEKEEPER AUDIT', `scope: ${scope.join('; ')}`]
  report.push(findings.length > 0 ? `findings: ${findings.length}` : 'findings: none')
  for (const f of findings) report.push(`  - ${f}`)
  if (suppressed.length > 0) {
    report.push(`suppressed by .claude/gatekeeper.json: ${suppressed.length}`)
    for (const s of suppressed) report.push(`  - ${s}`)
  }
  report.push(
    findings.length > 0
      ? 'The commit/publish hook enforces these same checks, so fix them before committing or publishing.'
      : 'Clean — the commit/publish hook will not block on these checks.'
  )
  console.log(report.join('\n'))
}

// --- Verdict -----------------------------------------------------------------------

if (findings.length > 0) {
  const reason = 'Gatekeeper blocked this command. Findings:\n' + findings.map((f) => `- ${f}`).join('\n')
  const context =
    'The gatekeeper hook (dev plugin) blocked the command. The findings above are the complete result — fix them and retry; do not re-scan by hand. For wider context run `gatekeeper --audit` (whole workspace, one report). Load the dev plugin\'s \'gatekeeper\' skill only when a finding needs remediation guidance. For a single false-positive line, append a `gitleaks:allow` comment to it. If the user confirms the whole block is a false positive, re-run the command prefixed with GATEKEEPER_SKIP=1 (never do this without explicit user confirmation).'

  // Both blocking channels: JSON deny on stdout, exit 2 + stderr as backstop.
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
        additionalContext: context
      },
      systemMessage: `Gatekeeper blocked \`${command.split('\n')[0].slice(0, 80)}\` (${findings.length} finding(s))`
    })
  )
  console.error(reason + '\n\n' + context)
  process.exit(2)
}

// Allowed — but if allowlist entries suppressed findings, say so out loud. A
// silent suppression would defeat the point of a review-visible allowlist.
if (suppressed.length > 0) {
  const shown = suppressed.slice(0, 5).join('; ')
  const more = suppressed.length > 5 ? `; …and ${suppressed.length - 5} more` : ''
  console.log(
    JSON.stringify({
      systemMessage: `Gatekeeper: ${suppressed.length} finding(s) suppressed by .claude/gatekeeper.json — ${shown}${more}`
    })
  )
}

process.exit(0)
