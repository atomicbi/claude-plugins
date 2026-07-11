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
 * On findings it blocks both ways: a "deny" decision as JSON on stdout AND
 * exit code 2 with the findings on stderr (the exit-2 path still works when
 * Bash is broadly allowlisted, see anthropics/claude-code#18312).
 *
 * False positives:
 *   - a line containing `gitleaks:allow` is never flagged (ecosystem-standard
 *     inline escape, compatible with real gitleaks)
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
import { join } from 'node:path'

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

const findings: string[] = []

// Scan text for secret rules; report per-file summary without ever echoing
// the matched value (that would leak the secret into the transcript).
function scanContent(content: string, label: string): void {
  const hits: string[] = []
  content.split('\n').forEach((line, i) => {
    if (line.includes(INLINE_ALLOW)) return
    const rule = SECRET_RULES.find((r) => r.re.test(line))
    if (rule) hits.push(`${rule.id} at line ${i + 1}`)
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
  scanContent(buf.toString('utf8'), label)
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
if (command.includes('GATEKEEPER_SKIP=1')) process.exit(0) // user-approved bypass

// hooks.json already filters via `if` (Claude Code >= 2.1.85); this re-check
// is the fallback for older versions, where the hook fires on every Bash call.
const isCommit = /\bgit\b[^;&|]*\scommit\b/.test(command)
const isPublish = /\b(npm|pnpm)\b[^;&|]*\spublish\b/.test(command)
if (!isCommit && !isPublish) process.exit(0)

// --- Commit checks -------------------------------------------------------------

// This hook runs BEFORE the command, so `git diff --cached` alone would miss
// files that the command itself is about to stage. Predict those: `-a`/`--all`
// stages all modified tracked files, and chained `git add … && git commit`
// stages whatever `git add --dry-run` reports for the same arguments.
function predictStagedFiles(): string[] {
  const files = new Set<string>()
  for (const segment of command.split(/&&|\|\||;/)) {
    const commit = segment.match(/\bgit\b[^]*?\bcommit\b(.*)$/)
    if (commit && /(^|\s)(-[a-zA-Z]*a[a-zA-Z]*|--all)(\s|$)/.test(commit[1])) {
      lines(git(['diff', '--name-only', '--diff-filter=ACM'])).forEach((f) => files.add(f))
    }
    const add = segment.match(/\bgit(\s+-\S+)*\s+add\b(.*)$/)
    if (add) {
      const dryRun = spawnSync('/bin/sh', ['-c', `git add --dry-run --ignore-missing ${add[2]}`], {
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
      for (const leak of leaks.slice(0, 10)) {
        findings.push(`gitleaks: ${leak.RuleID} in ${leak.File}:${leak.StartLine}`)
      }
      if (leaks.length > 10) findings.push(`gitleaks: …and ${leaks.length - 10} more findings`)
      if (leaks.length === 0) findings.push('gitleaks detected secrets in the staged changes')
      return true
    }
    return false // unexpected exit (old gitleaks?) → fall back to our rules
  } finally {
    rmSync(reportDir, { recursive: true, force: true })
  }
}

if (isCommit && git(['rev-parse', '--is-inside-work-tree']) === 'true') {
  for (const file of lines(git(['ls-files']))) {
    if (SENSITIVE_FILE_RE.test(file) && !SENSITIVE_FILE_EXCEPTIONS.test(file)) {
      findings.push(`sensitive file tracked in git: ${file} (git rm --cached '${file}' and add to .gitignore)`)
    }
  }

  const staged = lines(git(['diff', '--cached', '--name-only', '--diff-filter=ACM']))
  const delegated = staged.length > 0 && gitleaksStagedScan()
  if (!delegated) {
    for (const file of staged) {
      if (SCAN_SKIP_RE.test(file)) continue
      scanContent(git(['show', `:${file}`]), `staged file ${file}`)
    }
  }
  for (const file of predictStagedFiles()) {
    if (staged.includes(file)) continue // already covered above
    scanWorkingTreeFile(file, `file to be committed: ${file}`)
  }
}

// --- Publish checks --------------------------------------------------------------

if (isPublish) {
  // --ignore-scripts keeps prepare/prepack output from corrupting the JSON
  // (npm/cli#7354); the leading-[ slice is a second guard for the same bug.
  let tarballFiles: string[] = []
  try {
    const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    })
    const jsonStart = raw.indexOf('[')
    if (jsonStart >= 0) {
      const packInfo: Array<{ files?: Array<{ path: string }> }> = JSON.parse(raw.slice(jsonStart))
      tarballFiles = (packInfo[0]?.files ?? []).map((f) => f.path)
    }
  } catch {} // pack failed (private package, no package.json, …) → nothing to check

  const nonBuild = tarballFiles.filter((f) => NON_BUILD_RE.test(f) && !NON_BUILD_EXCEPTIONS.test(f))
  if (nonBuild.length > 0) {
    const shown = nonBuild.slice(0, 8).join(', ')
    const more = nonBuild.length > 8 ? ', …' : ''
    findings.push(
      `package tarball contains ${nonBuild.length} non-build file(s): ${shown}${more} — set a "files" whitelist in package.json (e.g. ["dist"]) or add .npmignore`
    )
  }

  // Secrets in files about to be published (npm ignores .gitignore!)
  for (const file of tarballFiles) {
    scanWorkingTreeFile(file, `file to be published: ${file}`)
  }
}

// --- Verdict -----------------------------------------------------------------------

if (findings.length > 0) {
  const reason = 'Gatekeeper blocked this command. Findings:\n' + findings.map((f) => `- ${f}`).join('\n')
  const context =
    'The gatekeeper hook (dev plugin) blocked the command. Fix the findings, then retry. For a thorough audit and remediation guidance, use the dev plugin\'s \'gatekeeper\' skill. For a single false-positive line, append a `gitleaks:allow` comment to it. If the user confirms the whole block is a false positive, re-run the command prefixed with GATEKEEPER_SKIP=1 (never do this without explicit user confirmation).'

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

process.exit(0)
