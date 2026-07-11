/**
 * End-to-end tests for the dev plugin's gatekeeper hook.
 *
 * Each test builds a throwaway git repo, feeds the hook a PreToolUse payload
 * on stdin (exactly like Claude Code does), and asserts on the decision.
 * Run with: pnpm test  (node --test, native TS type stripping)
 *
 * Note: assertions check the deny/allow decision, not finding wording —
 * on machines with gitleaks installed the staged-content scan delegates to
 * it and produces different finding text.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync, execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const GATEKEEPER = join(dirname(fileURLToPath(import.meta.url)), '..', 'plugins', 'dev', 'scripts', 'gatekeeper.ts')

// The concatenations are deliberate: they keep these fixtures from matching
// the gatekeeper's own secret rules when this repo is committed.
// oxlint-disable-next-line no-useless-concat
const FAKE_AWS_KEY = 'k = "AKIA' + 'IOSFODNN7EXAMPLE"'
// oxlint-disable-next-line no-useless-concat
const FAKE_GITLAB_PAT = 't = "glpat-' + 'abcdefghij0123456789"'

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' })
}

function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-test-'))
  git(dir, 'init', '-q', '.')
  git(dir, 'config', 'user.email', 'test@test.local')
  git(dir, 'config', 'user.name', 'Test')
  return dir
}

interface HookResult {
  code: number
  denied: boolean
  reason: string
}

function runHook(cwd: string, command: string): HookResult {
  const payload = JSON.stringify({ tool_input: { command }, cwd })
  const res = spawnSync('node', [GATEKEEPER], { input: payload, encoding: 'utf8' })
  let denied = false
  let reason = ''
  if (res.stdout.trim()) {
    const out = JSON.parse(res.stdout) as { hookSpecificOutput?: { permissionDecision?: string, permissionDecisionReason?: string } }
    denied = out.hookSpecificOutput?.permissionDecision === 'deny'
    reason = out.hookSpecificOutput?.permissionDecisionReason ?? ''
  }
  return { code: res.status ?? -1, denied, reason }
}

function inRepo(fn: (repo: string) => void): () => void {
  return () => {
    const repo = makeRepo()
    try {
      fn(repo)
    } finally {
      rmSync(repo, { recursive: true, force: true })
    }
  }
}

// --- Commit gating ---------------------------------------------------------

test('blocks commit when a staged file contains a secret', inRepo((repo) => {
  writeFileSync(join(repo, 'config.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'config.js')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, true)
  assert.equal(res.code, 2)
}))

test('blocks git commit -a when an unstaged tracked file contains a secret', inRepo((repo) => {
  writeFileSync(join(repo, 'base.txt'), 'clean\n')
  git(repo, 'add', 'base.txt')
  git(repo, 'commit', '-q', '-m', 'base')
  writeFileSync(join(repo, 'base.txt'), `clean\n${FAKE_GITLAB_PAT}\n`)
  const res = runHook(repo, 'git commit -am test')
  assert.equal(res.denied, true)
  assert.match(res.reason, /base\.txt/)
}))

test('blocks chained git add && git commit with a secret in the added file', inRepo((repo) => {
  writeFileSync(join(repo, 'new.js'), FAKE_AWS_KEY)
  const res = runHook(repo, 'git add new.js && git commit -m test')
  assert.equal(res.denied, true)
  assert.match(res.reason, /new\.js/)
}))

test('blocks commit when a sensitive file (.env) is tracked', inRepo((repo) => {
  writeFileSync(join(repo, '.env'), 'DB_PASSWORD=hunter2\n')
  git(repo, 'add', '-f', '.env')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, true)
  assert.match(res.reason, /\.env/)
}))

test('allows .env.example to be tracked', inRepo((repo) => {
  writeFileSync(join(repo, '.env.example'), 'DB_PASSWORD=changeme\n')
  git(repo, 'add', '-f', '.env.example')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('respects an inline gitleaks:allow comment', inRepo((repo) => {
  writeFileSync(join(repo, 'fixture.js'), `${FAKE_AWS_KEY} // gitleaks:allow\n`)
  git(repo, 'add', 'fixture.js')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
}))

test('skips lockfiles in the content scan', inRepo((repo) => {
  const jwt = 'eyJ' + 'a'.repeat(24) + '.eyJ' + 'b'.repeat(24) + '.' + 'c'.repeat(24)
  writeFileSync(join(repo, 'package-lock.json'), `{"integrity":"${jwt}"}\n`)
  git(repo, 'add', 'package-lock.json')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
}))

test('allows a clean commit', inRepo((repo) => {
  writeFileSync(join(repo, 'clean.txt'), 'nothing to see\n')
  git(repo, 'add', 'clean.txt')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

// --- Bypass and scoping ------------------------------------------------------

test('GATEKEEPER_SKIP=1 bypasses the gate', inRepo((repo) => {
  writeFileSync(join(repo, 'config.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'config.js')
  const res = runHook(repo, 'GATEKEEPER_SKIP=1 git commit -m test')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('ignores unrelated commands', inRepo((repo) => {
  writeFileSync(join(repo, 'config.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'config.js')
  const res = runHook(repo, 'ls -la')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

// --- Publish gating -----------------------------------------------------------

test('blocks publish when the tarball contains non-build files', inRepo((repo) => {
  mkdirSync(join(repo, 'src'))
  mkdirSync(join(repo, 'dist'))
  writeFileSync(join(repo, 'src', 'index.ts'), 'export {}\n')
  writeFileSync(join(repo, 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, 'tsconfig.tsbuildinfo'), '{}\n')
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'gatekeeper-test-pkg', version: '1.0.0', main: 'dist/index.js' }))
  const res = runHook(repo, 'npm publish')
  assert.equal(res.denied, true)
  assert.match(res.reason, /non-build file/)
}))

test('allows publish with a files whitelist', inRepo((repo) => {
  mkdirSync(join(repo, 'src'))
  mkdirSync(join(repo, 'dist'))
  writeFileSync(join(repo, 'src', 'index.ts'), 'export {}\n')
  writeFileSync(join(repo, 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'gatekeeper-test-pkg', version: '1.0.0', main: 'dist/index.js', files: ['dist'] }))
  const res = runHook(repo, 'pnpm publish')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('blocks publish when a packed file contains a secret', inRepo((repo) => {
  mkdirSync(join(repo, 'dist'))
  writeFileSync(join(repo, 'dist', 'index.js'), `${FAKE_AWS_KEY}\n`)
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'gatekeeper-test-pkg', version: '1.0.0', main: 'dist/index.js', files: ['dist'] }))
  const res = runHook(repo, 'npm publish')
  assert.equal(res.denied, true)
  assert.match(res.reason, /dist\/index\.js/)
}))
