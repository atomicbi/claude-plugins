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

// --- Command classification (no over-firing on message text) -----------------

// A package the publish check would flag: no "files" whitelist, so src/ and
// tsconfig.json land in the tarball. If a commit is misread as a publish, the
// hook blocks with a packaging finding — which is exactly what used to happen.
function packableRepo(repo: string): void {
  mkdirSync(join(repo, 'src'))
  mkdirSync(join(repo, 'dist'))
  writeFileSync(join(repo, 'src', 'index.ts'), 'export {}\n')
  writeFileSync(join(repo, 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, 'tsconfig.json'), '{}\n')
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'gatekeeper-test-pkg', version: '1.0.0', main: 'dist/index.js' }))
  git(repo, 'add', '-A')
}

test('a commit message mentioning npm and publish is not treated as a publish', inRepo((repo) => {
  packableRepo(repo)
  const message = [
    'fix(gatekeeper): stop packing the private root package',
    '',
    'The npm repository never receives this package, so the check',
    'was meaningless — the tarball only matters at publish time.'
  ].join('\n')
  const res = runHook(repo, `git commit -m "$(cat <<'EOF'\n${message}\nEOF\n)"`)
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('a bare heredoc commit message does not trip the publish branch', inRepo((repo) => {
  packableRepo(repo)
  const res = runHook(repo, 'git commit -F - <<\'EOF\'\nchore: notes\n\nrun pnpm publish once the registry is ready\nEOF\n')
  assert.equal(res.denied, false)
}))

test('a single-line message mentioning npm publish is not treated as a publish', inRepo((repo) => {
  packableRepo(repo)
  const res = runHook(repo, 'git commit -m "docs: explain npm publish flow"')
  assert.equal(res.denied, false)
}))

test('a message mentioning git commit does not make a non-git command a commit', inRepo((repo) => {
  writeFileSync(join(repo, 'config.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'config.js')
  const res = runHook(repo, 'echo "remember to git commit this"')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('GATEKEEPER_SKIP=1 inside a commit message does not disarm the gate', inRepo((repo) => {
  writeFileSync(join(repo, 'config.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'config.js')
  const res = runHook(repo, 'git commit -m "note: GATEKEEPER_SKIP=1 is the bypass"')
  assert.equal(res.denied, true)
}))

test('still gates a real publish chained after a commit', inRepo((repo) => {
  packableRepo(repo)
  const res = runHook(repo, 'git commit -m "chore: release" && npm publish')
  assert.equal(res.denied, true)
  assert.match(res.reason, /non-build file/)
}))

test('still gates a publish behind flags and a wrapper', inRepo((repo) => {
  packableRepo(repo)
  const res = runHook(repo, 'env FOO=bar pnpm -r --filter pkg publish --tag next')
  assert.equal(res.denied, true)
  assert.match(res.reason, /non-build file/)
}))

test('still gates a publish inside a subshell or behind a shell keyword', inRepo((repo) => {
  packableRepo(repo)
  for (const cmd of ['(cd . && npm publish)', 'if [ -f package.json ]; then npm publish; fi']) {
    const res = runHook(repo, cmd)
    assert.equal(res.denied, true, cmd)
    assert.match(res.reason, /non-build file/)
  }
}))

test('still gates git commit -a behind a global -C flag', inRepo((repo) => {
  writeFileSync(join(repo, 'base.txt'), 'clean\n')
  git(repo, 'add', 'base.txt')
  git(repo, 'commit', '-q', '-m', 'base')
  writeFileSync(join(repo, 'base.txt'), `clean\n${FAKE_GITLAB_PAT}\n`)
  const res = runHook(repo, `git -C ${repo} -c user.name=x commit -am "wip"`)
  assert.equal(res.denied, true)
  assert.match(res.reason, /base\.txt/)
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

// --- Audit mode (--audit) ----------------------------------------------------

interface AuditResult {
  code: number
  out: string
}

function runAudit(cwd: string): AuditResult {
  const res = spawnSync('node', [GATEKEEPER, '--audit'], { cwd, encoding: 'utf8' })
  return { code: res.status ?? -1, out: res.stdout }
}

test('audit reports a clean repo without blocking', inRepo((repo) => {
  writeFileSync(join(repo, 'clean.txt'), 'nothing to see\n')
  git(repo, 'add', 'clean.txt')
  const res = runAudit(repo)
  assert.equal(res.code, 0)
  assert.match(res.out, /GATEKEEPER AUDIT/)
  assert.match(res.out, /findings: none/)
}))

test('audit covers every publishable package in a workspace, skipping private ones', inRepo((repo) => {
  mkdirSync(join(repo, 'packages', 'a', 'src'), { recursive: true })
  mkdirSync(join(repo, 'packages', 'a', 'dist'), { recursive: true })
  mkdirSync(join(repo, 'packages', 'b', 'dist'), { recursive: true })
  writeFileSync(join(repo, 'packages', 'a', 'src', 'index.ts'), 'export {}\n')
  writeFileSync(join(repo, 'packages', 'a', 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, 'packages', 'b', 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, 'packages', 'a', 'package.json'), JSON.stringify({ name: 'pkg-a', version: '1.0.0', main: 'dist/index.js' }))
  writeFileSync(join(repo, 'packages', 'b', 'package.json'), JSON.stringify({ name: 'pkg-b', version: '2.0.0', main: 'dist/index.js', files: ['dist'] }))
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'root', version: '0.0.0', private: true }))
  git(repo, 'add', '-A')
  const res = runAudit(repo)
  assert.equal(res.code, 0) // an audit reports, it never gates
  assert.match(res.out, /2 publishable package\(s\): pkg-a@1\.0\.0, pkg-b@2\.0\.0/)
  assert.match(res.out, /pkg-a@1\.0\.0: package tarball contains 1 non-build file/)
  assert.doesNotMatch(res.out, /pkg-b@2\.0\.0: package tarball/) // files whitelist → clean
  assert.doesNotMatch(res.out, /root/) // private → not published, not audited
}))

test('audit finds secrets in uncommitted work and sensitive tracked files', inRepo((repo) => {
  writeFileSync(join(repo, 'base.txt'), 'clean\n')
  git(repo, 'add', 'base.txt')
  git(repo, 'commit', '-q', '-m', 'base')
  writeFileSync(join(repo, '.env'), 'DB_PASSWORD=hunter2\n')
  git(repo, 'add', '-f', '.env')
  git(repo, 'commit', '-q', '-m', 'env')
  writeFileSync(join(repo, 'untracked.js'), FAKE_AWS_KEY) // never staged
  const res = runAudit(repo)
  assert.match(res.out, /sensitive file tracked in git: \.env/)
  assert.match(res.out, /untracked\.js/)
}))

// --- .npmrc content-awareness ------------------------------------------------

function writeAllow(repo: string, config: unknown): void {
  mkdirSync(join(repo, '.claude'), { recursive: true })
  writeFileSync(join(repo, '.claude', 'gatekeeper.json'), JSON.stringify(config))
}

test('allows a tracked .npmrc with only registry/linker/hoist settings', inRepo((repo) => {
  writeFileSync(join(repo, '.npmrc'), 'registry=https://registry.npmjs.org/\nnode-linker=hoisted\nshamefully-hoist=true\n')
  git(repo, 'add', '-f', '.npmrc')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('allows a tracked .npmrc that references a token via ${ENV_VAR}', inRepo((repo) => {
  writeFileSync(join(repo, '.npmrc'), '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n')
  git(repo, 'add', '-f', '.npmrc')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
}))

test('blocks a tracked .npmrc that assigns a literal credential', inRepo((repo) => {
  // A plaintext _password value — not a recognized token shape, so this
  // exercises the .npmrc credential check itself, not the generic secret rules.
  writeFileSync(join(repo, '.npmrc'), '//registry.npmjs.org/:_password=s3cr3t-literal-value\n')
  git(repo, 'add', '-f', '.npmrc')
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, true)
  assert.match(res.reason, /\.npmrc/)
}))

// --- Allowlist (.claude/gatekeeper.json) -------------------------------------

test('allowlist: sensitiveFile entry permits a tracked .env', inRepo((repo) => {
  writeFileSync(join(repo, '.env'), 'PORT=3000\n')
  git(repo, 'add', '-f', '.env')
  writeAllow(repo, { allow: [{ path: '.env', sensitiveFile: true, reason: 'app config, no secrets' }] })
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))

test('allowlist: per-path rule "*" suppresses a secret in matching files', inRepo((repo) => {
  mkdirSync(join(repo, 'fixtures'))
  writeFileSync(join(repo, 'fixtures', 'sample.js'), FAKE_AWS_KEY)
  git(repo, 'add', 'fixtures/sample.js')
  writeAllow(repo, { allow: [{ path: 'fixtures/**', rule: '*', reason: 'fake keys in test fixtures' }] })
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, false)
}))

test('allowlist: a malformed entry (missing reason) grants nothing', inRepo((repo) => {
  writeFileSync(join(repo, '.env'), 'PORT=3000\n')
  git(repo, 'add', '-f', '.env')
  writeAllow(repo, { allow: [{ path: '.env', sensitiveFile: true }] })
  const res = runHook(repo, 'git commit -m test')
  assert.equal(res.denied, true)
  assert.match(res.reason, /\.env/)
}))

test('allowlist: pack entry permits an intentionally shipped src/', inRepo((repo) => {
  mkdirSync(join(repo, 'src'))
  mkdirSync(join(repo, 'dist'))
  writeFileSync(join(repo, 'src', 'index.ts'), 'export {}\n')
  writeFileSync(join(repo, 'dist', 'index.js'), 'module.exports = {}\n')
  writeFileSync(join(repo, '.npmignore'), '.claude\n')
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'gatekeeper-test-pkg', version: '1.0.0', main: 'dist/index.js' }))
  writeAllow(repo, { allow: [{ path: 'src/**', pack: true, reason: 'ships TS sources for consumers' }] })
  const res = runHook(repo, 'npm publish')
  assert.equal(res.denied, false)
  assert.equal(res.code, 0)
}))
