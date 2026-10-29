import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateChecks, evaluationMarkdown, checkClasses } from '../src/checks.ts';
import type { Check } from '../src/checks.ts';
import { runLabCase } from '../src/cases.ts';
import { startRoleLab } from '../src/role-lab.ts';
import type { Session } from '../src/session.ts';

for (const kind of checkClasses) {
  test(`${kind}: vulnerable lab is confirmed and fixed lab is not reproduced, with real HTTP`, async () => {
    const vulnerable = await runLabCase(kind, 'vulnerable');
    const fixed = await runLabCase(kind, 'fixed');
    assert.deepEqual(vulnerable.findings.map(f => f.status), ['confirmed']);
    assert.deepEqual(fixed.findings.map(f => f.status), ['not-reproduced']);
    const [v, f] = [vulnerable.findings[0].steps, fixed.findings[0].steps];
    assert.deepEqual([v.control.status, v.baseline.status, v.probe.status], [401, 200, 200]);
    assert.equal(v.probe.sha256, v.baseline.sha256);
    assert.equal(f.control.status, 401);
    assert.equal(f.baseline.status, 200);
    // BOLA and BFLA are denied outright; property exposure is a filtered 200.
    assert.equal(f.probe.status, kind === 'property-exposure' ? 200 : 403);
    assert.notEqual(f.probe.sha256, f.baseline.sha256);
  });
}

const hash = (c: string) => c.repeat(64);
type Responses = Record<string, [number, string] | null>;
function session(responses: Responses, envs: Record<string, string | null> = {}): Session {
  const url = 'http://127.0.0.1:9/x';
  const steps = Object.keys(responses).map(id => ({ id, method: 'GET' as const, url,
    credentialEnv: id in envs ? envs[id] : id === 'control' ? null : id === 'baseline' ? 'BBA_TOKEN_A' : 'BBA_TOKEN_B' }));
  return { id: 'x', scopeDigest: 'd', status: 'completed', plan: { schemaVersion: 1, steps },
    attempts: Object.entries(responses).filter(([, r]) => r).map(([stepId, r]) => ({ stepId, outcome: 'succeeded',
      response: { status: r![0], bytes: 1, sha256: hash(r![1]) } })) } as unknown as Session;
}
const check = (extra: Partial<Check> = {}) => ({ schemaVersion: 1, checks: [{ id: 'c', class: 'bola', control: 'control', baseline: 'baseline', probe: 'probe', ...extra }] });
const verdict = (s: Session, c: unknown = check()) => evaluateChecks(s, c).findings[0].status;

test('anything that is not clean evidence stays unresolved', () => {
  assert.equal(verdict(session({ control: [200, 'a'], baseline: [200, 'a'], probe: [200, 'a'] })), 'unresolved', 'open control');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [500, 'a'], probe: [200, 'a'] })), 'unresolved', 'baseline failed');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [200, 'a'], probe: null })), 'unresolved', 'probe never completed');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [500, 'b'] })), 'unresolved', 'server error is not a denial');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'b'] })), 'unresolved', 'different 200 is not a BOLA denial');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'b'] }), check({ class: 'property-exposure' })), 'not-reproduced');
  assert.equal(verdict(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] })), 'confirmed');
  assert.equal(verdict(session({ control: [403, 'a'], baseline: [200, 'a'], probe: [404, 'b'] })), 'not-reproduced');
});

test('checks must form a control and two distinct authenticated identities on one URL', () => {
  const ok = session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] });
  assert.throws(() => evaluateChecks(ok, check({ probe: 'baseline' })), /three distinct/);
  assert.throws(() => evaluateChecks(ok, check({ probe: 'nope' })), /three distinct/);
  assert.throws(() => evaluateChecks(ok, check({ class: 'xss' as 'bola' })), /Unsupported check class/);
  assert.throws(() => evaluateChecks(ok, { schemaVersion: 1, checks: [check().checks[0], check().checks[0]] }), /Invalid check ID/);
  assert.throws(() => evaluateChecks(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] }, { control: 'BBA_TOKEN_A' }), check()), /control and two distinct/);
  assert.throws(() => evaluateChecks(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] }, { probe: 'BBA_TOKEN_A' }), check()), /control and two distinct/);
  const moved = session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] });
  moved.plan.steps[2].url = 'http://127.0.0.1:9/other';
  assert.throws(() => evaluateChecks(moved, check()), /same URL/);
  assert.throws(() => evaluateChecks(ok, { schemaVersion: 1, checks: [], extra: 1 }), /Invalid contract fields/);
});

test('CLI runs a session against the role lab, evaluates it and refuses to overwrite', async () => {
  const lab = await startRoleLab('vulnerable');
  const dir = await mkdtemp(join(tmpdir(), 'bba-checks-'));
  try {
    const url = lab.origin + '/admin/users';
    await writeFile(join(dir, 'scope.json'), JSON.stringify({ schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'BBA role lab', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin: lab.origin, paths: ['/admin/users'] }], excluded: [],
      limits: { maxRequests: 3, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 } }));
    await writeFile(join(dir, 'plan.json'), JSON.stringify({ schemaVersion: 1, steps: [
      { id: 'control', method: 'GET', url, credentialEnv: null }, { id: 'baseline', method: 'GET', url, credentialEnv: 'BBA_TOKEN_ADMIN' },
      { id: 'probe', method: 'GET', url, credentialEnv: 'BBA_TOKEN_USER' }] }));
    await writeFile(join(dir, 'checks.json'), JSON.stringify({ schemaVersion: 1, checks: [{ id: 'admin-users', class: 'bfla', control: 'control', baseline: 'baseline', probe: 'probe' }] }));
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    // Async on purpose: the lab server lives in this process and must keep answering.
    const run = (...args: string[]) => promisify(execFile)(process.execPath, [cli, ...args],
      { env: { ...process.env, BBA_TOKEN_ADMIN: lab.credentials.admin, BBA_TOKEN_USER: lab.credentials.user } })
      .then(r => ({ status: 0, ...r }), (e: { code: number; stdout: string; stderr: string }) => ({ status: e.code, stdout: e.stdout, stderr: e.stderr }));
    const executed = await run('run', '--scope', join(dir, 'scope.json'), '--plan', join(dir, 'plan.json'), '--out', join(dir, 'run'));
    assert.equal(executed.status, 0, executed.stdout + executed.stderr);
    const json = await run('evaluate-run', join(dir, 'run'), '--checks', join(dir, 'checks.json'), '--out', join(dir, 'e.json'));
    assert.equal(json.status, 0, json.stderr);
    assert.deepEqual(JSON.parse(json.stdout), [{ check: 'admin-users', class: 'bfla', status: 'confirmed' }]);
    const saved = JSON.parse(await readFile(join(dir, 'e.json'), 'utf8'));
    assert.match(saved.sha256, /^[a-f0-9]{64}$/);
    const md = await run('evaluate-run', join(dir, 'run'), '--checks', join(dir, 'checks.json'), '--out', join(dir, 'e.md'));
    assert.equal(md.status, 0, md.stderr);
    assert.match(await readFile(join(dir, 'e.md'), 'utf8'), /admin-users \| bfla \| \*\*confirmed\*\*/);
    assert.equal((await run('evaluate-run', join(dir, 'run'), '--checks', join(dir, 'checks.json'), '--out', join(dir, 'e.json'))).status, 1);
    const written = json.stdout + executed.stdout + await readFile(join(dir, 'e.json'), 'utf8');
    for (const secret of [lab.credentials.admin, lab.credentials.user]) assert.doesNotMatch(written, new RegExp(secret));
  } finally { await lab.close(); await rm(dir, { recursive: true, force: true }); }
});

test('markdown report states that confirmed is a hash comparison, not severity', () => {
  const e = evaluateChecks(session({ control: [401, 'a'], baseline: [200, 'a'], probe: [200, 'a'] }), check());
  assert.match(evaluationMarkdown(e), /no mide impacto ni severidad/);
});
