import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { RequestListener } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { validateScope, validatePlan, assertAuthorized } from '../src/scope.ts';
import type { Scope, Plan } from '../src/scope.ts';
import { isPublicAddress, destination } from '../src/http.ts';
import { createSession, inspectSession, exportSession, withSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
function fixture(origin: string, paths = ['/one', '/two', '/three']): { scope: Scope; plan: Plan } {
  return {
    scope: {
      schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'owned-test-fixture', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() },
      allowed: [{ origin, paths }], excluded: [],
      limits: { maxRequests: 3, minIntervalMs: 0, timeoutMs: 1000, maxResponseBytes: 4096, maxDurationMs: 60000 },
    },
    plan: { schemaVersion: 1, steps: paths.map((path, i) => ({ id: `step-${i + 1}`, method: 'GET', url: origin + path, credentialEnv: null })) },
  };
}
async function local(handler: RequestListener, action: (origin: string, folder: string) => Promise<void>) {
  const temp = await mkdtemp(join(tmpdir(), 'bba-execution-'));
  const server = createServer(handler);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  try { await action(`http://127.0.0.1:${address.port}`, join(temp, 'session')); }
  finally {
    await new Promise<void>((resolve, reject) => { server.close(e => e ? reject(e) : resolve()); server.closeAllConnections(); });
    // Only remove the absolute directory returned by mkdtemp for this test.
    assert.ok(temp.startsWith(join(tmpdir(), 'bba-execution-')));
    await rm(temp, { recursive: true, force: true });
  }
}

test('scope validates exact origins/paths, exclusions, methods and credential references', () => {
  const { scope, plan } = fixture('http://127.0.0.1:12345');
  validateScope(scope); validatePlan(plan, scope);
  for (const url of ['http://127.0.0.1:12345/One', 'http://127.0.0.1:12346/one',
    'http://127.0.0.1:12345/one?token=x', 'http://127.0.0.1:12345/a/../one',
    'http://127.0.0.1:12345/%6fne', 'http://127.0.0.1:12345//one',
    'http://user:secret@127.0.0.1:12345/one', 'http://2130706433:12345/one']) {
    assert.throws(() => assertAuthorized(scope, url));
  }
  scope.excluded = [{ origin: scope.allowed[0].origin, paths: ['/one'] }];
  assert.throws(() => validatePlan(plan, scope), /outside scope/);
  scope.excluded = [];
  for (const patch of [{ method: 'POST' }, { credentialEnv: 'MY_SECRET' }, { token: 'SECRET' }]) {
    const bad = structuredClone(plan); Object.assign(bad.steps[0], patch);
    assert.throws(() => validatePlan(bad, scope));
  }
});

test('invalid, expired and future scopes are rejected offline', () => {
  const { scope, plan } = fixture('http://127.0.0.1:12345');
  const bad = structuredClone(scope); bad.limits.maxRequests = 0;
  assert.throws(() => validateScope(bad));
  assert.throws(() => assertAuthorized(scope, plan.steps[0].url, Date.parse(scope.authorization.validUntil)));
  assert.throws(() => assertAuthorized(scope, plan.steps[0].url, Date.parse(scope.authorization.validFrom) - 1));
});

test('public HTTPS refuses private/special addresses, including mapped IPv6 and mixed DNS answers', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.169.254', '172.16.1.1',
    '192.168.1.1', '192.0.2.1', '198.18.0.1', '224.0.0.1', '::1', '::ffff:127.0.0.1',
    'fc00::1', 'fe80::1', '2001:db8::1', '2002::1', '3fff::1', 'bad-address']) assert.equal(isPublicAddress(address), false, address);
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isPublicAddress(address), true, address);
  const { scope } = fixture('http://127.0.0.1:12345'); scope.mode = 'public-https';
  scope.allowed = [{ origin: 'https://example.com', paths: ['/one'] }];
  validateScope(scope);
  const mockDns = async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }];
  await assert.rejects(destination(new URL('https://example.com/one'), scope, mockDns as any), /address-blocked/);
  assert.deepEqual(await destination(new URL('https://example.com/one'), scope,
    (async () => [{ address: '8.8.8.8', family: 4 }]) as any), { address: '8.8.8.8', family: 4 });
  await assert.rejects(destination(new URL('https://[::1]/one'), scope), /address-blocked/);
});

test('durable execution shares a budget across steps and never stores tokens, cookies or response bodies', async () => {
  let hits = 0;
  await local((req, res) => {
    hits++; assert.equal(req.headers.authorization, 'Bearer TOKEN_VALUE_SECRET');
    res.setHeader('Set-Cookie', 'COOKIE_VALUE_SECRET'); res.end('BODY_VALUE_SECRET');
  }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.maxRequests = 2;
    plan.steps.forEach(step => { step.credentialEnv = 'BBA_TOKEN_TEST'; });
    createSession(folder, scope, plan);
    const state = await executeSession(folder, scope, { credentials: { BBA_TOKEN_TEST: 'TOKEN_VALUE_SECRET' } });
    assert.equal(state.status, 'stopped'); assert.equal(state.stopReason, 'budget-exhausted');
    assert.equal(state.attempts.length, 2); assert.equal(hits, 2);
    await assert.rejects(executeSession(folder, scope), /Session stopped/);
    const bytes = await readFile(join(folder, 'session.sqlite'));
    for (const secret of ['TOKEN_VALUE_SECRET', 'COOKIE_VALUE_SECRET', 'BODY_VALUE_SECRET']) assert.equal(bytes.includes(Buffer.from(secret)), false);
    assert.equal(inspectSession(folder).attempts.length, 2);
  });
});

test('missing credentials and a changed scope cause zero requests', async () => {
  let hits = 0;
  await local((_req, res) => { hits++; res.end(); }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); plan.steps[0].credentialEnv = 'BBA_TOKEN_MISSING';
    createSession(folder, scope, plan);
    await assert.rejects(executeSession(folder, scope, { credentials: {} }), /Missing credential/);
    const changed = structuredClone(scope); changed.limits.maxRequests = 4;
    await assert.rejects(executeSession(folder, changed), /Scope changed/);
    assert.equal(hits, 0); assert.equal(inspectSession(folder).attempts.length, 0);
  });
});

test('successful execution respects spacing and can be inspected/exported without more requests', async () => {
  const times: number[] = [];
  await local((_req, res) => { times.push(Date.now()); res.end('synthetic'); }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.minIntervalMs = 60;
    createSession(folder, scope, plan);
    assert.equal((await executeSession(folder, scope)).status, 'completed');
    assert.ok(times[1] - times[0] >= 55); assert.ok(times[2] - times[1] >= 55);
    assert.equal((await executeSession(folder, scope)).attempts.length, 3);
    exportSession(folder, join(folder, 'export.json'), 'json');
    exportSession(folder, join(folder, 'report.md'), 'markdown');
    assert.equal(JSON.parse(await readFile(join(folder, 'export.json'), 'utf8')).session.status, 'completed');
    assert.throws(() => exportSession(folder, join(folder, 'export.json'), 'json'), /EEXIST/);
    assert.equal(times.length, 3);
  });
});

test('graceful cancellation during a request consumes the reservation and resumes only unstarted steps', async () => {
  const controller = new AbortController(); const paths: string[] = [];
  await local((req, res) => {
    paths.push(req.url!);
    if (req.url === '/two') { controller.abort(); return; }
    res.end('synthetic');
  }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); createSession(folder, scope, plan);
    const paused = await executeSession(folder, scope, { signal: controller.signal });
    assert.equal(paused.status, 'paused'); assert.equal(paused.attempts[1].outcome, 'cancelled');
    const resumed = await executeSession(folder, scope);
    assert.equal(resumed.status, 'partial'); assert.equal(resumed.attempts.length, 3);
    assert.deepEqual(paths, ['/one', '/two', '/three']);
  });
});

test('pre-cancelled runs reserve nothing; total duration survives pauses', async () => {
  let hits = 0;
  await local((_req, res) => { hits++; res.end(); }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.maxDurationMs = 60;
    createSession(folder, scope, plan);
    const controller = new AbortController(); controller.abort();
    assert.equal((await executeSession(folder, scope, { signal: controller.signal })).status, 'paused');
    await delay(80);
    const stopped = await executeSession(folder, scope);
    assert.equal(stopped.stopReason, 'deadline'); assert.equal(hits, 0);
  });
});

for (const [status, reason] of [[302, 'redirect'], [429, 'rate-limited'], [503, 'server-error']] as const) {
  test(`HTTP ${status} persists a terminal stop without following, retrying or forgetting budget`, async () => {
    let hits = 0;
    await local((_req, res) => { hits++; res.writeHead(status, { Location: '/three' }); res.end('SECRET'); }, async (origin, folder) => {
      const { scope, plan } = fixture(origin); createSession(folder, scope, plan);
      const stopped = await executeSession(folder, scope);
      assert.equal(stopped.stopReason, reason); assert.equal(stopped.attempts[0].response?.bytes, 0);
      await assert.rejects(executeSession(folder, scope), /Session stopped/);
      assert.equal(inspectSession(folder).attempts.length, 1); assert.equal(hits, 1);
    });
  });
}

test('response byte limits and deadlines are persisted as incomplete evidence', async () => {
  await local((_req, res) => { res.end('x'.repeat(100)); }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.maxResponseBytes = 16;
    createSession(folder, scope, plan);
    assert.equal((await executeSession(folder, scope)).stopReason, 'response-too-large');
    assert.equal(inspectSession(folder).attempts[0].response, null);
  });
  await local(() => {}, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.timeoutMs = 40;
    createSession(folder, scope, plan);
    assert.equal((await executeSession(folder, scope)).stopReason, 'deadline');
  });
});

test('concurrent writers are refused and checkpoint corruption is detected', async () => {
  await local((_req, res) => res.end(), async (origin, folder) => {
    const { scope, plan } = fixture(origin); createSession(folder, scope, plan);
    await withSession(folder, async () => {
      await assert.rejects(executeSession(folder, scope), /already active/);
    });
    await executeSession(folder, scope);
    const db = new DatabaseSync(join(folder, 'session.sqlite'));
    try { db.prepare('UPDATE checkpoints SET hash = ? WHERE sequence = 2').run('0'.repeat(64)); }
    finally { db.close(); }
    assert.throws(() => inspectSession(folder), /integrity mismatch/);
  });
});

test('hard process death leaves a durable reservation, releases the OS lock and never replays the uncertain request', { timeout: 15000 }, async () => {
  const seen: string[] = [];
  let hitSecond: () => void = () => {};
  const second = new Promise<void>(resolve => { hitSecond = resolve; });
  await local((req, res) => {
    seen.push(req.url!);
    if (req.url === '/two') { hitSecond(); return; }
    res.end('synthetic');
  }, async (origin, folder) => {
    const { scope, plan } = fixture(origin); scope.limits.timeoutMs = 10000;
    createSession(folder, scope, plan);
    const scopeFile = join(folder, 'scope.json'); await writeFile(scopeFile, JSON.stringify(scope));
    const child = spawn(process.execPath, [cli, 'resume', folder, '--scope', scopeFile], { stdio: 'ignore' });
    const exited = once(child, 'exit');
    try {
      await Promise.race([second, exited.then(() => { throw new Error('Child exited before request'); })]);
      await assert.rejects(executeSession(folder, scope), /already active/);
      assert.equal(inspectSession(folder).attempts[1].outcome, 'reserved');
      child.kill('SIGKILL'); await exited;
      const recovered = await executeSession(folder, scope);
      assert.equal(recovered.status, 'partial'); assert.equal(recovered.attempts[1].outcome, 'interrupted');
      assert.equal(recovered.attempts.length, 3);
      assert.deepEqual(seen, ['/one', '/two', '/three']);
    } finally { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exited; } }
  });
});

test('CLI scope-check is offline and new inspect/export commands read a completed run', async () => {
  await local((_req, res) => res.end('synthetic'), async (origin, folder) => {
    const { scope, plan } = fixture(origin); createSession(folder, scope, plan);
    const scopeFile = join(folder, 'scope.json'), planFile = join(folder, 'plan.json');
    await writeFile(scopeFile, JSON.stringify(scope)); await writeFile(planFile, JSON.stringify(plan));
    const offline = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000 });
    assert.equal(offline(['scope-check', '--scope', scopeFile, '--plan', planFile]).status, 0);
    assert.equal(inspectSession(folder).attempts.length, 0);
    const child = spawn(process.execPath, [cli, 'resume', folder, '--scope', scopeFile], { stdio: 'pipe' });
    let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
    const [code] = await once(child, 'exit'); assert.equal(code, 0, errors);
    const result = offline(['inspect-run', folder]); assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, 'completed');
    assert.equal(offline(['export-run', folder, '--out', join(folder, 'export.json')]).status, 0);
    assert.equal(offline(['report-run', folder, '--out', join(folder, 'report.md')]).status, 0);
    assert.equal(offline(['run', '--scope', scopeFile, '--plan', planFile, '--out', folder]).status, 1);
    const runFolder = join(folder, 'new-run');
    const runner = spawn(process.execPath, [cli, 'run', '--scope', scopeFile, '--plan', planFile, '--out', runFolder], { stdio: 'pipe' });
    let runErrors = ''; runner.stderr.on('data', chunk => { runErrors += chunk; });
    const [runCode] = await once(runner, 'exit'); assert.equal(runCode, 0, runErrors);
    assert.equal(inspectSession(runFolder).status, 'completed');
  });
});

test('scope expiration after pausing is rechecked before any network call', async () => {
  let hits = 0;
  await local((_req, res) => { hits++; res.end(); }, async (origin, folder) => {
    const { scope, plan } = fixture(origin);
    scope.authorization.validUntil = new Date(Date.now() + 1000).toISOString();
    createSession(folder, scope, plan);
    const controller = new AbortController(); controller.abort();
    await executeSession(folder, scope, { signal: controller.signal });
    await delay(1100);
    await assert.rejects(executeSession(folder, scope), /Authorization expired/);
    assert.equal(hits, 0);
  });
});

test('deleting an interior checkpoint breaks the sequence', async () => {
  await local((_req, res) => res.end(), async (origin, folder) => {
    const { scope, plan } = fixture(origin); createSession(folder, scope, plan);
    await executeSession(folder, scope);
    const db = new DatabaseSync(join(folder, 'session.sqlite'));
    try { db.exec('DELETE FROM checkpoints WHERE sequence = 2'); } finally { db.close(); }
    assert.throws(() => inspectSession(folder), /Broken checkpoint chain/);
  });
});
