import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { digest, evidence, validateBundle } from '../src/contracts.ts';
import { investigateLab, evaluate } from '../src/investigation.ts';
import { startLab } from '../src/lab.ts';
import { labTransport } from '../src/transport.ts';
import { exportReport, loadInvestigation, saveInvestigation, verify } from '../src/storage.ts';

const paths = ['/documents/11111111-1111-4111-8111-111111111111', '/documents/22222222-2222-4222-8222-222222222222'];

test('vulnerable lab confirms both cross-account reads from five real HTTP observations', async () => {
  const inv = await investigateLab('vulnerable');
  assert.deepEqual(inv.evidence.map(e => e.status), [401, 200, 200, 200, 200]);
  assert.deepEqual(inv.findings.map(f => f.status), ['confirmed', 'confirmed']);
  validateBundle({ investigation: inv, sha256: digest(inv) });
  assert.equal(inv.evidence[3].document?.marker, inv.evidence[2].document?.marker);
  assert.equal(inv.evidence[4].document?.marker, inv.evidence[1].document?.marker);
  await assert.rejects(fetch(inv.environment.origin), /fetch failed/);
});

test('fixed lab rejects both cross-account reads while owner baselines work', async () => {
  const inv = await investigateLab('fixed');
  assert.deepEqual(inv.evidence.map(e => e.status), [401, 200, 200, 403, 403]);
  assert.deepEqual(inv.findings.map(f => f.status), ['not-reproduced', 'not-reproduced']);
  verify({ investigation: inv, sha256: digest(inv) });
  inv.environment.variant = 'vulnerable';
  assert.deepEqual(evaluate(inv.evidence), inv.findings, 'variant label cannot influence detection');
});

test('absent controls, expired authentication and mismatched data stay unresolved', async () => {
  const inv = await investigateLab('fixed');
  for (const index of [0, 1, 2, 3]) {
    const items = structuredClone(inv.evidence);
    items[index].status = index === 0 ? 200 : 401;
    items[index].document = null;
    assert.equal(evaluate(items)[0].status, 'unresolved');
  }
  const items = structuredClone(inv.evidence);
  items[3].status = 200;
  items[3].document = structuredClone(items[1].document);
  assert.equal(evaluate(items)[0].status, 'unresolved', 'HTTP 200 is not enough');
});

test('lab isolation, unauthorized requests, unsupported methods and cleanup', async () => {
  const lab = await startLab('fixed');
  try {
    assert.notEqual(lab.credentials['account-a'], lab.credentials['account-b']);
    assert.equal((await fetch(lab.origin + '/documents/' + lab.documents[0].id, {
      headers: { authorization: 'Bearer invalid' },
    })).status, 401);
    assert.equal((await fetch(lab.origin, { method: 'POST' })).status, 405);
    assert.equal((await fetch(lab.origin + '/other', {
      headers: { authorization: 'Bearer ' + lab.credentials['account-a'] },
    })).status, 404);
  } finally { await lab.close(); }
});

test('transport rejects non-lab origins and scope escapes before any request', async () => {
  for (const origin of ['https://example.com', 'http://localhost:80', 'http://127.0.0.1:80/', 'http://127.0.0.1:80@evil.test']) {
    assert.throws(() => labTransport(origin, paths));
  }
  const get = labTransport('http://127.0.0.1:65534', paths);
  for (const path of ['//example.com', '/documents/../admin', paths[0] + '?token=secret', 'http://example.com']) {
    await assert.rejects(get(path, 'anonymous'), /outside scope/);
  }
});

async function withServer(handler: Parameters<typeof createServer>[0], fn: (origin: string, hits: () => number) => Promise<void>) {
  let hits = 0;
  const server = createServer((req, res) => { hits++; (handler as Function)(req, res); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try { await fn(`http://127.0.0.1:${address.port}`, () => hits); }
  finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve()); server.closeAllConnections();
    });
  }
}

test('budget limits count actual requests, including denials', async () => {
  await withServer((_req, res) => { res.writeHead(401); res.end('{}'); }, async (origin, hits) => {
    const get = labTransport(origin, paths, { budget: 1 });
    await get(paths[0], 'anonymous');
    await assert.rejects(get(paths[0], 'anonymous'), /budget exhausted/);
    assert.equal(hits(), 1);
  });
});

for (const status of [302, 429, 503]) {
  test(`HTTP ${status} stops transport without following redirects or retrying`, async () => {
    await withServer((_req, res) => { res.writeHead(status, { Location: '/unexpected' }); res.end(); }, async (origin, hits) => {
      const get = labTransport(origin, paths);
      await assert.rejects(get(paths[0], 'anonymous'), /Stopped on HTTP/);
      await assert.rejects(get(paths[1], 'anonymous'), /Transport stopped/);
      assert.equal(hits(), 1);
    });
  });
}

test('oversized responses and timeouts abort without persisting raw bodies', async () => {
  await withServer((_req, res) => { res.end('secret'.repeat(100)); }, async origin => {
    await assert.rejects(labTransport(origin, paths, { maxBytes: 32 })(paths[0], 'anonymous'), /oversized/);
  });
  await withServer(() => {}, async origin => {
    await assert.rejects(labTransport(origin, paths, { timeoutMs: 40 })(paths[0], 'anonymous'), /deadline/);
  });
});

test('unexpected fields and document contents are rejected, credentials never enter evidence', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'session=SECRET_COOKIE' });
    res.end(JSON.stringify({ id: paths[0].slice(11), owner: 'account-a', marker: 'SECRET_BODY' }));
  }, async origin => {
    await assert.rejects(labTransport(origin, paths)(paths[0], 'anonymous'), /synthetic lab contract/);
  });
  const lab = await startLab('vulnerable');
  try {
    const observation = await labTransport(lab.origin, lab.documents.map(d => '/documents/' + d.id))(
      '/documents/' + lab.documents[0].id, 'account-a', lab.credentials['account-a']);
    const serialized = JSON.stringify(evidence(observation));
    assert.ok(!serialized.includes(lab.credentials['account-a']));
    assert.ok(!serialized.toLowerCase().includes('authorization'));
  } finally { await lab.close(); }
});

test('persist, reopen offline and regenerate the same report; refuse overwrite', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'bba-test-'));
  try {
    const folder = join(temp, 'case');
    const inv = await investigateLab('vulnerable');
    await saveInvestigation(folder, inv);
    assert.deepEqual(await loadInvestigation(folder), inv);
    const regenerated = join(temp, 'regenerated.md');
    await exportReport(folder, regenerated);
    assert.equal(await readFile(regenerated, 'utf8'), await readFile(join(folder, 'report.md'), 'utf8'));
    await assert.rejects(saveInvestigation(folder, inv), /already exists/);
    await assert.rejects(exportReport(folder, regenerated), /EEXIST/);
    await writeFile(join(folder, '.incomplete'), 'interrupted');
    await assert.rejects(loadInvestigation(folder), /incomplete/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('corruption, unsupported contracts, extra secrets and inconsistent conclusions fail validation', async () => {
  const inv = await investigateLab('fixed');
  const bundle = { investigation: inv, sha256: digest(inv) };
  const cases = [
    (b: any) => { b.investigation.evidence[1].document.marker = 'synthetic-' + '0'.repeat(32); },
    (b: any) => { b.investigation.schemaVersion = 2; },
    (b: any) => { b.investigation.evidence[0].token = 'SECRET'; },
    (b: any) => { b.investigation.findings[0].status = 'confirmed'; b.sha256 = digest(b.investigation); },
  ];
  for (const mutate of cases) {
    const bad = structuredClone(bundle); mutate(bad);
    assert.throws(() => verify(bad));
  }
});

test('CLI runs end to end and rejects arbitrary targets before output creation', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'bba-cli-'));
  const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
  const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 15000 });
  try {
    const folder = join(temp, 'fixed');
    const invalid = run(['lab', '--variant', 'fixed', '--out', folder, '--target', 'https://example.com']);
    assert.equal(invalid.status, 2);
    const valid = run(['lab', '--variant', 'fixed', '--out', folder]);
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(JSON.parse(valid.stdout).notReproduced, 2);
    const inspect = run(['inspect', folder]);
    assert.equal(inspect.status, 0, inspect.stderr);
    assert.equal(JSON.parse(inspect.stdout).confirmed, 0);
    const report = run(['report', folder, '--out', join(temp, 'export.md')]);
    assert.equal(report.status, 0, report.stderr);
    assert.equal(run(['lab', '--variant', 'fixed', '--out', folder]).status, 1);
  } finally { await rm(temp, { recursive: true, force: true }); }
});
