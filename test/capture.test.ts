import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { captureSurface } from '../src/capture.ts';
import type { Plan, Scope } from '../src/scope.ts';

const browser = await chromium.launch({ headless: true }).then(b => b.close().then(() => true), () => false);
const skip = browser ? false : 'Chromium headless shell missing: npx playwright-core install --only-shell chromium';
const token = 'capture-test-token-0123456789';

async function listen(handler: (url: string, method: string, auth?: string) => [number, string, string]) {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url} ${req.headers.authorization ?? '-'}`);
    const [status, type, body] = handler(req.url ?? '', req.method ?? '', req.headers.authorization);
    res.writeHead(status, { 'Content-Type': type }); res.end(body);
  });
  server.on('upgrade', (req, socket) => { hits.push(`UPGRADE ${req.url}`); socket.destroy(); });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  return { origin: `http://127.0.0.1:${port}`, hits, close: () => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }) as Promise<void>, server: server as Server };
}

async function fixture() {
  const other = await listen(() => [200, 'text/plain', 'other']);
  const app = await listen(url => url === '/app' ? [200, 'text/html', `<!doctype html><script>
    fetch('/api/doc/42'); fetch('/api/admin'); fetch('/api/doc/42', { method: 'POST' });
    fetch('${other.origin}/leak'); try { new WebSocket('${other.origin.replace('http', 'ws')}/ws'); } catch {}
  </script>`] : url === '/api/doc/42' ? [200, 'application/json', '{"id":42}'] : [404, 'text/plain', 'no']);
  const scope = (maxRequests: number, mode: Scope['mode'] = 'loopback-lab'): Scope => ({
    schemaVersion: 1, mode,
    authorization: { reference: 'BBA capture test', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
    allowed: [{ origin: app.origin, paths: ['/app', '/api/doc/42'] }], excluded: [],
    limits: { maxRequests, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 20000 },
  });
  const plan: Plan = { schemaVersion: 1, steps: [{ id: 'app', method: 'GET', url: app.origin + '/app', credentialEnv: 'BBA_TOKEN_A' }] };
  const dir = await mkdtemp(join(tmpdir(), 'bba-capture-'));
  return { app, other, scope, plan, dir, close: async () => { await app.close(); await other.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('browser capture sends only exact in-scope GETs with the plan token and blocks everything else', { skip }, async () => {
  const f = await fixture();
  try {
    const out = join(f.dir, 'run');
    const { capture, surface } = await captureSurface(out, f.scope(10), f.plan, { credentials: { BBA_TOKEN_A: token } });
    assert.deepEqual(f.app.hits.sort(), [`GET /api/doc/42 Bearer ${token}`, `GET /app Bearer ${token}`]);
    assert.deepEqual(f.other.hits, [], 'other origin and WebSocket never contacted');
    assert.equal(capture.stopReason, null);
    assert.equal(capture.counts.sent, 2);
    assert.ok(capture.counts.blocked >= 3, JSON.stringify(capture.counts));
    assert.equal(capture.counts['websocket-blocked'], 1, 'WebSocket intercepted by BBA, not left to chance');
    const sent = surface.entries.filter((_, i) => capture.outcomes[i] === 'sent');
    assert.deepEqual(sent.map(e => `${e.path} ${e.status} ${e.authentication}`).sort(),
      ['/api/doc/{opaque} 200 credential-present', '/app 200 credential-present']);
    assert.ok(surface.entries.some(e => e.method === 'POST' && e.status === null));
    for (const file of ['surface.json', 'capture.json']) assert.doesNotMatch(await readFile(join(out, file), 'utf8'), new RegExp(token));
    await assert.rejects(captureSurface(out, f.scope(10), f.plan, { credentials: { BBA_TOKEN_A: token } }), /already exists/);
  } finally { await f.close(); }
});

test('capture refuses public scopes and missing tokens before launching a browser', async () => {
  const f = await fixture();
  try {
    const publicScope = { ...f.scope(5), mode: 'public-https' as const, allowed: [{ origin: 'https://example.com', paths: ['/app'] }] };
    const publicPlan: Plan = { schemaVersion: 1, steps: [{ ...f.plan.steps[0], url: 'https://example.com/app' }] };
    await assert.rejects(captureSurface(join(f.dir, 'a'), publicScope, publicPlan, { credentials: { BBA_TOKEN_A: token } }), /loopback-lab/);
    await assert.rejects(captureSurface(join(f.dir, 'b'), f.scope(5), f.plan, { credentials: {} }), /Missing credential/);
    assert.deepEqual(f.app.hits, []);
  } finally { await f.close(); }
});

test('CLI capture stops at the request budget and exits 1 without sending more', { skip }, async () => {
  const f = await fixture();
  try {
    await writeFile(join(f.dir, 'scope.json'), JSON.stringify(f.scope(1)));
    await writeFile(join(f.dir, 'plan.json'), JSON.stringify(f.plan));
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const result = await promisify(execFile)(process.execPath,
      [cli, 'capture', '--scope', join(f.dir, 'scope.json'), '--plan', join(f.dir, 'plan.json'), '--out', join(f.dir, 'run')],
      { env: { ...process.env, BBA_TOKEN_A: token } }).then(r => ({ code: 0, ...r }), e => e);
    assert.equal(result.code, 1, result.stderr);
    assert.equal(JSON.parse(result.stdout).stopReason, 'budget-exhausted');
    assert.deepEqual(f.app.hits, [`GET /app Bearer ${token}`]);
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(token));
  } finally { await f.close(); }
});
