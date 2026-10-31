import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateScope } from '../src/scope.ts';
import type { Scope } from '../src/scope.ts';
import { identifyingHeaders } from '../src/headers.ts';
import { scopedRequest } from '../src/http.ts';
import { createSession, inspectSession, exportSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import { captureSurface } from '../src/capture.ts';
import { hunt } from '../src/hunt.ts';

const scope = (): Scope => ({ schemaVersion: 1, mode: 'public-https',
  authorization: { reference: 'synthetic header tests', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() },
  allowed: [{ origin: 'https://one.example', paths: ['/'] }, { origin: 'https://two.example', paths: ['/'] }], excluded: [],
  limits: { maxRequests: 3, minIntervalMs: 0, timeoutMs: 1000, maxResponseBytes: 4096, maxDurationMs: 10000 },
  requestHeaders: [{ origin: 'https://one.example', name: 'x-researcher-id', valueEnv: 'BBA_HEADER_RESEARCHER' }] });

test('identifying headers validate exact origin, allowed names, duplicates and value references', () => {
  validateScope(scope());
  for (const change of [
    { name: 'authorization' }, { name: 'cookie' }, { name: 'host' }, { name: 'connection' },
    { name: 'User-Agent' }, { name: 'x-marker\r\ninjected' }, { origin: 'https://outside.example' },
    { valueEnv: 'BBA_TOKEN_A' }, { value: 'literal-value' },
  ]) {
    const s = scope(); Object.assign(s.requestHeaders![0], change); assert.throws(() => validateScope(s));
  }
  const s = scope(); s.requestHeaders!.push(s.requestHeaders![0]); assert.throws(() => validateScope(s), /Duplicate/);
  const env = { BBA_HEADER_RESEARCHER: 'synthetic-private-researcher' };
  assert.deepEqual(identifyingHeaders(scope(), 'https://two.example', env), {});
  assert.deepEqual(identifyingHeaders(scope(), 'https://one.example', env), { 'x-researcher-id': env.BBA_HEADER_RESEARCHER });
  for (const value of ['', '\r\ninjected', '\u0000', 'x'.repeat(513), 'unicode-ñ']) {
    assert.throws(() => identifyingHeaders(scope(), 'https://one.example', { BBA_HEADER_RESEARCHER: value }), /invalid/);
  }
});

test('run sends identifying headers only to their origin and never persists values', async () => {
  const hits: { marker?: string; ua?: string; authorization?: string }[][] = [[], []];
  const servers = hits.map(list => createServer((req, res) => { list.push({ marker: req.headers['x-researcher-id'] as string, ua: req.headers['user-agent'], authorization: req.headers.authorization }); res.end('ok'); }));
  for (const server of servers) await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origins = servers.map(s => 'http://127.0.0.1:' + (s.address() as { port: number }).port);
  const root = await mkdtemp(join(tmpdir(), 'bba-headers-'));
  const s = scope(); s.mode = 'loopback-lab'; s.allowed = origins.map(origin => ({ origin, paths: ['/'] }));
  s.requestHeaders = [{ origin: origins[0], name: 'x-researcher-id', valueEnv: 'BBA_HEADER_RESEARCHER' }, { origin: origins[0], name: 'user-agent', valueEnv: 'BBA_HEADER_UA' }];
  const env = { BBA_HEADER_RESEARCHER: 'private-synthetic-researcher', BBA_HEADER_UA: 'private-synthetic-agent', BBA_TOKEN_A: 'synthetic-token' };
  try {
    const plan = { schemaVersion: 1 as const, steps: origins.map((origin, i) => ({ id: 'seed-' + i, method: 'GET' as const, url: origin + '/', credentialEnv: i ? null : 'BBA_TOKEN_A' })) };
    createSession(join(root, 'run'), s, plan);
    await assert.rejects(executeSession(join(root, 'run'), s, { credentials: {} }), /identifying header/);
    assert.equal(inspectSession(join(root, 'run')).attempts.length, 0);
    assert.deepEqual(hits, [[], []]);
    const result = await executeSession(join(root, 'run'), s, { credentials: env });
    assert.equal(result.status, 'completed');
    assert.deepEqual(hits, [[{ marker: env.BBA_HEADER_RESEARCHER, ua: env.BBA_HEADER_UA, authorization: 'Bearer ' + env.BBA_TOKEN_A }], [{ marker: undefined, ua: undefined, authorization: undefined }]]);
    exportSession(join(root, 'run'), join(root, 'report.md'), 'markdown');
    for (const file of [...(await readdir(join(root, 'run'))).map(f => join(root, 'run', f)), join(root, 'report.md')]) {
      const bytes = await readFile(file);
      for (const value of Object.values(env)) assert.equal(bytes.includes(Buffer.from(value)), false, file);
    }
    await assert.rejects(scopedRequest(s, origins[0] + '/', { environment: {} }), /invalid-identifying-header/);
    const config = { schemaVersion: 1 as const, seed: origins[0] + '/', identityUrl: origins[0] + '/', identityField: 'id', ownerField: 'owner', privateField: 'privateValue', accounts: ['BBA_TOKEN_A', 'BBA_TOKEN_B'] as [string, string], boundary: 'owner-only' as const };
    await assert.rejects(hunt(join(root, 'hunt'), s, config, { credentials: {} }), /identifying header/);
    await assert.rejects(captureSurface(join(root, 'capture'), s, plan, { credentials: {} }), /identifying header/);
    assert.deepEqual(hits.map(list => list.length), [1, 1]);
  } finally {
    for (const server of servers) await new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); });
    await rm(root, { recursive: true, force: true });
  }
});
