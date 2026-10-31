import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createNetServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { PassThrough } from 'node:stream';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SafeError, digest, safeErrorMessage } from '../src/contracts.ts';
import { credentialFor, destination, destinationAddresses, RequestFailure, scopedRequest } from '../src/http.ts';
import { projectJson } from '../src/observations.ts';
import { samePath, isStrictSubpath, withSqliteLockSync } from '../src/paths.ts';
import { confine } from '../src/tools.ts';
import { serveMcp } from '../src/mcp.ts';
import { withProgramBudget, inspectBudget } from '../src/budget.ts';
import { csrfCheck } from '../src/csrf-check.ts';
import { mutateOwnedJwt } from '../src/jwt-integrity.ts';
import { compileStudy, validateStudyPolicy } from '../src/study.ts';
import { captureSurface, launchIsolated } from '../src/capture.ts';
import { strictUrl } from '../src/scope.ts';
import { importSurface } from '../src/surface.ts';
import type { Scope } from '../src/scope.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const hasBrowser = await launchIsolated().then(b => b.close().then(() => true), () => false);

function makeScope(origin: string, paths: string[], maxRequests = 10): Scope {
  return {
    schemaVersion: 1,
    mode: 'loopback-lab',
    authorization: {
      reference: 'BBA fixes test',
      validFrom: new Date(Date.now() - 5000).toISOString(),
      validUntil: new Date(Date.now() + 600_000).toISOString(),
    },
    allowed: [{ origin, paths }],
    excluded: [],
    limits: { maxRequests, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 20_000 },
  };
}

test('Fix #1: SafeError, safeErrorMessage y ayuda por comando en CLI', async () => {
  assert.equal(safeErrorMessage(new Error('Campaign blocked: scope, policy_review')), 'Campaign blocked: scope, policy_review');
  assert.equal(safeErrorMessage(new SafeError('Field [allowed.0.paths] failed: invalid_segment')), 'Field [allowed.0.paths] failed: invalid_segment');
  assert.equal(safeErrorMessage(Object.assign(new Error('ENOENT: C:\\secret\\file'), { code: 'ENOENT' })), 'Required file or directory does not exist');
  assert.equal(safeErrorMessage(new Error('<script>alert("secret")</script>')), 'Operation failed; check arguments and local artifact integrity');

  const { stdout } = await promisify(execFile)(process.execPath, [cli, 'jwt-check', '--help']);
  assert.match(stdout, /jwt-check --scope/);
  assert.doesNotMatch(stdout, /ssrf-callback-check/);
});

test('Fix #2: credentialFor acepta cookies RFC 6265 con pipes y dos puntos pero bloquea inyección', () => {
  const wp = 'wordpress_logged_in_0123=usuario|1799999999|token_seguro|hmac_hex; express:sess=s%3Aabc.sig';
  assert.deepEqual(credentialFor('BBA_COOKIE_WP', wp), { cookie: wp });
  for (const hostile of ['wp=a|b;injected=1', 'wp=a|b\r\nX-Evil: 1', 'wp=a b']) {
    assert.throws(() => credentialFor('BBA_COOKIE_WP', hostile), /Invalid credential format/);
  }
});

test('Fix #3: JSON Pointer RFC 6901 bloquea acceso a Array.length e índices con ceros a la izquierda', () => {
  const body = Buffer.from(JSON.stringify({ items: ['alpha', 'beta'] }));
  const fields = projectJson(body, 'application/json', [
    { name: 'len', pointer: '/items/length' },
    { name: 'leading-zero', pointer: '/items/01' },
    { name: 'first', pointer: '/items/0' },
  ]);
  assert.equal(fields[0].present, false);
  assert.equal(fields[0].kind, 'missing');
  assert.equal(fields[1].present, false);
  assert.equal(fields[2].present, true);
  assert.equal(fields[2].kind, 'string');
});

test('Fix #4: scopedRequest rechaza respuestas truncadas y destination soporta dual-stack público seguro', async () => {
  const rawServer = createNetServer(socket => {
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\ntruncated');
      socket.destroy();
    });
  });
  await new Promise<void>(r => rawServer.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(rawServer.address() as { port: number }).port}`;
  try {
    await assert.rejects(
      scopedRequest(makeScope(origin, ['/trunc']), origin + '/trunc'),
      (err: unknown) => err instanceof RequestFailure && err.code === 'incomplete-response',
    );
  } finally {
    rawServer.close();
  }

  const publicScope: Scope = { ...makeScope('https://dual.example.test', ['/']), mode: 'public-https' };
  const dual = await destinationAddresses(new URL('https://dual.example.test/'), publicScope, async () => [
    { address: '2606:4700:4700::1111', family: 6 },
    { address: '1.1.1.1', family: 4 },
  ] as any);
  assert.equal(dual.length, 2);
  assert.deepEqual(await destination(new URL('https://dual.example.test/'), publicScope, async () => [
    { address: '1.1.1.1', family: 4 },
  ] as any), { address: '1.1.1.1', family: 4 });

  await assert.rejects(
    destination(new URL('https://rebind.example.test/'), publicScope, async () => [
      { address: '1.1.1.1', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ] as any),
    (err: unknown) => err instanceof RequestFailure && err.code === 'address-blocked',
  );
});

test('Fix #5 y #6: locks transaccionales SQLite y normalización de rutas en Windows', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-fix56-'));
  try {
    const lockPath = join(dir, '.test.lock.sqlite');
    withSqliteLockSync(lockPath, 'Busy lock', () => {
      assert.throws(() => withSqliteLockSync(lockPath, 'Busy lock', () => 'never'), /Busy lock/);
    });
    assert.equal(withSqliteLockSync(lockPath, 'Busy lock', () => 'released'), 'released');

    if (process.platform === 'win32') {
      assert.equal(samePath(dir.toLowerCase(), dir.toUpperCase()), true);
      assert.equal(isStrictSubpath(dir.toLowerCase(), join(dir.toUpperCase(), 'nested', 'file.json')), true);
      const confined = confine(dir.toLowerCase());
      assert.ok(confined('sub/item.json').endsWith('item.json'));
      assert.throws(() => confined('../escape.json'), /outside the workspace root/);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Fix #7: MCP responde ping fuera de cola, acepta arguments omitidos y cancela tools/call en vuelo', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-mcp-fix7-'));
  const slowServer = createHttpServer((_req, res) => {
    const timer = setTimeout(() => { res.writeHead(200); res.end('slow'); }, 5000);
    res.on('close', () => clearTimeout(timer));
  });
  await new Promise<void>(r => slowServer.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(slowServer.address() as { port: number }).port}`;
  const input = new PassThrough();
  const output = new PassThrough();
  const responses = new Map<number | string, any>();
  let buf = '';
  output.on('data', chunk => {
    buf += chunk.toString();
    for (let idx = buf.indexOf('\n'); idx >= 0; idx = buf.indexOf('\n')) {
      const msg = JSON.parse(buf.slice(0, idx));
      buf = buf.slice(idx + 1);
      responses.set(msg.id, msg);
    }
  });
  const done = serveMcp({ root: dir, allowNetwork: true, input, output });
  try {
    await writeFile(join(dir, 'scope.json'), JSON.stringify(makeScope(origin, ['/slow'])));
    await writeFile(join(dir, 'plan.json'), JSON.stringify({
      schemaVersion: 1,
      steps: [{ id: 's1', method: 'GET', url: origin + '/slow', credentialEnv: null }],
    }));

    input.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'capabilities' } }) + '\n');
    while (!responses.has(1)) await new Promise(r => setTimeout(r, 10));
    assert.equal(responses.get(1).result.isError, false);

    const started = Date.now();
    input.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'run', arguments: { scope: 'scope.json', plan: 'plan.json', out: 'run1' } } }) + '\n');
    await new Promise(r => setTimeout(r, 80));
    input.write(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }) + '\n');
    while (!responses.has(3)) await new Promise(r => setTimeout(r, 10));
    assert.ok(Date.now() - started < 1500, 'ping answered immediately while run was still in flight');
    assert.equal(responses.has(2), false);

    input.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 2 } }) + '\n');
    while (!responses.has(2)) await new Promise(r => setTimeout(r, 10));
    assert.ok(Date.now() - started < 2500, 'notifications/cancelled aborted in-flight run promptly');
    assert.equal(JSON.parse(responses.get(2).result.content[0].text).status, 'paused');
  } finally {
    input.end();
    await done;
    slowServer.closeAllConnections();
    slowServer.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('Fix #8: beforeConcurrentPair permite cerrar reservas hermanas en orden FIFO sin dejarlas uncertain', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-fix8-'));
  try {
    const scope = { ...makeScope('http://127.0.0.1:9', ['/x']), budgetId: 'pair-fifo' };
    await withProgramBudget(dir, scope, async budget => {
      await budget.beforeConcurrentPair(['leg-1', 'leg-2']);
      budget.complete('leg-1');
      budget.complete('leg-2');
    });
    const inspected = inspectBudget(dir);
    assert.equal(inspected.uncertainRequests, 0);
    assert.equal(inspected.reservedRequests, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Fix #9: csrfCheck valida múltiples cookies sin depender del orden y reenvía todas al endpoint', { skip: !hasBrowser }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-fix9-'));
  let state = 'initial';
  let receivedCookie = '';
  const attacker = createHttpServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body>fixture</body></html>'); });
  const target = createHttpServer(async (req, res) => {
    if (req.url === '/state') {
      if (!req.headers.cookie) { res.writeHead(401); res.end(); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ state }));
      return;
    }
    if (req.url === '/update' && req.method === 'POST') {
      receivedCookie = req.headers.cookie ?? '';
      if (!receivedCookie.includes('sid=owned') || !receivedCookie.includes('pref=dark')) {
        res.writeHead(403); res.end(); return;
      }
      let body = '';
      for await (const chunk of req) body += chunk;
      state = new URLSearchParams(body).get('state') ?? state;
      res.writeHead(200); res.end('ok');
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>(r => attacker.listen(0, '127.0.0.1', r));
  await new Promise<void>(r => target.listen(0, '127.0.0.1', r));
  const attackerOrigin = `http://127.0.0.1:${(attacker.address() as { port: number }).port}`;
  const targetOrigin = `http://127.0.0.1:${(target.address() as { port: number }).port}`;
  try {
    const scope: Scope = {
      ...makeScope(targetOrigin, ['/state', '/update']),
      allowed: [{ origin: targetOrigin, paths: ['/state', '/update'] }, { origin: attackerOrigin, paths: ['/'] }],
      requestRules: [{ origin: targetOrigin, path: '/update', method: 'POST', queryNames: [], bodyFormats: ['form'] }],
    };
    const res = await csrfCheck(join(dir, 'csrf'), scope, {
      schemaVersion: 1,
      class: 'cross-origin-form',
      policyReference: 'owned multi-cookie csrf test',
      attackerPageUrl: attackerOrigin + '/',
      stateUrl: targetOrigin + '/state',
      actionUrl: targetOrigin + '/update',
      cookieEnv: 'BBA_COOKIE_MULTI',
      sameSite: 'Lax',
      formField: 'state',
      formValue: 'updated',
      statePointer: '/state',
      beforeValue: 'initial',
      afterValue: 'updated',
    }, { credentials: { BBA_COOKIE_MULTI: 'pref=dark; sid=owned' } });
    assert.equal(res.status, 'confirmed');
    assert.match(receivedCookie, /sid=owned/);
    assert.match(receivedCookie, /pref=dark/);
  } finally {
    attacker.closeAllConnections(); attacker.close();
    target.closeAllConnections(); target.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('Fix #10: mutateOwnedJwt conserva e infiere tipos JSON numéricos, booleanos y strings explícitos', () => {
  const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const token = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 'u1', tier: 1, active: false })}.sig_fija`;
  const baseCfg = {
    schemaVersion: 1 as const,
    policyReference: 'jwt type test',
    boundary: 'jwt-signature-integrity' as const,
    url: 'http://127.0.0.1:9/me',
    request: { method: 'GET' as const },
    credentialEnv: 'BBA_TOKEN_OWN',
    proofPointer: '/sub',
  };
  const mutatedNum = mutateOwnedJwt(token, { ...baseCfg, mutation: { mode: 'replace', claim: 'tier', valueEnv: 'BBA_INPUT_TIER' } }, { BBA_INPUT_TIER: '2' });
  const payloadNum = JSON.parse(Buffer.from(mutatedNum.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(payloadNum.tier, 2);

  const mutatedStr = mutateOwnedJwt(token, { ...baseCfg, mutation: { mode: 'replace', claim: 'tier', valueEnv: 'BBA_INPUT_TIER', valueType: 'string' } }, { BBA_INPUT_TIER: '2' });
  const payloadStr = JSON.parse(Buffer.from(mutatedStr.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(payloadStr.tier, '2');
});

test('Fix #11: StudyPolicy propaga requestHeaders identificatorios hacia el Scope compilado', () => {
  const policy = {
    schemaVersion: 1 as const,
    mode: 'public-https' as const,
    sourceUrl: 'https://program.example.test/policy',
    reviewedAt: '2026-10-30T00:00:00.000Z',
    authorization: {
      reference: 'study policy test',
      validFrom: new Date(Date.now() - 5000).toISOString(),
      validUntil: new Date(Date.now() + 600_000).toISOString(),
    },
    assets: [{ origin: 'https://api.example.test', pathPrefixes: ['/v1/profile', '/v1/orders'] }],
    excluded: [],
    requestHeaders: [{ origin: 'https://api.example.test', name: 'x-bug-bounty', valueEnv: 'BBA_HEADER_RESEARCHER' }],
    techniques: ['jwt-signature-integrity'] as ['jwt-signature-integrity'],
    budgetId: 'study-headers-test',
    limits: { maxRequests: 4, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 20_000 },
  };
  validateStudyPolicy(policy);
  const surface = importSurface({
    openapi: '3.0.0',
    servers: [{ url: 'https://api.example.test' }],
    security: [{ bearerAuth: [] }],
    paths: {
      '/v1/profile': { get: { responses: { '200': { description: 'ok' } } } },
      '/v1/orders': { get: { security: [{}, { bearerAuth: [] }], responses: { '200': { description: 'ok' } } } },
    },
  }, 'openapi');
  const compiled = compileStudy({
    schemaVersion: 1,
    case: { schemaVersion: 1, id: 'case-1', title: 'Test', author: 'DCS', published: '2026-01-01', sourceUrl: 'https://blog.example.test/post', class: 'jwt-signature-integrity', referenceOnly: true },
    policy,
    surface: { surface, sha256: digest(surface) },
    historical: { schemaVersion: 1, sourceUrl: 'https://web.archive.org/cdx', capturedAt: '2025-01-01T00:00:00.000Z', routes: [{ path: '/v1/orders', clue: 'endpoint-reference' }] },
    profile: { schemaVersion: 1, credentialEnv: 'BBA_TOKEN_OWN', request: { method: 'GET' }, mutation: { mode: 'replace', claim: 'sub', valueEnv: 'BBA_INPUT_SUB' }, proofPointer: '/owner' },
  });
  assert.deepEqual(compiled.scope?.requestHeaders, policy.requestHeaders);
});

test('Fix #12: captureSurface corta de inmediato ante AbortSignal durante la espera de intervalo', { skip: !hasBrowser }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-fix12-'));
  const srv = createHttpServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(req.url === '/page' ? '<html><body><script>fetch("/sub")</script></body></html>' : 'ok');
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
  try {
    const scope: Scope = {
      ...makeScope(origin, ['/page', '/sub']),
      limits: { maxRequests: 5, minIntervalMs: 8000, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 20_000 },
    };
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 350);
    const start = Date.now();
    const { capture } = await captureSurface(join(dir, 'cap'), scope, {
      schemaVersion: 1,
      steps: [{ id: 'p', method: 'GET', url: origin + '/page', credentialEnv: null }],
    }, { signal: controller.signal });
    assert.equal(capture.stopReason, 'cancelled');
    assert.ok(Date.now() - start < 5000, 'aborted without waiting full 8000ms interval');
  } finally {
    srv.closeAllConnections(); srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('Fix #13: strictUrl e importSurface aceptan pchar RFC 3986 canónicos (: y @ en ruta) y bloquean traversal/userinfo', () => {
  assert.equal(strictUrl('https://api.example.test/v1/users:batchGet/@me').pathname, '/v1/users:batchGet/@me');
  const surface = importSurface({
    log: {
      version: '1.2',
      entries: [{ request: { method: 'POST', url: 'https://api.example.test/v1/users:batchGet/@me', headers: [], queryString: [] }, response: { status: 200 } }],
    },
  }, 'har');
  assert.equal(surface.entries[0].path, '/v1/users:batchGet/@me');

  for (const forbidden of [
    'https://user@api.example.test/v1/users',
    'https://api.example.test/v1%2Fadmin',
    'https://api.example.test/v1/%2e%2e/admin',
    'https://api.example.test/v1//admin',
  ]) {
    assert.throws(() => strictUrl(forbidden), / URL|non-canonical|Invalid/);
  }
});

