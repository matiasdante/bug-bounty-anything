import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { credentialFor, scopedRequest, RequestFailure } from '../src/http.ts';
import type { Scope } from '../src/scope.ts';

test('credentialFor maps env names to Bearer or Cookie and rejects header-injection shapes', () => {
  assert.deepEqual(credentialFor('BBA_TOKEN_A', 'abc.def-123'), { token: 'abc.def-123' });
  assert.deepEqual(credentialFor('BBA_COOKIE_A', 'sid=abc123; csrf=x%20y'), { cookie: 'sid=abc123; csrf=x%20y' });
  for (const bad of ['sid=a\r\nX: y', 'sid=a;b=c', 'novalue', 'sid=a; ', '', 'sid=' + 'a'.repeat(2049)])
    assert.throws(() => credentialFor('BBA_COOKIE_A', bad), /Invalid credential format/, bad);
  assert.throws(() => credentialFor('BBA_TOKEN_A', 'a b'), /Invalid credential format/);
});

test('scopedRequest sends Cookie without Authorization and refuses both together', async () => {
  const seen: Record<string, string | undefined>[] = [];
  const server = createServer((req, res) => { seen.push({ auth: req.headers.authorization, cookie: req.headers.cookie }); res.end('ok'); });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab',
    authorization: { reference: 'cookie test', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() },
    allowed: [{ origin, paths: ['/x'] }], excluded: [],
    limits: { maxRequests: 5, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 1024, maxDurationMs: 60000 } };
  try {
    await scopedRequest(scope, origin + '/x', { cookie: 'sid=abc' });
    await scopedRequest(scope, origin + '/x', { token: 'tok' });
    assert.deepEqual(seen, [{ auth: undefined, cookie: 'sid=abc' }, { auth: 'Bearer tok', cookie: undefined }]);
    await assert.rejects(scopedRequest(scope, origin + '/x', { token: 'tok', cookie: 'sid=abc' }), (e: unknown) => e instanceof RequestFailure && e.code === 'invalid-credential');
    assert.equal(seen.length, 2, 'rejected before any connection');
  } finally { server.closeAllConnections(); server.close(); }
});
