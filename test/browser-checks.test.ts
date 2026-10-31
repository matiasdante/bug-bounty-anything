import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fixture } from './support.ts';
import { browserCheck } from '../src/browser-checks.ts';
import type { BrowserCheck } from '../src/browser-checks.ts';
import { artifactView } from '../src/artifacts.ts';

for (const variant of ['vulnerable', 'escaped', 'csp', 'budget']) test(`actual browser XSS proof: ${variant}`, async () => {
  const received: string[] = [];
  await fixture((req, res) => {
    received.push(req.url!);
    const input = new URL(req.url!, 'http://fixture').searchParams.get('q') ?? '';
    res.writeHead(200, { 'Content-Type': 'text/html', ...(variant === 'csp' ? { 'Content-Security-Policy': "script-src 'none'" } : {}) });
    const text = variant === 'escaped' ? input.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;') : input;
    res.end('<html><body>' + text + '</body></html>');
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['q'], bodyFormats: [] }];
    if (variant === 'budget') scope.limits.maxRequests = 1;
    const config: BrowserCheck = { schemaVersion: 1, class: 'xss', boundary: 'untrusted-input-script', policyReference: 'owned synthetic reflected input', resources: [], observationMs: 100,
      markerEnv: 'BBA_INPUT_MARKER', baseline: { id: 'baseline', method: 'GET', url: origin + '/', credentialEnv: null, query: [{ name: 'q', valueEnv: 'BBA_INPUT_BASELINE' }] },
      probe: { id: 'probe', method: 'GET', url: origin + '/', credentialEnv: null, query: [{ name: 'q', valueEnv: 'BBA_INPUT_PROBE' }] } };
    const env = { BBA_INPUT_BASELINE: 'benign-test-text', BBA_INPUT_MARKER: 'synthetic_unique_marker_123', BBA_INPUT_PROBE: "<script>window.__bbaProof('synthetic_unique_marker_123')</script>" };
    const result = await browserCheck(join(folder, 'check'), scope, config, { credentials: env });
    assert.equal(result.status, variant === 'vulnerable' ? 'confirmed' : variant === 'budget' ? 'unresolved' : 'not-reproduced', JSON.stringify(result));
    assert.equal(result.requests, received.length); assert.ok(result.requests <= scope.limits.maxRequests);
    assert.equal(artifactView(join(folder, 'check'), { kind: 'summary', offset: 0, limit: 10 }).artifactKind, 'browser-check');
    for (const file of await readdir(join(folder, 'check'))) {
      const text = await readFile(join(folder, 'check', file), 'utf8'); assert.ok(!text.includes(env.BBA_INPUT_MARKER)); assert.ok(!text.includes(env.BBA_INPUT_PROBE));
    }
  });
});

for (const variant of ['vulnerable', 'wildcard', 'no-credentials', 'public', 'expired', 'filtered']) test(`actual browser CORS proof: ${variant}`, async () => {
  let hits = 0;
  await fixture((req, res) => {
    hits++;
    if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html>owned application</html>'); return; }
    const origin = req.headers.origin;
    const cors: Record<string, string> = origin ? { 'Access-Control-Allow-Origin': variant === 'wildcard' ? '*' : origin,
      ...(variant === 'no-credentials' ? {} : { 'Access-Control-Allow-Credentials': 'true' }) } : {};
    const authenticated = req.headers.cookie === 'sid=synthetic-cookie';
    if (!authenticated && variant !== 'public') { res.writeHead(401, { 'Content-Type': 'application/json', ...cors }); res.end('{}'); return; }
    const foreign = !!origin && origin !== ('http://' + req.headers.host);
    res.writeHead(foreign && variant === 'expired' ? 401 : 200, { 'Content-Type': 'application/json', ...cors });
    res.end(JSON.stringify(foreign && variant === 'filtered' ? {} : { private: 'SYNTHETIC_PRIVATE_CORS_VALUE' }));
  }, async (scope, folder) => {
    const foreign = createServer((_req, res) => { hits++; res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html>controlled foreign origin</html>'); });
    await new Promise<void>(resolve => foreign.listen(0, '127.0.0.1', resolve));
    try {
      const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/', '/api'];
      const attacker = 'http://127.0.0.1:' + (foreign.address() as { port: number }).port;
      scope.allowed.push({ origin: attacker, paths: ['/'] });
      const config: BrowserCheck = { schemaVersion: 1, class: 'cors', boundary: 'private-cross-origin-read', policyReference: 'owned private test field', resources: [], observationMs: 100,
        baseline: { id: 'app', method: 'GET', url: origin + '/', credentialEnv: 'BBA_COOKIE_A' },
        probe: { id: 'foreign', method: 'GET', url: attacker + '/', credentialEnv: null }, target: { id: 'api', method: 'GET', url: origin + '/api', credentialEnv: 'BBA_COOKIE_A' },
        protectedPointer: '/private', cookie: { origin, valueEnv: 'BBA_COOKIE_A', sameSite: 'Lax' } };
      const result = await browserCheck(join(folder, 'check'), scope, config, { credentials: { BBA_COOKIE_A: 'sid=synthetic-cookie' } });
      assert.equal(result.status, variant === 'vulnerable' ? 'confirmed' : ['public', 'expired'].includes(variant) ? 'unresolved' : 'not-reproduced', JSON.stringify(result));
      assert.equal(result.requests, hits);
      for (const file of await readdir(join(folder, 'check'))) {
        const text = await readFile(join(folder, 'check', file), 'utf8');
        assert.ok(!text.includes('SYNTHETIC_PRIVATE_CORS_VALUE')); assert.ok(!text.includes('sid=synthetic-cookie'));
      }
    } finally { await new Promise<void>(resolve => { foreign.closeAllConnections(); foreign.close(() => resolve()); }); }
  });
});
