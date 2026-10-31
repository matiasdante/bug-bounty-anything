import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { fixture } from './support.ts';
import { ssrfCallbackCheck, validateSsrfCallback } from '../src/ssrf-callback.ts';
import type { SsrfCallback } from '../src/ssrf-callback.ts';
import { usingScopeBudget, inspectBudget } from '../src/budget.ts';

for (const vulnerable of [true, false]) test(`owned callback proof: ${vulnerable ? 'outbound fetch' : 'no fetch'}`, async () => {
  let seen = false, inbound = 0, triggerHits = 0;
  const receiver = createServer((req, res) => {
    if (req.url === '/cb/opaqueProof123456') { seen = true; inbound++; res.end('ok'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ seen }));
  });
  await new Promise<void>(resolve => receiver.listen(0, '127.0.0.1', resolve));
  const receiverOrigin = 'http://127.0.0.1:' + (receiver.address() as { port: number }).port;
  try {
    await fixture(async (req, res) => {
      triggerHits++;
      const callback = new URL(req.url!, 'http://fixture').searchParams.get('url');
      if (vulnerable && callback) await fetch(callback);
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{}');
    }, async (scope, folder) => {
      const origin = scope.allowed[0].origin;
      scope.budgetId = vulnerable ? 'ssrf-vulnerable' : 'ssrf-fixed'; scope.limits.maxRequests = 4;
      scope.allowed.push({ origin: receiverOrigin, paths: ['/cb/opaqueProof123456', '/receipt'] });
      scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['url'], bodyFormats: [] }];
      const config: SsrfCallback = { schemaVersion: 1, class: 'outbound-fetch', policyReference: 'no arbitrary external fetch',
        triggerUrl: origin + '/', queryName: 'url', credentialEnv: null,
        callbackUrl: receiverOrigin + '/cb/opaqueProof123456', receiptUrl: receiverOrigin + '/receipt', receiptPointer: '/seen' };
      const result = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => ssrfCallbackCheck(join(folder, 'check'), scope, config, { budget }));
      assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced');
      assert.equal(triggerHits, 1); assert.equal(inbound, vulnerable ? 1 : 0);
      assert.equal(inspectBudget(join(folder, '.bba-budgets', scope.budgetId)).reservedRequests, vulnerable ? 3 : 4);
    });
  } finally { await new Promise<void>(resolve => { receiver.closeAllConnections(); receiver.close(() => resolve()); }); }
});

test('callback proof refuses an undeclared receiver before sending requests', async () => {
  await fixture((_req, res) => res.end(), async (scope) => {
    const origin = scope.allowed[0].origin;
    scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['url'], bodyFormats: [] }];
    const config: SsrfCallback = { schemaVersion: 1, class: 'outbound-fetch', policyReference: 'no external fetch',
      triggerUrl: origin + '/', queryName: 'url', credentialEnv: null,
      callbackUrl: 'http://127.0.0.1:34567/cb/opaqueProof123456', receiptUrl: 'http://127.0.0.1:34567/receipt', receiptPointer: '/seen' };
    assert.throws(() => validateSsrfCallback(config, scope), /declared in scope/);
  });
});
