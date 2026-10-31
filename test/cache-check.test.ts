import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fixture } from './support.ts';
import { cacheCheck, validateCacheCheck } from '../src/cache-check.ts';
import type { CacheCheck } from '../src/cache-check.ts';
import { usingScopeBudget, inspectBudget } from '../src/budget.ts';

for (const vulnerable of [true, false]) test(`controlled cache exposure: ${vulnerable ? 'cross-account leak' : 'segmented'}`, async () => {
  let hits = 0, primed = false;
  await fixture((req, res) => {
    hits++;
    const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a'
      : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
    const url = new URL(req.url!, 'http://fixture');
    let status = 200, body: object = {};
    if (url.pathname === '/me') body = { id: actor };
    else if (url.searchParams.has('bust')) {
      if (actor === 'a') body = { private: 'owned-a-value' };
      else status = actor ? 403 : 401;
    } else if (!actor) status = 401;
    else if (actor === 'a') { primed = true; body = { private: 'owned-a-value' }; }
    else if (vulnerable && primed) body = { private: 'owned-a-value' };
    else status = 403;
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.allowed[0].paths = ['/me', '/resource']; scope.budgetId = vulnerable ? 'cache-leak' : 'cache-fixed';
    scope.limits.maxRequests = 7;
    scope.requestRules = [{ origin, path: '/resource', method: 'GET', queryNames: ['bust'], bodyFormats: [] }];
    const config: CacheCheck = { schemaVersion: 1, class: 'cross-identity-cache', policyReference: 'private resource owner only',
      identityUrl: origin + '/me', identityPointer: '/id', resourceUrl: origin + '/resource', protectedPointer: '/private',
      accountA: 'BBA_TOKEN_CACHE_A', accountB: 'BBA_TOKEN_CACHE_B', bustQueryName: 'bust',
      bustTokens: ['opaqueBustTokenA123', 'opaqueBustTokenB456'] };
    process.env.BBA_TOKEN_CACHE_A = 'synthetic-a'; process.env.BBA_TOKEN_CACHE_B = 'synthetic-b';
    try {
      const result = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => cacheCheck(join(folder, 'check'), scope, config, { budget }));
      assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced');
      assert.equal(hits, 7);
      assert.equal(inspectBudget(join(folder, '.bba-budgets', scope.budgetId)).reservedRequests, 7);
    } finally { delete process.env.BBA_TOKEN_CACHE_A; delete process.env.BBA_TOKEN_CACHE_B; }
  });
});

test('cache check rejects an undeclared bust parameter before requests', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope) => {
    const origin = scope.allowed[0].origin;
    scope.allowed[0].paths = ['/me', '/resource']; scope.limits.maxRequests = 7;
    const config: CacheCheck = { schemaVersion: 1, class: 'cross-identity-cache', policyReference: 'private resource owner only',
      identityUrl: origin + '/me', identityPointer: '/id', resourceUrl: origin + '/resource', protectedPointer: '/private',
      accountA: 'BBA_TOKEN_CACHE_A', accountB: 'BBA_TOKEN_CACHE_B', bustQueryName: 'bust',
      bustTokens: ['opaqueBustTokenA123', 'opaqueBustTokenB456'] };
    assert.throws(() => validateCacheCheck(config, scope), /outside scope/);
    assert.equal(hits, 0);
  });
});
