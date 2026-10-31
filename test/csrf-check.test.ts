import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { fixture } from './support.ts';
import { csrfCheck, validateCsrfCheck } from '../src/csrf-check.ts';
import type { CsrfCheck } from '../src/csrf-check.ts';
import { usingScopeBudget, inspectBudget } from '../src/budget.ts';

for (const vulnerable of [true, false]) test(`controlled cross-origin form: ${vulnerable ? 'state changes' : 'token required'}`, async () => {
  let value = 'before', actions = 0;
  const attacker = createServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body>owned attacker fixture</body></html>'); });
  await new Promise<void>(resolve => attacker.listen(0, '127.0.0.1', resolve));
  const attackerOrigin = 'http://127.0.0.1:' + (attacker.address() as { port: number }).port;
  try {
    await fixture(async (req, res) => {
      if (req.url === '/state') {
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ value })); return;
      }
      if (req.url === '/action' && req.method === 'POST') {
        actions++;
        if (req.headers.cookie !== 'sid=owned') { res.writeHead(403); res.end(); return; }
        if (!vulnerable && req.headers['x-csrf-token'] !== 'owned') { res.writeHead(403); res.end(); return; }
        let body = ''; for await (const chunk of req) body += chunk;
        value = new URLSearchParams(body).get('value') ?? value;
        res.writeHead(200); res.end(); return;
      }
      res.writeHead(404); res.end();
    }, async (scope, folder) => {
      const origin = scope.allowed[0].origin;
      scope.allowed[0].paths = ['/state', '/action'];
      scope.allowed.push({ origin: attackerOrigin, paths: ['/attacker'] });
      scope.requestRules = [{ origin, path: '/action', method: 'POST', queryNames: [], bodyFormats: ['form'] }];
      scope.budgetId = vulnerable ? 'csrf-vulnerable' : 'csrf-fixed'; scope.limits.maxRequests = 5;
      scope.limits.timeoutMs = 5000;
      const config: CsrfCheck = { schemaVersion: 1, class: 'cross-origin-form', policyReference: 'owner state requires user intent',
        attackerPageUrl: attackerOrigin + '/attacker', stateUrl: origin + '/state', actionUrl: origin + '/action',
        cookieEnv: 'BBA_COOKIE_CSRF', sameSite: 'Lax', formField: 'value', formValue: 'after',
        statePointer: '/value', beforeValue: 'before', afterValue: 'after' };
      process.env.BBA_COOKIE_CSRF = 'sid=owned';
      try {
        const result = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => csrfCheck(join(folder, 'check'), scope, config, { budget }));
        assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced', JSON.stringify(result));
        assert.equal(result.cookieDelivered, true);
        assert.equal(result.originMatched, true);
        assert.equal(value, vulnerable ? 'after' : 'before');
        assert.equal(actions, 2);
        assert.equal(inspectBudget(join(folder, '.bba-budgets', scope.budgetId)).reservedRequests, 5);
      } finally { delete process.env.BBA_COOKIE_CSRF; }
    });
  } finally { await new Promise<void>(resolve => { attacker.closeAllConnections(); attacker.close(() => resolve()); }); }
});

test('CSRF check rejects an undeclared form action before requests', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope) => {
    const origin = scope.allowed[0].origin;
    scope.allowed[0].paths = ['/state', '/action']; scope.limits.maxRequests = 5;
    scope.allowed.push({ origin: 'http://127.0.0.1:34567', paths: ['/attacker'] });
    const config: CsrfCheck = { schemaVersion: 1, class: 'cross-origin-form', policyReference: 'owner state requires user intent',
      attackerPageUrl: 'http://127.0.0.1:34567/attacker', stateUrl: origin + '/state', actionUrl: origin + '/action',
      cookieEnv: 'BBA_COOKIE_CSRF', sameSite: 'Lax', formField: 'value', formValue: 'after',
      statePointer: '/value', beforeValue: 'before', afterValue: 'after' };
    assert.throws(() => validateCsrfCheck(config, scope), /outside scope/);
    assert.equal(hits, 0);
  });
});
