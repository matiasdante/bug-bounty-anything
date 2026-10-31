import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { join } from 'node:path';
import { fixture } from './support.ts';
import { raceCheck, validateRaceCheck } from '../src/race-check.ts';
import type { RaceCheck } from '../src/race-check.ts';
import { usingScopeBudget, inspectBudget } from '../src/budget.ts';
import { artifactView } from '../src/artifacts.ts';

for (const vulnerable of [true, false]) test(`single-use race: ${vulnerable ? 'double effect' : 'atomic guard'}`, async () => {
  let controlCount = 0, raceCount = 0, hits = 0;
  await fixture(async (req, res) => {
    hits++;
    if (req.headers.authorization !== 'Bearer synthetic-race') { res.writeHead(401); res.end(); return; }
    if (req.url === '/state/control' || req.url === '/state/race') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ uses: req.url.endsWith('control') ? controlCount : raceCount })); return;
    }
    let text = ''; for await (const chunk of req) text += chunk;
    const body = JSON.parse(text);
    if (body.resourceId === 'controlOwned123') {
      if (controlCount) { res.writeHead(409); res.end(); return; }
      controlCount++; res.writeHead(200); res.end(); return;
    }
    if (body.resourceId === 'raceOwned456') {
      if (raceCount) { res.writeHead(409); res.end(); return; }
      if (vulnerable) { await delay(80); raceCount++; res.writeHead(200); res.end(); }
      else { raceCount++; await delay(80); res.writeHead(200); res.end(); }
      return;
    }
    res.writeHead(400); res.end();
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.allowed[0].paths = ['/state/control', '/state/race', '/redeem'];
    scope.requestRules = [{ origin, path: '/redeem', method: 'POST', queryNames: [], bodyFormats: ['json'] }];
    scope.budgetId = vulnerable ? 'race-vulnerable' : 'race-fixed'; scope.limits.maxRequests = 7;
    const config: RaceCheck = { schemaVersion: 1, class: 'single-use-race', policyReference: 'one redemption per owned resource',
      credentialEnv: 'BBA_TOKEN_RACE', actionUrl: origin + '/redeem', actionField: 'resourceId',
      controlResourceId: 'controlOwned123', raceResourceId: 'raceOwned456',
      controlStateUrl: origin + '/state/control', raceStateUrl: origin + '/state/race', countPointer: '/uses' };
    const output = join(folder, 'check');
    process.env.BBA_TOKEN_RACE = 'synthetic-race';
    try {
      const result = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => raceCheck(output, scope, config, { budget }));
      assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced');
      assert.equal(result.overlap, true);
      assert.equal(raceCount, vulnerable ? 2 : 1);
      assert.equal(controlCount, 1); assert.equal(hits, 7);
      assert.equal(inspectBudget(join(folder, '.bba-budgets', scope.budgetId)).reservedRequests, 7);
      assert.equal(artifactView(output, { kind: 'summary', offset: 0, limit: 5 }).artifactKind, 'race-check');
    } finally { delete process.env.BBA_TOKEN_RACE; }
  });
});

test('race check rejects spacing and unsupported state changes before requests', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope) => {
    const origin = scope.allowed[0].origin;
    scope.allowed[0].paths = ['/state/control', '/state/race', '/redeem']; scope.limits.maxRequests = 7;
    const config: RaceCheck = { schemaVersion: 1, class: 'single-use-race', policyReference: 'one redemption per owned resource',
      credentialEnv: 'BBA_TOKEN_RACE', actionUrl: origin + '/redeem', actionField: 'resourceId',
      controlResourceId: 'controlOwned123', raceResourceId: 'raceOwned456',
      controlStateUrl: origin + '/state/control', raceStateUrl: origin + '/state/race', countPointer: '/uses' };
    assert.throws(() => validateRaceCheck(config, scope), /outside scope/);
    scope.requestRules = [{ origin, path: '/redeem', method: 'POST', queryNames: [], bodyFormats: ['json'] }];
    scope.limits.minIntervalMs = 100;
    assert.throws(() => validateRaceCheck(config, scope), /zero interval/);
    assert.equal(hits, 0);
  });
});
