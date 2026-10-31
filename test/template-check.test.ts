import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { templateCheck, resumeTemplateCheck, validateTemplateCheck } from '../src/template-check.ts';
import type { TemplateCheck } from '../src/template-check.ts';
import { usingScopeBudget, inspectBudget } from '../src/budget.ts';

for (const vulnerable of [true, false]) test(`template arithmetic proof: ${vulnerable ? 'evaluated' : 'literal'}`, async () => {
  let hits = 0;
  await fixture((req, res) => {
    hits++;
    const input = new URL(req.url!, 'http://fixture').searchParams.get('q') ?? '';
    const value = vulnerable ? input.replace(/^\{\{(\d+)\*(\d+)\}\}$/, (_all, a, b) => String(Number(a) * Number(b))) : input;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ output: value }));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.budgetId = vulnerable ? 'template-vulnerable' : 'template-fixed';
    scope.limits.maxRequests = 3;
    scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['q'], bodyFormats: [] }];
    const config: TemplateCheck = { schemaVersion: 1, class: 'template-arithmetic', policyReference: 'literal search field',
      url: origin + '/', parameter: 'q', pointer: '/output', operands: [17, 23, 31], credentialEnv: null };
    const output = join(folder, 'proof');
    const result = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => templateCheck(output, scope, config, { budget }));
    assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced');
    assert.equal(hits, 3);
    assert.equal(inspectBudget(join(folder, '.bba-budgets', scope.budgetId)).reservedRequests, 3);
    const report = await readFile(join(output, 'template-check.md'), 'utf8');
    assert.match(report, /## Demostración de explotabilidad/);
    const replay = await readFile(join(output, 'template-check.json'), 'utf8');
    assert.doesNotMatch(replay, /BBA_TOKEN_|Authorization|Cookie/);
  });
});

test('template check refuses undeclared inputs and resumes only pending steps', async () => {
  let hits = 0;
  await fixture((req, res) => { hits++; const value = new URL(req.url!, 'http://fixture').searchParams.get('q');
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ output: value }));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.budgetId = 'template-resume'; scope.limits.maxRequests = 3;
    const config: TemplateCheck = { schemaVersion: 1, class: 'template-arithmetic', policyReference: 'literal search field',
      url: origin + '/', parameter: 'q', pointer: '/output', operands: [13, 19, 29], credentialEnv: null };
    assert.throws(() => validateTemplateCheck(config, scope), /outside scope/);
    assert.equal(hits, 0);
    scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['q'], bodyFormats: [] }];
    const abort = new AbortController(); abort.abort();
    const output = join(folder, 'proof');
    const paused = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => templateCheck(output, scope, config, { budget, signal: abort.signal }));
    assert.equal(paused.status, 'unresolved'); assert.equal(hits, 0);
    const altered = { ...config, operands: [13, 19, 37] as [number, number, number] };
    await assert.rejects(() => resumeTemplateCheck(output, scope, altered), /definition changed/);
    assert.equal(hits, 0);
    const resumed = await usingScopeBudget(scope, join(folder, 'scope.json'), budget => resumeTemplateCheck(output, scope, config, { budget }));
    assert.equal(resumed.status, 'not-reproduced'); assert.equal(hits, 3);
  });
});
