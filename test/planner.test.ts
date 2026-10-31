import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { access, readFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { compileInvestigation, prepareCompiled, investigateSurface, resumeInvestigation } from '../src/planner.ts';
import type { Profile } from '../src/planner.ts';
import { importSurface } from '../src/surface.ts';
import { digest } from '../src/contracts.ts';
import { semanticClasses, evaluateSemantic } from '../src/semantic.ts';
import type { SemanticClass } from '../src/semantic.ts';
import { inspectSession, createSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';

const profile = (origin: string, kind: SemanticClass): Profile => ({ schemaVersion: 1, accounts: ['BBA_TOKEN_A', 'BBA_TOKEN_B'],
  identity: { url: origin + '/me', fact: 'identity', observe: [{ name: 'identity', pointer: '/id' }, { name: 'role', pointer: '/role' }, { name: 'tenant', pointer: '/tenant' }] },
  rules: [{ class: kind, origin, pathPrefix: '/resources', protectedPointer: '/private', subjectPointer: kind === 'bola' ? '/owner' : kind === 'tenant-isolation' ? '/tenant' : null, query: [],
    policy: kind === 'bola' ? { reference: 'owned fixture private owner data', boundary: 'owner-only', ownerFact: 'owner' }
      : kind === 'tenant-isolation' ? { reference: 'owned fixture tenant data', boundary: 'tenant-private', tenantFact: 'tenant', resourceTenantFact: 'resource-tenant' }
      : { reference: 'owned fixture admin data', boundary: 'role-private', roleFact: 'role', baselineRole: 'admin', probeRole: 'member' } }] });
const bundle = (origin: string, paths: Record<string, unknown>) => {
  const surface = importSurface({ openapi: '3.0.3', info: {}, servers: [{ url: origin }], paths }, 'openapi');
  return { surface, sha256: digest(surface) };
};

for (const kind of semanticClasses) for (const vulnerable of [true, false]) test(`surface -> hypothesis -> controlled proof -> report: ${kind} ${vulnerable}`, async () => {
  const hits: string[] = [];
  await fixture((req, res) => {
    hits.push(req.url!);
    const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a' : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
    const json = (status: number, value: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (req.url === '/me') return json(200, { id: actor, role: actor === 'a' ? 'admin' : 'member', tenant: 'tenant-' + actor });
    if (!actor) return json(401, {});
    if (!vulnerable && actor === 'b') return json(403, {});
    json(200, { owner: 'a', tenant: 'tenant-a', private: 'SYNTHETIC_PROTECTED_VALUE', nonce: actor });
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/me', '/resources/first', '/resources/second'];
    const surface = bundle(origin, { '/resources/first': { get: {} }, '/resources/second': { get: {} }, '/excluded': { get: {} }, '/resources/{id}': { get: {} }, '/resources/create': { post: {} } });
    const p = profile(origin, kind);
    const compiled = compileInvestigation(scope, surface, p);
    assert.equal(hits.length, 0); assert.equal(compiled.checks.checks.length, 2); assert.equal(compiled.plan!.steps.length, 8);
    assert.ok(compiled.coverage.some(c => c.reason.includes('Concrete controlled URL')));
    assert.deepEqual(compileInvestigation(scope, surface, p), compiled, 'deterministic planning');
    const result = await investigateSurface(join(folder, 'case'), scope, surface, p, { credentials: { BBA_TOKEN_A: 'synthetic-a', BBA_TOKEN_B: 'synthetic-b' } });
    assert.equal(result.findings.filter(f => f.status === 'confirmed').length, vulnerable ? 1 : 0);
    assert.equal(result.requests, vulnerable ? 5 : 8); assert.equal(result.requests, hits.length);
    assert.equal(result.stopped, vulnerable ? 'proof-complete' : null);
    assert.ok(hits.every(path => ['/me', '/resources/first', '/resources/second'].includes(path)));
    if (vulnerable) assert.ok(result.findings.some(f => f.status === 'unresolved'));
    const text = await readFile(join(folder, 'case', 'report.md'), 'utf8');
    assert.match(text, /coverage.json/); assert.ok(!text.includes('SYNTHETIC_PROTECTED_VALUE'));
    assert.equal(inspectSession(join(folder, 'case', 'run')).attempts.length, result.requests);
    const coverage = JSON.parse(await readFile(join(folder, 'case', 'coverage.json'), 'utf8')); assert.equal(coverage.sha256, digest(coverage.coverage));
    assert.throws(() => prepareCompiled(join(folder, 'case'), scope, surface, p), /EEXIST/);
  });
});

test('planner preserves templates, budget gaps, query requirements and source integrity without sending traffic', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope, folder) => {
    const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/me', '/resources/known'];
    const surface = bundle(origin, { '/resources/{id}': { get: { parameters: [{ in: 'query', name: 'q', schema: { type: 'string' } }] } } });
    const p = profile(origin, 'bola');
    const entryId = surface.surface.entries[0].id;
    assert.equal(compileInvestigation(scope, surface, p).plan, null);
    p.bindings = [{ entryId, url: origin + '/resources/known' }];
    assert.equal(compileInvestigation(scope, surface, p).plan, null, 'query value is still unknown');
    p.rules[0].query = [{ name: 'q', valueEnv: 'BBA_INPUT_Q' }];
    scope.requestRules = [{ origin, path: '/resources/known', method: 'GET', queryNames: ['q'], bodyFormats: [] }];
    assert.equal(compileInvestigation(scope, surface, p).checks.checks.length, 1);
    scope.limits.maxRequests = 4;
    const r = prepareCompiled(join(folder, 'no-budget'), scope, surface, p); assert.equal(r.plan, null);
    const noRun = await investigateSurface(join(folder, 'case'), scope, surface, p);
    assert.equal(noRun.requests, 0); assert.equal(noRun.stopped, 'no-testable-hypotheses'); await assert.rejects(access(join(folder, 'case', 'run')));
    const corrupt = structuredClone(surface); corrupt.surface.entries[0].path = '/other'; assert.throws(() => compileInvestigation(scope, corrupt, p), /bundle/);
    p.rules[0].policy = { ...p.rules[0].policy, secret: 'never-accepted' } as any; assert.throws(() => compileInvestigation(scope, surface, p), /fields/);
    assert.equal(hits, 0);
  });
});

test('resuming a case reuses an already completed proof without another request', async () => {
  let hits = 0;
  await fixture((req, res) => {
    hits++;
    const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a' : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
    res.writeHead(!actor ? 401 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(req.url === '/me' ? { id: actor } : { owner: 'a', private: 'owned-test-data' }));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/me', '/resources/one', '/resources/two'];
    const config = profile(origin, 'bola'), source = bundle(origin, { '/resources/one': { get: {} }, '/resources/two': { get: {} } });
    const caseFolder = join(folder, 'case'), compiled = prepareCompiled(caseFolder, scope, source, config);
    createSession(join(caseFolder, 'run'), scope, compiled.plan!);
    const controller = new AbortController(), credentials = { BBA_TOKEN_A: 'synthetic-a', BBA_TOKEN_B: 'synthetic-b' };
    const paused = await executeSession(join(caseFolder, 'run'), scope, { credentials, signal: controller.signal, stopWhen: s => {
      if (evaluateSemantic(s, compiled.checks).findings.some(f => f.status === 'confirmed')) controller.abort(); return false;
    } });
    assert.equal(paused.status, 'paused'); assert.equal(hits, 5);
    const resumed = await resumeInvestigation(caseFolder, scope, join(folder, 'report.md'), { credentials });
    assert.equal(resumed.newRequests, 0); assert.equal(resumed.stopped, 'proof-complete'); assert.equal(hits, 5);
  });
});
