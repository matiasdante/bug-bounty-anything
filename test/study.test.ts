import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { digest } from '../src/contracts.ts';
import { readJson } from '../src/session.ts';
import { importSurface } from '../src/surface.ts';
import { compileStudy, executeStudy, prepareStudy } from '../src/study.ts';
import type { StudyBundle } from '../src/study.ts';
import { inspectBudget, usingScopeBudget } from '../src/budget.ts';

const caseFile = fileURLToPath(new URL('../cases/faav-titan-jwt-2026.json', import.meta.url));
const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const exec = promisify(execFile);
const secret = 'synthetic-private-signing-secret';
const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
function token() {
  const a = part({ alg: 'HS256', typ: 'JWT' }), b = part({ sub: 'owned-research-account', aud: 'study-fixture' });
  return `${a}.${b}.${createHmac('sha256', secret).update(`${a}.${b}`).digest('base64url')}`;
}
function bundle(origin: string, optionalPaths = ['/v2/Query']): StudyBundle {
  const u = new URL(origin);
  const paths: Record<string, unknown> = { '/GetConfiguration': { get: {} }, '/v2/Insert': { post: {} } };
  for (const path of optionalPaths) paths[path] = { post: { security: [], parameters: [{ in: 'body', name: 'query' }] } };
  const surface = importSurface({ swagger: '2.0', host: u.host, schemes: [u.protocol.slice(0, -1)], security: [{ bearer: [] }], paths }, 'openapi');
  const now = Date.now();
  return { schemaVersion: 1, case: readJson(caseFile) as StudyBundle['case'],
    policy: { schemaVersion: 1, mode: 'loopback-lab', sourceUrl: origin + '/program-policy', reviewedAt: new Date(now).toISOString(),
      authorization: { reference: 'owned disposable fixture policy', validFrom: new Date(now - 1000).toISOString(), validUntil: new Date(now + 600000).toISOString() },
      assets: [{ origin, pathPrefixes: ['/v2'] }], excluded: [{ origin, pathPrefixes: ['/v2/Insert'] }],
      techniques: ['jwt-signature-integrity'], budgetId: 'study-titan-fixture',
      limits: { maxRequests: 4, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 } },
    surface: { surface, sha256: digest(surface) },
    historical: { schemaVersion: 1, sourceUrl: 'https://web.archive.org/web/20230101000000/https://fixture.example/privacy',
      capturedAt: '2023-01-01T00:00:00.000Z', routes: [{ path: '/v2/Query', clue: 'routing-definition' }] },
    profile: { schemaVersion: 1, credentialEnv: 'BBA_TOKEN_OWNED', proofPointer: '/result',
      request: { method: 'POST', body: { format: 'json', valueEnv: 'BBA_BODY_QUERY' } }, mutation: { claim: 'bba_probe', mode: 'add-canary' } } };
}
function accepts(auth: string | undefined, vulnerable: boolean): boolean {
  const pieces = auth?.replace(/^Bearer /, '').split('.') ?? [];
  if (pieces.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(pieces[1], 'base64url').toString());
    return payload.sub === 'owned-research-account' && payload.aud === 'study-fixture'
      && (vulnerable || createHmac('sha256', secret).update(`${pieces[0]}.${pieces[1]}`).digest('base64url') === pieces[2]);
  } catch { return false; }
}

for (const vulnerable of [true, false]) test(`published Titan-style study: ${vulnerable ? 'vulnerable' : 'corrected'} fixture`, async () => {
  let hits = 0;
  await fixture(async (req, res) => {
    hits++;
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const ok = req.method === 'POST' && req.url === '/v2/Query' && body === '{"query":"SELECT 1","tableName":"OwnedTestData","rowLimit":1}'
      && accepts(req.headers.authorization, vulnerable);
    res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(ok ? { result: 1 } : { error: 'denied' }));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin, input = bundle(origin), env = { BBA_TOKEN_OWNED: token(),
      BBA_BODY_QUERY: '{"query":"SELECT 1","tableName":"OwnedTestData","rowLimit":1}' };
    const plan = compileStudy(input);
    assert.equal(plan.status, 'ready'); assert.equal(plan.candidates.length, 1);
    assert.equal(plan.selected, plan.candidates[0].id);
    assert.deepEqual(plan.scope?.allowed[0].paths, ['/v2/Query']);
    assert.equal(plan.graph.edges.some(e => e.relation === 'hints'), true);
    prepareStudy(join(folder, 'offline'), input); assert.equal(hits, 0);
    const inputPath = join(folder, 'study-input.json'); await writeFile(inputPath, JSON.stringify(input));
    const result = await usingScopeBudget(plan.scope!, inputPath, budget => executeStudy(join(folder, 'active'), input, { budget, environment: env }));
    assert.equal(result.result?.status, vulnerable ? 'confirmed' : 'not-reproduced');
    assert.equal(hits, 4);
    const budget = inspectBudget(join(folder, '.bba-budgets', input.policy.budgetId));
    assert.equal(budget.reservedRequests, 4); assert.equal(budget.uncertainRequests, 0);
    const report = await readFile(result.report!, 'utf8');
    for (const title of ['Qué es', 'Cómo se encontró', 'Demostración de explotación', 'Cómo reproducirlo', 'Cómo corregirlo']) assert.ok(report.includes(title));
    for (const secretValue of [env.BBA_TOKEN_OWNED, env.BBA_BODY_QUERY, secret, 'owned-research-account']) assert.ok(!report.includes(secretValue));
    assert.match(report, vulnerable ? /control anónimo fue denegado/ : /No hay vulnerabilidad confirmada/);
    const saved = await readFile(join(folder, 'active', 'jwt', 'run', 'session.sqlite'));
    assert.ok(!saved.includes(Buffer.from(env.BBA_TOKEN_OWNED)));
    assert.equal((await executeStudy(join(folder, 'active'), input, { budget: undefined, environment: env, resume: true }).catch(e => e.message)),
      'Shared program budget runtime is required');
  });
});

test('ambiguous or excluded declared routes remain offline and unresolved', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    const ambiguous = bundle(origin, ['/v2/Query', '/v2/Other']);
    ambiguous.historical.routes = [];
    assert.equal(compileStudy(ambiguous).status, 'unresolved');
    const output = await executeStudy(join(folder, 'ambiguous'), ambiguous);
    assert.equal(output.result, null); assert.equal(hits, 0);
    assert.match(await readFile(output.report!, 'utf8'), /No se eligió un candidato único/);
    const excluded = bundle(origin);
    excluded.policy.excluded.push({ origin, pathPrefixes: ['/v2/Query'] });
    assert.equal(compileStudy(excluded).candidates.length, 0);
    assert.equal(hits, 0);
  });
});

test('a changed study bundle is rejected before resuming', async () => {
  await fixture((_req, res) => { res.end(); }, async (scope, folder) => {
    const input = bundle(scope.allowed[0].origin), plan = compileStudy(input), env = { BBA_TOKEN_OWNED: token(), BBA_BODY_QUERY: '{}' };
    const controller = new AbortController(); controller.abort();
    const inputPath = join(folder, 'study-input.json'); await writeFile(inputPath, JSON.stringify(input));
    const first = await usingScopeBudget(plan.scope!, inputPath, budget => executeStudy(join(folder, 'case'), input,
      { budget, environment: env, signal: controller.signal }));
    assert.equal(first.result?.status, 'unresolved'); assert.equal(first.report, null);
    const changed = structuredClone(input); changed.historical.routes = [];
    await assert.rejects(usingScopeBudget(plan.scope!, inputPath, budget => executeStudy(join(folder, 'case'), changed,
      { budget, environment: env, resume: true })), /integrity mismatch/);
  });
});

test('CLI assembles, plans and runs a published case with a bounded local proof', async () => {
  let hits = 0;
  await fixture(async (req, res) => {
    hits++;
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const accepted = req.method === 'POST' && req.url === '/v2/Query' && accepts(req.headers.authorization, true);
    res.writeHead(accepted ? 200 : 401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(accepted ? { result: 1 } : { error: 'denied' }));
  }, async (scope, folder) => {
    const input = bundle(scope.allowed[0].origin);
    for (const part of ['policy', 'surface', 'historical', 'profile'] as const)
      await writeFile(join(folder, part + '.json'), JSON.stringify(input[part]));
    const bundleFile = join(folder, 'bundle.json'), planFolder = join(folder, 'plan'), runFolder = join(folder, 'run');
    const args = [
      ['study-bundle', '--case', caseFile, '--policy', join(folder, 'policy.json'), '--surface', join(folder, 'surface.json'),
        '--historical', join(folder, 'historical.json'), '--profile', join(folder, 'profile.json'), '--out', bundleFile],
      ['study-plan', '--input', bundleFile, '--out', planFolder],
      ['study-run', '--input', bundleFile, '--out', runFolder]
    ];
    const env = { ...process.env, BBA_TOKEN_OWNED: token(), BBA_BODY_QUERY: '{"query":"SELECT 1","tableName":"OwnedTestData","rowLimit":1}' };
    for (let i = 0; i < args.length; i++) {
      const { stdout } = await exec(process.execPath, [cli, ...args[i]], { env });
      assert.ok(!stdout.includes(env.BBA_TOKEN_OWNED));
      if (i < 2) assert.equal(hits, 0);
      if (i === 2) assert.equal(JSON.parse(stdout).status, 'confirmed');
    }
    assert.equal(hits, 4);
    assert.match(await readFile(join(runFolder, 'report.md'), 'utf8'), /Cómo corregirlo/);
  });
});
