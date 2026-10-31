import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readdir, readFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { methods, validateScope, validatePlan } from '../src/scope.ts';
import type { Plan } from '../src/scope.ts';
import { createSession, inspectSession, exportSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import { resolveRequest } from '../src/requests.ts';
import { scopedRequest } from '../src/http.ts';
import { projectJson, validateFacts, validateProjections } from '../src/observations.ts';

test('HTTP methods, encoded query values and JSON/form/text bodies obey exact request rules', async () => {
  const received: any[] = [];
  await fixture(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    received.push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString(), type: req.headers['content-type'] });
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ result: { id: 'synthetic-private-response' } }));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.requestRules = methods.map(method => ({ origin, path: '/', method, queryNames: ['search'], bodyFormats: ['GET', 'HEAD'].includes(method) ? [] : ['json', 'form', 'text'] }));
    const steps: Plan['steps'] = methods.map((method, i) => ({ id: 'method-' + i, method, url: origin + '/', credentialEnv: null,
      query: [{ name: 'search', valueEnv: 'BBA_INPUT_SEARCH' }],
      ...(['GET', 'HEAD'].includes(method) ? {} : { body: { format: 'json' as const, valueEnv: 'BBA_BODY_JSON' } }),
      observe: [{ name: 'id', pointer: '/result/id' }] }));
    steps.push(...(['form', 'text'] as const).map(format => ({ id: format, method: 'POST' as const, url: origin + '/', credentialEnv: null, body: { format, valueEnv: 'BBA_BODY_' + format.toUpperCase() } })));
    const plan: Plan = { schemaVersion: 1, steps }; validateScope(scope); validatePlan(plan, scope);
    const env = { BBA_INPUT_SEARCH: 'private-query &?#/ñ', BBA_BODY_JSON: '{"value":"private-json"}', BBA_BODY_FORM: 'value=private-form', BBA_BODY_TEXT: 'private-text' };
    createSession(join(folder, 'run'), scope, plan);
    const state = await executeSession(join(folder, 'run'), scope, { credentials: env });
    assert.equal(state.status, 'completed'); assert.equal(received.length, 9);
    for (let i = 0; i < methods.length; i++) {
      assert.equal(received[i].method, methods[i]);
      assert.equal(new URL(received[i].url, origin).searchParams.get('search'), env.BBA_INPUT_SEARCH);
      assert.equal(new URL(received[i].url, origin).pathname, '/');
      assert.equal(received[i].body, ['GET', 'HEAD'].includes(methods[i]) ? '' : env.BBA_BODY_JSON);
    }
    assert.equal(received[7].type, 'application/x-www-form-urlencoded'); assert.equal(received[7].body, env.BBA_BODY_FORM);
    assert.equal(received[8].body, env.BBA_BODY_TEXT);
    assert.equal(state.attempts[0].response!.facts![0].meaningful, true);
    assert.equal(state.attempts[1].response!.facts![0].kind, 'unavailable', 'HEAD has no JSON body');
    exportSession(join(folder, 'run'), join(folder, 'export.json'), 'json');
    for (const file of [...(await readdir(join(folder, 'run'))).map(f => join(folder, 'run', f)), join(folder, 'export.json')]) {
      const bytes = await readFile(file);
      for (const secret of [...Object.values(env), 'synthetic-private-response']) assert.ok(!bytes.includes(Buffer.from(secret)));
    }
    assert.equal(inspectSession(join(folder, 'run')).inputDigest, state.inputDigest);
  });
});

test('unsupported inputs, methods, exclusions and missing variables cannot reach the network', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end('ok'); }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    const post = { id: 'post', method: 'POST' as const, url: origin + '/', credentialEnv: null, body: { format: 'json' as const, valueEnv: 'BBA_BODY_JSON' } };
    const plan: Plan = { schemaVersion: 1, steps: [post] };
    assert.throws(() => validatePlan(plan, scope), /outside scope/);
    scope.requestRules = [{ origin, path: '/', method: 'POST', queryNames: ['safe'], bodyFormats: ['json'] }];
    validatePlan(plan, scope);
    for (const mutation of [
      { method: 'CONNECT' }, { url: origin + '/?safe=x' }, { body: { format: 'json', valueEnv: 'MY_SECRET' } },
      { query: [{ name: 'not-allowed', valueEnv: 'BBA_INPUT_X' }] }, { body: { format: 'text', valueEnv: 'BBA_BODY_JSON' } },
    ]) assert.throws(() => validatePlan({ schemaVersion: 1, steps: [{ ...post, ...mutation }] }, scope));
    createSession(join(folder, 'run'), scope, plan);
    for (const env of [{}, { BBA_BODY_JSON: 'invalid' }, { BBA_BODY_JSON: 'x'.repeat(65537) }]) {
      await assert.rejects(executeSession(join(folder, 'run'), scope, { credentials: env }));
      assert.equal(inspectSession(join(folder, 'run')).attempts.length, 0);
    }
    await assert.rejects(scopedRequest(scope, origin + '/', { request: { method: 'DELETE' } }), /invalid-request-input/);
    scope.excluded = [{ origin, paths: ['/'] }]; assert.throws(() => validateScope(scope), /outside scope/);
    assert.equal(hits, 0);
  });
});

test('paused plans bind all input values and refuse changed inputs without replaying anything', async () => {
  let hits = 0;
  const controller = new AbortController();
  await fixture((_req, res) => { hits++; controller.abort(); res.end('ok'); }, async (scope, folder) => {
    const origin = scope.allowed[0].origin;
    scope.requestRules = [{ origin, path: '/', method: 'GET', queryNames: ['q'], bodyFormats: [] }];
    const plan: Plan = { schemaVersion: 1, steps: ['first', 'second'].map(id => ({ id, method: 'GET', url: origin + '/', credentialEnv: null, query: [{ name: 'q', valueEnv: 'BBA_INPUT_Q' }] })) };
    createSession(join(folder, 'run'), scope, plan);
    const env = { BBA_INPUT_Q: 'original-private-query' };
    const paused = await executeSession(join(folder, 'run'), scope, { credentials: env, signal: controller.signal });
    assert.equal(paused.status, 'paused'); assert.equal(hits, 1);
    await assert.rejects(executeSession(join(folder, 'run'), scope, { credentials: { BBA_INPUT_Q: 'different' } }), /inputs changed/);
    assert.equal(hits, 1);
    const completed = await executeSession(join(folder, 'run'), scope, { credentials: env });
    assert.equal(completed.attempts.length, 2); assert.equal(hits, 2);
  });
});

test('JSON pointers distinguish missing, null, malformed and meaningful values without retaining contents', () => {
  const projections = [{ name: 'secret', pointer: '/a~1b/~0key/0' }, { name: 'missing', pointer: '/missing' }, { name: 'null', pointer: '/empty' }];
  const facts = projectJson(Buffer.from('{"a/b":{"~key":["private-value"]},"empty":null}'), 'application/problem+json; charset=utf-8', projections);
  validateFacts(facts, projections);
  assert.equal(facts[0].kind, 'string'); assert.ok(facts[0].meaningful);
  assert.equal(facts[1].kind, 'missing'); assert.equal(facts[2].kind, 'null');
  assert.ok(!JSON.stringify(facts).includes('private-value'));
  assert.equal(projectJson(Buffer.from('{}'), 'text/html', projections)[0].kind, 'unavailable');
  assert.equal(projectJson(Buffer.from('{'), 'application/json', projections)[0].kind, 'unavailable');
  for (const pointer of ['not-a-pointer', '/bad~2', '/bad~']) assert.throws(() => validateProjections([{ name: 'a', pointer }]));
  const corrupt = structuredClone(facts); corrupt[1].meaningful = true; assert.throws(() => validateFacts(corrupt, projections));
});
