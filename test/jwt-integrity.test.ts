import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { join } from 'node:path';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { jwtIntegrityCheck, mutateOwnedJwt, validateJwtIntegrity, evaluateJwtIntegrityFile } from '../src/jwt-integrity.ts';
import { inspectSession } from '../src/session.ts';
import type { JwtIntegrityConfig } from '../src/jwt-integrity.ts';

const secret = 'fixture-signing-key-with-entropy';
const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
function jwt() {
  const header = part({ alg: 'HS256', typ: 'JWT' }), payload = part({ sub: 'owned-test-account', aud: 'fixture-api' });
  return `${header}.${payload}.${createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url')}`;
}
function config(url: string): JwtIntegrityConfig {
  return { schemaVersion: 1, policyReference: 'owned fixture policy', boundary: 'jwt-signature-integrity',
    url, request: { method: 'POST', body: { format: 'json', valueEnv: 'BBA_BODY_QUERY' } },
    credentialEnv: 'BBA_TOKEN_OWNED', proofPointer: '/result', mutation: { claim: 'bba_probe', mode: 'add-canary' } };
}

for (const vulnerable of [true, false]) test(`JWT integrity ${vulnerable ? 'confirms unverified signature' : 'rejects altered signature'} with owned fixture`, async () => {
  let hits = 0;
  await fixture(async (req, res) => {
    hits++;
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    const pieces = token.split('.');
    let accepted = false;
    if (pieces.length === 3 && body === '{"query":"SELECT 1","rowLimit":1}') {
      try {
        const payload = JSON.parse(Buffer.from(pieces[1], 'base64url').toString());
        accepted = payload.sub === 'owned-test-account' && payload.aud === 'fixture-api'
          && (vulnerable || createHmac('sha256', secret).update(`${pieces[0]}.${pieces[1]}`).digest('base64url') === pieces[2]);
      } catch { /* anonymous control */ }
    }
    res.writeHead(accepted ? 200 : 401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(accepted ? { result: 1 } : { error: 'denied' }));
  }, async (scope, folder) => {
    const url = scope.allowed[0].origin + '/';
    scope.requestRules = [{ origin: scope.allowed[0].origin, path: '/', method: 'POST', queryNames: [], bodyFormats: ['json'] }];
    const c = config(url), token = jwt(), env = { BBA_TOKEN_OWNED: token, BBA_BODY_QUERY: '{"query":"SELECT 1","rowLimit":1}' };
    validateJwtIntegrity(c, scope);
    const result = await jwtIntegrityCheck(join(folder, 'jwt'), scope, c, { environment: env });
    assert.equal(result.status, vulnerable ? 'confirmed' : 'not-reproduced', JSON.stringify({ result, session: inspectSession(join(folder, 'jwt', 'run')) }));
    assert.equal(hits, 4);
    assert.equal(inspectSession(join(folder, 'jwt', 'run')).attempts.length, 4);
    const output = await readFile(join(folder, 'jwt', 'result.json'), 'utf8');
    const sqlite = await readFile(join(folder, 'jwt', 'run', 'session.sqlite'));
    for (const value of [token, 'owned-test-account', env.BBA_BODY_QUERY, 'fixture-signing-key']) {
      assert.ok(!output.includes(value)); assert.ok(!sqlite.includes(Buffer.from(value)));
    }
    assert.equal((await readdir(join(folder, 'jwt'))).includes('result.json'), true);
    const report = await readFile(join(folder, 'jwt', 'report.md'), 'utf8');
    assert.match(report, /firma inválida|no está demostrado/);
    assert.ok(!report.includes(token));
    await writeFile(join(folder, 'config.json'), JSON.stringify(c));
    const offline = evaluateJwtIntegrityFile(join(folder, 'jwt', 'run'), join(folder, 'config.json'), join(folder, 'offline.json'));
    assert.equal(offline.status, result.status);
    const markdown = evaluateJwtIntegrityFile(join(folder, 'jwt', 'run'), join(folder, 'config.json'), join(folder, 'offline.md'));
    assert.equal(markdown.status, result.status);
    assert.match(await readFile(join(folder, 'offline.md'), 'utf8'), /Reproducción acotada/);
  });
});

test('JWT check validates signed format and exact request rule before sending', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope, folder) => {
    const c = config(scope.allowed[0].origin + '/');
    assert.throws(() => validateJwtIntegrity(c, scope), /outside scope/);
    scope.requestRules = [{ origin: scope.allowed[0].origin, path: '/', method: 'POST', queryNames: [], bodyFormats: ['json'] }];
    validateJwtIntegrity(c, scope);
    const token = jwt();
    assert.throws(() => mutateOwnedJwt(token.replace(/.$/, 'x').split('.').slice(0, 2).join('.'), c), /Expected signed/);
    assert.throws(() => mutateOwnedJwt(token, { ...c, mutation: { claim: 'sub', mode: 'add-canary' } }), /already exists/);
    const replaced = mutateOwnedJwt(token, { ...c, mutation: { claim: 'sub', mode: 'replace', valueEnv: 'BBA_INPUT_OWN_VALUE' } }, { BBA_INPUT_OWN_VALUE: 'owned-other-value' });
    assert.equal(replaced.split('.')[2], token.split('.')[2]);
    assert.equal(JSON.parse(Buffer.from(replaced.split('.')[1], 'base64url').toString()).sub, 'owned-other-value');
    assert.throws(() => mutateOwnedJwt(token, { ...c, mutation: { claim: 'sub', mode: 'replace', valueEnv: 'BBA_INPUT_OWN_VALUE' } }, { BBA_INPUT_OWN_VALUE: 'owned-test-account' }), /unchanged/);
    await assert.rejects(jwtIntegrityCheck(join(folder, 'missing'), scope, c, { environment: { BBA_TOKEN_OWNED: 'bad' } }));
    assert.equal(hits, 0);
  });
});

test('JWT resume requires same original token and does not replay a paused reservation', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.writeHead(401, { 'Content-Type': 'application/json' }); res.end('{}'); }, async (scope, folder) => {
    const c: JwtIntegrityConfig = { ...config(scope.allowed[0].origin + '/'), request: { method: 'GET' } };
    const env = { BBA_TOKEN_OWNED: jwt() };
    const controller = new AbortController(); controller.abort();
    const first = await jwtIntegrityCheck(join(folder, 'jwt'), scope, c, { environment: env, signal: controller.signal });
    assert.equal(first.status, 'unresolved'); assert.equal(hits, 0);
    await assert.rejects(jwtIntegrityCheck(join(folder, 'jwt'), scope, c, { environment: { BBA_TOKEN_OWNED: jwt() + 'x' }, resume: true }), /inputs changed|Invalid/);
    assert.equal(hits, 0);
    const resumed = await jwtIntegrityCheck(join(folder, 'jwt'), scope, c, { environment: env, resume: true });
    assert.equal(resumed.status, 'unresolved'); assert.equal(hits, 4, JSON.stringify(inspectSession(join(folder, 'jwt', 'run'))));
  });
});

test('JWT resume binds the replacement claim value before any request', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.writeHead(401); res.end(); }, async (scope, folder) => {
    const c: JwtIntegrityConfig = { ...config(scope.allowed[0].origin + '/'), request: { method: 'GET' },
      mutation: { claim: 'sub', mode: 'replace', valueEnv: 'BBA_INPUT_OWN_VALUE' } };
    const env = { BBA_TOKEN_OWNED: jwt(), BBA_INPUT_OWN_VALUE: 'owned-other-value' };
    const controller = new AbortController(); controller.abort();
    await jwtIntegrityCheck(join(folder, 'jwt'), scope, c, { environment: env, signal: controller.signal });
    await assert.rejects(jwtIntegrityCheck(join(folder, 'jwt'), scope, c, {
      environment: { ...env, BBA_INPUT_OWN_VALUE: 'owned-different-value' }, resume: true,
    }), /inputs changed/);
    assert.equal(hits, 0);
  });
});
