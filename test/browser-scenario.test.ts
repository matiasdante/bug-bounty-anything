import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readdir, readFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { captureScenario } from '../src/browser-scenario.ts';
import type { BrowserScenario } from '../src/browser-scenario.ts';
import { digest } from '../src/contracts.ts';
import { createServer } from 'node:http';
import { artifactView } from '../src/artifacts.ts';

for (const variant of ['workflow', 'wrong-body', 'undeclared-redirect', 'preserved-post-redirect']) test(`isolated browser workflow and session rotation: ${variant}`, async () => {
  const hits: { path: string; cookie: string; body: string; authorization: string }[] = [];
  await fixture(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString(); hits.push({ path: req.url!, cookie: req.headers.cookie ?? '', body, authorization: req.headers.authorization ?? '' });
    const html = (text: string) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(text); };
    if (req.url === '/') {
      res.setHeader('Set-Cookie', 'start=one; Path=/; HttpOnly; SameSite=Lax');
      return html('<form method="POST" action="/login"><input name="username" id="username"><input type="password" name="password" id="password"><button id="submit">login</button></form>');
    }
    if (req.url === '/login') {
      if (body !== 'username=own-user&password=synthetic-private-password' || !req.headers.cookie?.includes('start=one')) { res.writeHead(403); res.end(); return; }
      res.writeHead(variant === 'preserved-post-redirect' ? 307 : 302, { Location: variant === 'undeclared-redirect' ? '/outside' : '/dashboard', 'Set-Cookie': ['sid=first-private-session; Path=/; HttpOnly; SameSite=Lax', 'csrf=private-csrf; Path=/; SameSite=Lax'] }); res.end(); return;
    }
    if (req.url === '/dashboard') {
      if (!req.headers.cookie?.includes('sid=first-private-session')) { res.writeHead(403); res.end(); return; }
      return html('<button id="rotate" onclick="go()">rotate</button><div id="identity"></div><script>async function go(){await fetch("/rotate",{method:"POST",headers:{"content-type":"application/json"},body:"{}"});const r=await fetch("/me",{headers:{Authorization:"Bearer SYNTHETIC_BROWSER_PRIVATE_TOKEN"}});const d=await r.json();document.querySelector("#identity").textContent=d.id;document.querySelector("#identity").setAttribute("data-ready","yes");}</script>');
    }
    if (req.url === '/rotate') { res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'sid=second-private-session; Path=/; HttpOnly; SameSite=Lax' }); res.end('{}'); return; }
    if (req.url === '/me') { res.writeHead(req.headers.cookie?.includes('sid=second-private-session') && req.headers.authorization === 'Bearer SYNTHETIC_BROWSER_PRIVATE_TOKEN' ? 200 : 401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ id: 'private-controlled-user' })); return; }
    res.writeHead(404); res.end();
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/', '/login', '/dashboard', '/rotate', '/me'];
    scope.requestRules = ['/login', '/rotate'].map(path => ({ origin, path, method: 'POST', queryNames: [], bodyFormats: path === '/login' ? ['form'] : ['json'] }));
    const config: BrowserScenario = { schemaVersion: 1, boundary: 'controlled-workflow', policyReference: 'owned disposable login and cookie rotation', sessionOrigin: origin, maxRedirects: 1,
      plan: { schemaVersion: 1, steps: [
        { id: 'home', method: 'GET', url: origin + '/', credentialEnv: null },
        { id: 'login', method: 'POST', url: origin + '/login', credentialEnv: null, body: { format: 'form', valueEnv: 'BBA_BODY_LOGIN' } },
        { id: 'dashboard', method: 'GET', url: origin + '/dashboard', credentialEnv: null },
        { id: 'rotate', method: 'POST', url: origin + '/rotate', credentialEnv: null, body: { format: 'json', valueEnv: 'BBA_BODY_ROTATE' } },
        { id: 'me', method: 'GET', url: origin + '/me', credentialEnv: null, observe: [{ name: 'identity', pointer: '/id' }] },
      ] }, actions: [{ kind: 'navigate', stepId: 'home' }, { kind: 'fill', selector: '#username', valueEnv: 'BBA_INPUT_USERNAME' }, { kind: 'fill', selector: '#password', valueEnv: 'BBA_INPUT_PASSWORD' },
        { kind: 'click', selector: '#submit' }, { kind: 'wait', selector: '#rotate' }, { kind: 'click', selector: '#rotate' }, { kind: 'wait', selector: '#identity[data-ready="yes"]' }],
      observe: [{ name: 'identity', selector: '#identity', attribute: null }] };
    const env = { BBA_INPUT_USERNAME: 'own-user', BBA_INPUT_PASSWORD: 'synthetic-private-password', BBA_BODY_LOGIN: variant === 'wrong-body' ? 'username=different&password=other' : 'username=own-user&password=synthetic-private-password', BBA_BODY_ROTATE: '{}' };
    const result = await captureScenario(join(folder, 'scenario'), scope, config, { credentials: env });
    if (variant === 'workflow') {
      assert.equal(result.status, 'completed', JSON.stringify({ result, journal: await readFile(join(folder, 'scenario', 'requests.jsonl'), 'utf8') })); assert.equal(result.requests, 5);
      assert.equal(result.redirects, 1); assert.equal(result.setCookieCount, 4); assert.equal(result.completedActions, 7);
      assert.equal(result.facts[0].sha256, digest('private-controlled-user'));
      assert.ok(hits.find(h => h.path === '/me')!.cookie.includes('sid=second-private-session'));
      assert.equal(hits.find(h => h.path === '/me')!.authorization, 'Bearer SYNTHETIC_BROWSER_PRIVATE_TOKEN');
      assert.ok(hits.find(h => h.path === '/dashboard')!.cookie.includes('csrf=private-csrf'));
      const summary = artifactView(join(folder, 'scenario'), { kind: 'summary', offset: 0, limit: 20 });
      assert.equal(summary.artifactKind, 'scenario');
      const fields: any = artifactView(join(folder, 'scenario'), { kind: 'fields', offset: 0, limit: 20 });
      assert.equal(fields.items[0].fact.name, 'identity');
    } else if (variant === 'wrong-body') { assert.equal(result.status, 'unresolved'); assert.ok(result.blocked > 0); assert.equal(hits.length, 1); }
    else if (variant === 'preserved-post-redirect') { assert.equal(result.status, 'unresolved'); assert.ok(result.blocked > 0); assert.ok(!hits.some(h => h.path === '/dashboard')); }
    else { assert.equal(result.stopped, 'redirect-not-declared'); assert.ok(!hits.some(h => h.path === '/outside')); }
    assert.equal(result.requests, hits.length);
    for (const file of await readdir(join(folder, 'scenario'))) {
      const text = await readFile(join(folder, 'scenario', file), 'utf8');
      for (const secret of ['synthetic-private-password', 'first-private-session', 'second-private-session', 'private-csrf', 'private-controlled-user', 'SYNTHETIC_BROWSER_PRIVATE_TOKEN']) assert.ok(!text.includes(secret), file);
    }
  });
});

test('scenario cookies are never forwarded to a second allowed origin and foreign writes are refused', async () => {
  const cookies: (string | undefined)[] = [];
  const foreign = createServer((req, res) => { cookies.push(req.headers.cookie); res.writeHead(200, { 'Content-Type': 'image/svg+xml' }); res.end('<svg xmlns="http://www.w3.org/2000/svg"/>'); });
  await new Promise<void>(resolve => foreign.listen(0, '127.0.0.1', resolve));
  const other = 'http://127.0.0.1:' + (foreign.address() as { port: number }).port;
  try {
    await fixture((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'sid=private-origin-session; Path=/; HttpOnly; SameSite=Lax' }); res.end(`<html><body><img src="${other}/image"><div id="ready">ready</div></body></html>`); }, async (scope, folder) => {
      const origin = scope.allowed[0].origin; scope.allowed.push({ origin: other, paths: ['/image'] });
      const config: BrowserScenario = { schemaVersion: 1, boundary: 'controlled-workflow', policyReference: 'owned origin isolation fixture', sessionOrigin: origin,
        maxRedirects: 0, plan: { schemaVersion: 1, steps: [{ id: 'home', method: 'GET', url: origin + '/', credentialEnv: null }, { id: 'asset', method: 'GET', url: other + '/image', credentialEnv: null }] },
        actions: [{ kind: 'navigate', stepId: 'home' }, { kind: 'wait', selector: '#ready' }], observe: [] };
      const result = await captureScenario(join(folder, 'case'), scope, config);
      assert.equal(result.status, 'completed'); assert.equal(cookies.length, 1); assert.equal(cookies[0], undefined);
      const bad = structuredClone(config); bad.plan.steps[1].method = 'POST';
      scope.requestRules = [{ origin: other, path: '/image', method: 'POST', queryNames: [], bodyFormats: [] }];
      await assert.rejects(captureScenario(join(folder, 'bad'), scope, bad), /foreign requests/); assert.equal(cookies.length, 1);
    });
  } finally { await new Promise<void>(resolve => { foreign.closeAllConnections(); foreign.close(() => resolve()); }); }
});
