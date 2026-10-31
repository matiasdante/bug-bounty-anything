import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hunt } from '../src/hunt.ts';
import type { HuntConfig } from '../src/hunt.ts';
import type { Scope } from '../src/scope.ts';
import { artifactView } from '../src/artifacts.ts';

for (const mode of ['vulnerable', 'fixed', 'public', 'invalid-identity', 'expired-probe', 'budget', 'cancelled']) {
  test(`autonomous discovery and confirmation: ${mode}`, async () => {
    const resource = '/resources/' + randomUUID();
    const laterResource = '/resources/' + randomUUID();
    const hits: string[] = [];
    const controller = new AbortController();
    const server = createServer((req, res) => {
      hits.push(req.url!);
      assert.equal(req.headers['x-bounty-marker'], 'SYNTHETIC_PRIVATE_MARKER');
      if (mode === 'cancelled') setTimeout(() => controller.abort(), 30);
      const actor = req.headers.authorization === 'Bearer TEST_ACCOUNT_A' ? 'a' : req.headers.authorization === 'Bearer TEST_ACCOUNT_B' ? 'b' : null;
      const reply = (status: number, data: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
      if (req.url === '/me') return reply(200, { id: mode === 'invalid-identity' ? 'same' : actor });
      if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(`<a href="${resource}">own resource</a><a href="${laterResource}">later resource</a><a href="/excluded">excluded</a><a href="https://example.com/">outside</a>`); return; }
      if (req.url === resource || req.url === laterResource) {
        if (!actor && mode !== 'public') return reply(401, {});
        if (actor === 'b' && mode === 'fixed') return reply(403, {});
        if (actor === 'b' && mode === 'expired-probe') return reply(401, {});
        return reply(200, { owner: 'a', privateValue: 'CONTROLLED_PRIVATE_VALUE' });
      }
      return reply(404, {});
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
    const temp = await mkdtemp(join(tmpdir(), 'bba-hunt-'));
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: { reference: 'owned test lab', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() }, allowed: [{ origin, paths: ['/', '/me', resource, '/excluded'] }], excluded: [{ origin, paths: ['/excluded'] }], limits: { maxRequests: mode === 'budget' ? 5 : 15, minIntervalMs: 0, timeoutMs: 1000, maxResponseBytes: 4096, maxDurationMs: 10000 } };
      scope.allowed[0].paths.push(laterResource);
      scope.requestHeaders = [{ origin, name: 'x-bounty-marker', valueEnv: 'BBA_HEADER_MARKER' }];
      if (mode === 'cancelled') scope.limits.minIntervalMs = 1000;
      const config: HuntConfig = { schemaVersion: 1, seed: origin + '/', identityUrl: origin + '/me', identityField: 'id', ownerField: 'owner', privateField: 'privateValue', accounts: ['BBA_TOKEN_A', 'BBA_TOKEN_B'], boundary: 'owner-only' };
      const folder = join(temp, 'hunt');
      const credentials = { BBA_TOKEN_A: 'TEST_ACCOUNT_A', BBA_TOKEN_B: 'TEST_ACCOUNT_B', BBA_HEADER_MARKER: 'SYNTHETIC_PRIVATE_MARKER' };
      const result = await hunt(folder, scope, config, { credentials, signal: controller.signal });
      assert.equal(hits.includes('/excluded'), false);
      assert.ok(result.requests <= scope.limits.maxRequests);
      if (mode === 'cancelled') {
        assert.equal(result.stopped, 'cancelled'); assert.equal(result.requests, 1); assert.equal(hits.length, 1);
      } else if (mode === 'invalid-identity') {
        assert.equal(result.stopped, 'identity-not-established'); assert.equal(hits.length, 2);
      } else if (mode === 'budget') {
        assert.equal(result.stopped, 'budget-exhausted'); assert.ok(!result.findings.some(f => f.status === 'confirmed'));
      } else {
        assert.equal(result.stopped, null);
        assert.equal(result.findings[0].status, mode === 'vulnerable' ? 'confirmed' : mode === 'fixed' ? 'not-reproduced' : 'unresolved');
        assert.ok(result.surface.some(s => s.url === origin + resource));
        assert.ok(result.findings[0].evidence.length >= 5);
        if (mode === 'vulnerable') assert.equal(hits.includes(laterResource), false, 'stop after the first minimal proof');
      }
      const text = await readFile(join(folder, 'requests.jsonl'), 'utf8') + await readFile(join(folder, 'hunt.json'), 'utf8') + await readFile(join(folder, 'report.md'), 'utf8');
      for (const secret of ['TEST_ACCOUNT_A', 'TEST_ACCOUNT_B', 'CONTROLLED_PRIVATE_VALUE', 'SYNTHETIC_PRIVATE_MARKER']) assert.ok(!text.includes(secret));
      assert.match(text, /Reproducción/);
      await assert.rejects(hunt(folder, scope, config, { credentials }), /EEXIST/);
      const summary = artifactView(folder, { kind: 'summary', offset: 0, limit: 10 });
      assert.equal(summary.parentEvidenceId, result.id);
      const page: any = artifactView(folder, { kind: 'events', offset: 0, limit: 1, expectedDigest: summary.revisionDigest });
      assert.equal(page.items[0].sourceObjectsOmitted, true);
      assert.equal(page.items[0].event.scope, undefined);
      assert.throws(() => artifactView(folder, { kind: 'events', offset: 0, limit: 1, expectedDigest: 'changed' }), /revision changed/);
      await appendFile(join(folder, 'requests.jsonl'), '\n');
      assert.throws(() => artifactView(folder, { kind: 'summary', offset: 0, limit: 10 }), /integrity mismatch/);
    } finally {
      await new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); });
      assert.ok(temp.startsWith(join(tmpdir(), 'bba-hunt-'))); await rm(temp, { recursive: true, force: true });
    }
  });
}
