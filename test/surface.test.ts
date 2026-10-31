import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { importSurface, surfaceSummary } from '../src/surface.ts';

const id = '11111111-1111-4111-8111-111111111111';
const harEntry = (url: string, headers: any[] = [], status = 200) =>
  ({ request: { method: 'GET', url, headers, queryString: [] }, response: { status } });
const har = (...entries: any[]) => ({ log: { version: '1.2', entries } });

test('HAR import templates identifiers, keeps names only and marks credential presence', () => {
  const surface = importSurface(har(
    harEntry(`https://api.example.test/documents/${id}?token=secret-value`, [{ name: 'Authorization', value: 'Bearer secret-value' }]),
    harEntry('https://api.example.test/documents/42', [], 403),
    harEntry('https://api.example.test/'),
  ), 'har');
  const [first, second, root] = surface.entries;
  assert.equal(first.path, '/documents/{opaque}');
  assert.equal(first.pathKind, 'inferred-template');
  assert.equal(first.authentication, 'credential-present');
  assert.deepEqual(first.parameters, [{ location: 'query', name: 'token' }]);
  assert.equal(second.authentication, 'not-established');
  assert.equal(second.status, 403);
  assert.equal(root.pathKind, 'literal');
  assert.equal(first.locator, '/log/entries/0');
  assert.doesNotMatch(JSON.stringify(surface), /secret-value|11111111/);
  assert.deepEqual(surfaceSummary(surface), { format: 'har', records: 3, endpointCandidates: 2, observed: 3, declared: 0, reaEvidenceId: null });
});

test('HAR import rejects ambiguous paths, embedded credentials and unsupported versions', () => {
  for (const url of ['https://a.test/x/../y', 'https://a.test/x%2Fy', 'https://u:p@a.test/x', 'ftp://a.test/x', 'https://a.test//x'])
    assert.throws(() => importSurface(har(harEntry(url)), 'har'), undefined, url);
  assert.throws(() => importSurface({ log: { version: '1.1', entries: [] } }, 'har'), /HAR 1.2/);
  assert.throws(() => importSurface(har({ request: { method: 'CONNECT', url: 'https://a.test/' }, response: { status: 200 } }), 'har'), /method/);
});

test('OpenAPI import projects servers, resolves local refs and reads security declarations', () => {
  const doc = {
    openapi: '3.1.0',
    servers: [{ url: 'https://api.example.test/v1' }, { url: '/relative' }],
    security: [{ bearer: [] }],
    components: { parameters: { Id: { in: 'path', name: 'id' } }, pathItems: { Doc: { get: { parameters: [{ $ref: '#/components/parameters/Id' }] }, delete: { security: [] } } } },
    paths: { '/documents/{id}': { $ref: '#/components/pathItems/Doc' }, 'x-internal': {} },
  };
  const surface = importSurface(doc, 'openapi');
  assert.equal(surface.entries.length, 4);
  const [absGet, relGet, absDelete] = surface.entries;
  assert.equal(absGet.origin, 'https://api.example.test');
  assert.equal(absGet.path, '/v1/documents/{id}');
  assert.equal(absGet.pathKind, 'declared-template');
  assert.equal(absGet.authentication, 'declared-required');
  assert.deepEqual(absGet.parameters, [{ location: 'path', name: 'id' }]);
  assert.equal(absGet.locator, '/paths/~1documents~1{id}/get');
  assert.equal(relGet.origin, null);
  assert.equal(relGet.path, '/relative/documents/{id}');
  assert.equal(absDelete.method, 'DELETE');
  assert.equal(absDelete.authentication, 'declared-optional');
  assert.ok(surface.entries.every(e => e.basis === 'declared' && e.status === null));
});

test('Swagger 2 import preserves routes, optional auth and body parameter without copying examples', () => {
  const doc = { swagger: '2.0', host: 'api.example.test', basePath: '/titan', schemes: ['https'],
    security: [{ azuread: [] }],
    parameters: { Query: { in: 'body', name: 'query', schema: { example: 'private-example' } } },
    paths: { '/GetConfiguration': { get: {} }, '/v2/Query': { post: { security: [], parameters: [{ $ref: '#/parameters/Query' }] } } } };
  const surface = importSurface(doc, 'openapi');
  assert.equal(surface.entries.length, 2);
  const query = surface.entries.find(e => e.path === '/titan/v2/Query')!;
  assert.equal(query.origin, 'https://api.example.test');
  assert.equal(query.method, 'POST');
  assert.equal(query.authentication, 'declared-optional');
  assert.deepEqual(query.parameters, [{ location: 'body', name: 'query' }]);
  assert.equal(query.locator, '/paths/~1v2~1Query/post');
  assert.equal(surface.entries.find(e => e.method === 'GET')!.authentication, 'declared-required');
  assert.ok(!JSON.stringify(surface).includes('private-example'));
  const { schemes: _schemes, ...withoutSchemes } = doc;
  assert.equal(importSurface(withoutSchemes, 'openapi').entries[0].origin, null);
  assert.throws(() => importSurface({ ...doc, host: 'api.example.test/unsafe' }, 'openapi'), /host/);
});

test('OpenAPI import refuses cycles, external refs, server variables and unsupported Swagger versions', () => {
  const base = (patch: any) => ({ openapi: '3.0.3', paths: {}, ...patch });
  assert.throws(() => importSurface(base({ paths: { '/a': { $ref: '#/paths/~1a' } } }), 'openapi'), /cyclic/);
  assert.throws(() => importSurface(base({ paths: { '/a': { $ref: 'https://evil.test/a.json' } } }), 'openapi'), /reference/);
  assert.throws(() => importSurface(base({ servers: [{ url: 'https://{env}.example.test' }], paths: { '/a': { get: {} } } }), 'openapi'), /variables/);
  assert.throws(() => importSurface({ swagger: '1.2', paths: {} }, 'openapi'), /Swagger 2.0/);
});

test('REA import requires complete capture Evidence and keeps its ordinals', () => {
  const evidence = (records: any[], total = records.length) => ({
    operation: 'inspect_web_network_capture', evidence_id: 'ev:capture-1',
    normalized_result: { format: 'har', total_records: total, records },
  });
  const surface = importSurface(evidence([{ ordinal: 7, reported: harEntry('https://a.test/items/9') }]), 'rea');
  assert.equal(surface.reaEvidenceId, 'ev:capture-1');
  assert.equal(surface.entries[0].ordinal, 7);
  assert.equal(surface.entries[0].locator, '/normalized_result/records/0/reported');
  assert.throws(() => importSurface(evidence([{ ordinal: 1, reported: harEntry('https://a.test/') }], 2), 'rea'), /Complete REA/);
  const dup = [{ ordinal: 1, reported: harEntry('https://a.test/') }, { ordinal: 1, reported: harEntry('https://a.test/') }];
  assert.throws(() => importSurface(evidence(dup), 'rea'), /ordinal/);
  assert.throws(() => importSurface({ ...evidence([]), operation: 'other' }, 'rea'), /REA capture Evidence/);
});

test('CLI import-surface writes a new digest-bound file and never overwrites', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-surface-'));
  try {
    const input = join(dir, 'capture.har.json'), out = join(dir, 'surface.json');
    await writeFile(input, JSON.stringify(har(harEntry('https://a.test/x'))));
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const run = () => spawnSync(process.execPath, [cli, 'import-surface', '--format', 'har', '--input', input, '--out', out], { encoding: 'utf8' });
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    assert.equal(JSON.parse(first.stdout).records, 1);
    const saved = JSON.parse(await readFile(out, 'utf8'));
    assert.match(saved.sha256, /^[a-f0-9]{64}$/);
    assert.equal(saved.surface.entries[0].path, '/x');
    assert.equal(run().status, 1, 'existing output is refused');
    const bad = spawnSync(process.execPath, [cli, 'import-surface', '--format', 'yaml', '--input', input, '--out', out + '2'], { encoding: 'utf8' });
    assert.equal(bad.status, 2);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
