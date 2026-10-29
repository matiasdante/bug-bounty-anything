import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { candidateSummary, importCandidates } from '../src/candidates.ts';
import type { Scope } from '../src/scope.ts';

const scope: Scope = {
  schemaVersion: 1, mode: 'public-https',
  authorization: { reference: 'candidate test', validFrom: '2026-01-01T00:00:00.000Z', validUntil: '2030-01-01T00:00:00.000Z' },
  allowed: [{ origin: 'https://app.example.test', paths: ['/api/items', '/login'] }],
  excluded: [{ origin: 'https://app.example.test', paths: ['/api/internal'] }, { origin: 'https://legacy.example.test', paths: ['/'] }],
  limits: { maxRequests: 10, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 },
};
const zap = (...instances: unknown[]) => JSON.stringify({ site: [{ alerts: [{ pluginid: '40012', name: 'Cross Site Scripting (Reflected)', riskcode: '3',
  desc: 'SECRET-DESCRIPTION', instances }] }] });
const instance = (uri: string, method = 'GET') => ({ uri, method, evidence: 'SECRET-EVIDENCE', attack: '<script>', param: 'q' });

test('ZAP candidates are classified against the scope and never become validated', () => {
  const set = importCandidates(zap(
    instance('https://app.example.test/api/items?q=SECRET-QUERY'), instance('https://app.example.test/api/internal'),
    instance('https://app.example.test/other'), instance('ftp://app.example.test/api/items'), instance('not a url'),
    instance('https://app.example.test/api/items?q=again'),
  ), 'zap', scope);
  assert.deepEqual(set.candidates.map(c => c.scopeStatus), ['in-scope', 'excluded', 'out-of-scope', 'unparseable']);
  assert.equal(set.duplicates, 2, 'same rule and path collapse, and so do the two unparseable URLs; query values are not identity');
  assert.deepEqual(set.candidates.map(c => c.status), Array(4).fill('unvalidated'));
  assert.equal(set.candidates[0].reportedSeverity, 'high');
  assert.equal(set.candidates[0].hasQuery, true);
  assert.equal(set.candidates[0].path, '/api/items');
  assert.doesNotMatch(JSON.stringify(set), /SECRET|<script>/, 'descriptions, evidence, attacks and query values are dropped');
  assert.deepEqual(candidateSummary(set), { format: 'zap', candidates: 4, duplicates: 2, inScope: 1, excluded: 1, outOfScope: 1, unparseable: 1, validated: 0 });
});

test('Nuclei JSONL maps severity and matched-at and rejects malformed or oversized input', () => {
  const rows = [
    { 'template-id': 'exposed-config', info: { name: 'Exposed config', severity: 'Medium' }, host: 'https://app.example.test', 'matched-at': 'https://app.example.test/login', response: 'SECRET-BODY' },
    { 'template-id': 'weird id!', info: { name: 'x\nINJECTED: [link](http://evil.test)', severity: 'bogus' }, host: 'https://legacy.example.test' },
  ].map(r => JSON.stringify(r)).join('\n');
  const set = importCandidates(rows, 'nuclei', scope);
  assert.deepEqual(set.candidates.map(c => [c.ruleId, c.reportedSeverity, c.scopeStatus]),
    [['exposed-config', 'medium', 'in-scope'], [null, 'unknown', 'excluded']]);
  assert.doesNotMatch(set.candidates[1].title, /\n/);
  assert.doesNotMatch(JSON.stringify(set), /SECRET-BODY/);
  assert.throws(() => importCandidates('{"a":1}\nnot json', 'nuclei', scope), /Invalid JSON line/);
  assert.throws(() => importCandidates(Array(5001).fill('{}').join('\n'), 'nuclei', scope), /Too many records/);
  assert.throws(() => importCandidates('{}', 'nessus' as 'zap', scope), /Unsupported candidate format/);
});

test('empty or out-of-range ZAP risk codes are unknown, not informational', () => {
  const alert = (riskcode: unknown) => JSON.stringify({ site: [{ alerts: [{ pluginid: '1', name: 'n', riskcode, instances: [instance('https://app.example.test/login')] }] }] });
  for (const code of ['', null, '7', 'bogus']) assert.equal(importCandidates(alert(code), 'zap', scope).candidates[0].reportedSeverity, 'unknown', String(code));
  assert.equal(importCandidates(alert('0'), 'zap', scope).candidates[0].reportedSeverity, 'info');
});

test('Subfinder hosts are only compared with scope hostnames and never resolved', () => {
  const rows = ['app.example.test', 'LEGACY.example.test', 'new.example.test', 'bad host!', ''].map(host => JSON.stringify({ host, input: 'example.test', source: ['crtsh'] })).join('\n');
  const set = importCandidates(rows, 'subfinder', scope);
  assert.deepEqual(set.candidates.map(c => c.scopeStatus), ['in-scope', 'excluded', 'out-of-scope', 'unparseable']);
  assert.ok(set.candidates.every(c => c.kind === 'host' && c.origin === null && c.status === 'unvalidated'));
  assert.equal(set.duplicates, 1, 'the two invalid entries collapse');
});

test('CLI writes a new checksummed file, refuses to overwrite and prints no scanner content', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-candidates-'));
  try {
    await writeFile(join(dir, 'scope.json'), JSON.stringify(scope));
    await writeFile(join(dir, 'zap.json'), zap(instance('https://app.example.test/login')));
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const run = (...args: string[]) => promisify(execFile)(process.execPath, [cli, ...args])
      .then(r => ({ status: 0, ...r }), (e: { code: number; stdout: string; stderr: string }) => ({ status: e.code, stdout: e.stdout, stderr: e.stderr }));
    const args = ['import-candidates', '--format', 'zap', '--input', join(dir, 'zap.json'), '--scope', join(dir, 'scope.json'), '--out', join(dir, 'out.json')];
    const first = await run(...args);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(JSON.parse(first.stdout).inScope, 1);
    const saved = JSON.parse(await readFile(join(dir, 'out.json'), 'utf8'));
    assert.match(saved.sha256, /^[a-f0-9]{64}$/);
    assert.equal(saved.candidates.candidates[0].status, 'unvalidated');
    assert.equal((await run(...args)).status, 1, 'existing output is refused');
    assert.equal((await run(...args.map(a => a === 'zap' ? 'burp' : a))).status, 2);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
