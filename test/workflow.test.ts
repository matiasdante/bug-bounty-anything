import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { prepareInvestigation, startCase } from '../src/prepare.ts';
import { validatePlan, validateScope } from '../src/scope.ts';
import { digest } from '../src/contracts.ts';
import type { Scope } from '../src/scope.ts';
import { tools, confine } from '../src/tools.ts';

const project = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(project, 'src', 'cli.ts');
const exec = promisify(execFile);
const scope = (origin = 'https://service.example'): Scope => ({ schemaVersion: 1, mode: 'public-https',
  authorization: { reference: 'owned synthetic fixture', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 60000).toISOString() },
  allowed: [{ origin, paths: ['/', '/excluded'] }], excluded: [{ origin, paths: ['/excluded'] }],
  limits: { maxRequests: 10, minIntervalMs: 1000, timeoutMs: 1000, maxResponseBytes: 4096, maxDurationMs: 10000 } });

test('a case can start offline without inventing permission, dates or an executable plan', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-case-'));
  try {
    const result = startCase(join(root, 'case'), 'https://service.example/');
    assert.equal(result.authorizationVerification, 'unverified'); assert.equal(result.requestsSent, 0);
    await assert.rejects(access(join(root, 'case', 'scope.json'))); await assert.rejects(access(join(root, 'case', 'plan.json')));
    const { manifest, sha256 } = JSON.parse(await readFile(join(root, 'case', 'case.json'), 'utf8')); assert.equal(digest(manifest), sha256);
    assert.throws(() => startCase(join(root, 'case'), 'https://service.example/'), /EEXIST/);
    assert.throws(() => startCase(join(root, 'invalid'), 'https://user:password@service.example/'));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('prepare via CLI and MCP is offline, consistent and refuses excluded targets and overwrites', async () => {
  let hits = 0;
  const server = createServer((_req, res) => { hits++; res.end('not reached'); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
  const root = await mkdtemp(join(tmpdir(), 'bba-workflow-'));
  const s = { ...scope(origin), mode: 'loopback-lab' as const };
  try {
    await writeFile(join(root, 'scope.json'), JSON.stringify(s));
    const prepared = await exec(process.execPath, [cli, 'prepare', '--scope', join(root, 'scope.json'), '--target', origin + '/', '--out', join(root, 'case')]);
    assert.equal(JSON.parse(prepared.stdout).requestsSent, 0);
    const plan = JSON.parse(await readFile(join(root, 'case', 'plan.json'), 'utf8'));
    validatePlan(plan, s);
    assert.deepEqual(JSON.parse(await readFile(join(root, 'case', 'scope.json'), 'utf8')), s);
    const { manifest, sha256 } = JSON.parse(await readFile(join(root, 'case', 'case.json'), 'utf8'));
    assert.equal(sha256, digest(manifest)); assert.equal(manifest.scopeDigest, digest(s));
    assert.equal(manifest.authorizationVerification, 'operator-required');
    assert.throws(() => prepareInvestigation(join(root, 'case'), s, origin + '/'), /EEXIST/);
    for (const target of [origin + '/excluded', origin + '/other', origin + '/?token=private']) {
      assert.throws(() => prepareInvestigation(join(root, 'rejected'), s, target));
      await assert.rejects(access(join(root, 'rejected')));
    }
    const tool = tools.find(t => t.name === 'prepare')!;
    assert.equal(tool.network, false);
    const result: any = await tool.run({ scope: 'scope.json', target: origin + '/', out: 'mcp-case' }, confine(root));
    assert.equal(result.requestsSent, 0);
    await assert.rejects(tool.run({ scope: 'scope.json', target: origin + '/', out: '../escape-case' }, confine(root)), /outside/);
    assert.equal(hits, 0);
    const old = scope(); old.authorization.validUntil = new Date(Date.now() - 1).toISOString();
    old.authorization.validFrom = new Date(Date.now() - 60000).toISOString(); validateScope(old);
    assert.throws(() => prepareInvestigation(join(root, 'expired'), old, 'https://service.example/'), /expired/);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(root, { recursive: true, force: true }); }
});

// Run against the compiled package too: an installed skill must not depend on
// TypeScript stripping or the caller's current directory to locate its runtime.
test('install-skill copies usable references and binds a compiled runtime without overwriting', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-install-'));
  try {
    await exec(process.execPath, [join(project, 'scripts', 'build.ts')], { cwd: project });
    const out = join(root, 'bug-bounty-anything');
    const installed = await exec(process.execPath, ['--no-experimental-strip-types', join(project, 'dist', 'cli.js'), 'install-skill', '--out', out], { cwd: root });
    assert.equal(JSON.parse(installed.stdout).mcpConfigurationChanged, false);
    const skill = await readFile(join(out, 'SKILL.md'), 'utf8');
    for (const match of skill.matchAll(/\]\(((?:references|docs)\/[^)]+)\)/g)) await access(join(out, match[1]));
    for (const path of ['SKILL.es.md', 'docs/readme/README_es.md', 'docs/es/ROADMAP.md', 'references/scope-and-authorization.es.md']) await access(join(out, path));
    await access(join(out, 'agents', 'openai.yaml'));
    const runtime = JSON.parse(await readFile(join(out, 'runtime.json'), 'utf8'));
    const help = await exec(runtime.command, ['--no-experimental-strip-types', ...runtime.args, '--help'], { cwd: root });
    assert.match(help.stdout, /prepare --scope/);
    await assert.rejects(exec(process.execPath, [cli, 'install-skill', '--out', out]));
    assert.equal(await readFile(join(out, 'SKILL.md'), 'utf8'), skill);
    await writeFile(join(out, 'README.md'), 'local customization to preserve');
    await writeFile(join(out, 'notes.txt'), 'unrelated note');
    const updated = await exec(process.execPath, [cli, 'update-skill', '--out', out]);
    const backup = JSON.parse(updated.stdout).backup;
    assert.equal(await readFile(join(backup, 'README.md'), 'utf8'), 'local customization to preserve');
    assert.equal(await readFile(join(out, 'notes.txt'), 'utf8'), 'unrelated note');
    assert.notEqual(await readFile(join(out, 'README.md'), 'utf8'), 'local customization to preserve');
    assert.ok(JSON.parse(await readFile(join(out, 'installation.json'), 'utf8')).managedFiles.length > 5);
  } finally { await rm(root, { recursive: true, force: true }); }
});
