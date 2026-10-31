import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startRoleLab } from '../src/role-lab.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const project = fileURLToPath(new URL('..', import.meta.url));

function server(root: string, flags: string[] = [], env: Record<string, string> = {}) {
  const child = spawn(process.execPath, [cli, 'mcp', '--root', root, ...flags], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map<number | null, (message: any) => void>();
  let buffer = '', transcript = '';
  child.stdout.on('data', chunk => {
    buffer += chunk; transcript += chunk;
    for (let i = buffer.indexOf('\n'); i >= 0; i = buffer.indexOf('\n')) {
      const message = JSON.parse(buffer.slice(0, i)); buffer = buffer.slice(i + 1);
      pending.get(message.id)?.(message);
    }
  });
  let next = 1;
  const request = (method: string, params?: unknown, id: number | null = next++) =>
    new Promise<any>(resolve => { pending.set(id, resolve); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });
  const call = (name: string, args: Record<string, string>) => request('tools/call', { name, arguments: args });
  const nextNull = () => new Promise<any>(resolve => { pending.set(null, resolve); });
  return { request, call, nextNull, raw: (line: string) => child.stdin.write(line + '\n'), transcript: () => transcript,
    close: () => new Promise<number | null>(resolve => { child.once('close', resolve); child.stdin.end(); }) };
}

const har = { log: { version: '1.2', entries: [{ request: { method: 'GET', url: 'https://a.test/items/42', headers: [], queryString: [] }, response: { status: 200 } }] } };

test('MCP initializes, lists only offline tools by default and rejects network tools', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-mcp-'));
  const s = server(root);
  try {
    const init = await s.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.deepEqual(Object.keys(init.result.capabilities), ['tools']);
    assert.equal((await s.request('initialize', { protocolVersion: '1999-01-01' })).result.protocolVersion, '2025-06-18', 'unknown versions fall back to the newest supported');
    const names = (await s.request('tools/list')).result.tools.map((t: { name: string }) => t.name);
    assert.deepEqual(names.sort(), ['artifact_view', 'campaign_link', 'campaign_open', 'campaign_policy_review', 'campaign_status', 'capabilities', 'compare_runs', 'evaluate_jwt', 'evaluate_run', 'evaluate_semantic', 'evidence_view', 'export_run', 'import_candidates', 'import_surface', 'inspect_budget', 'inspect_run', 'page_view', 'plan_investigation', 'prepare', 'report_run', 'scope_check', 'start_case', 'study_bundle', 'study_plan']);
    for (const network of ['run', 'resume', 'capture', 'hunt', 'investigate', 'resume_investigation', 'browser_check', 'browser_scenario', 'jwt_check', 'resume_jwt', 'template_check', 'resume_template_check', 'ssrf_callback_check', 'resume_ssrf_callback', 'cache_check', 'resume_cache_check', 'race_check', 'csrf_check', 'study_run', 'resume_study', 'inspect_web_page', 'campaign_capture', 'campaign_execute', 'campaign_resume']) {
      const answer = await s.call(network, { scope: 'a', plan: 'b', out: 'c', run: 'd' });
      assert.equal(answer.error.code, -32602, network);
    }
    assert.deepEqual((await s.request('ping')).result, {});
    assert.equal(JSON.parse((await s.call('capabilities', {})).result.content[0].text).confirmation.length, 7);
    assert.equal((await s.request('resources/list')).error.code, -32601);
  } finally { assert.equal(await s.close(), 0); await rm(root, { recursive: true, force: true }); }
});

test('MCP binds a saved policy source and detects later changes without network access', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-mcp-policy-'));
  const s = server(root);
  try {
    const opened = await s.call('campaign_open', { target: 'https://program.example.test/', out: 'campaign' });
    assert.equal(opened.result.isError, false, JSON.stringify(opened));
    const scope = { schemaVersion: 1, mode: 'public-https', budgetId: 'mcp-policy-fixture',
      authorization: { reference: 'owned policy fixture', validFrom: new Date(Date.now() - 1000).toISOString(),
        validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin: 'https://program.example.test', paths: ['/'] }], excluded: [],
      limits: { maxRequests: 5, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 } };
    await writeFile(join(root, 'campaign', 'scope.json'), JSON.stringify(scope));
    const linkedScope = await s.call('campaign_link', { campaign: 'campaign', kind: 'scope', artifact: 'campaign/scope.json' });
    assert.equal(linkedScope.result.isError, false, JSON.stringify(linkedScope));
    await writeFile(join(root, 'campaign', 'policy-source.txt'), 'Synthetic owned policy fixture for the exact origin and GET /.');
    const reviewed = await s.call('campaign_policy_review', { campaign: 'campaign',
      sourceUrl: 'https://program.example.test/policy', sourceKind: 'owner-written-authorization', decision: 'authorized' });
    assert.equal(reviewed.result.isError, false, JSON.stringify(reviewed));
    const linkedPolicy = await s.call('campaign_link', { campaign: 'campaign', kind: 'policy', artifact: 'campaign/policy.json' });
    assert.equal(linkedPolicy.result.isError, false, JSON.stringify(linkedPolicy));
    const status = await s.call('campaign_status', { campaign: 'campaign' });
    assert.equal(JSON.parse(status.result.content[0].text).policySourceBound, true);
    await writeFile(join(root, 'campaign', 'policy-source.txt'), 'Changed synthetic policy fixture.');
    const changed = await s.call('campaign_status', { campaign: 'campaign' });
    assert.equal(changed.result.isError, true);
    assert.match(changed.result.content[0].text, /Policy source changed/);
  } finally { assert.equal(await s.close(), 0); await rm(root, { recursive: true, force: true }); }
});

test('MCP confines paths to the root, validates arguments and survives malformed input', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-mcp-'));
  const outside = await mkdtemp(join(tmpdir(), 'bba-outside-'));
  const s = server(root);
  try {
    await writeFile(join(root, 'capture.har'), JSON.stringify(har));
    const ok = await s.call('import_surface', { format: 'har', input: 'capture.har', out: 'surface.json' });
    assert.equal(ok.result.isError, false, JSON.stringify(ok));
    assert.equal(JSON.parse(ok.result.content[0].text).records, 1);
    assert.match(await readFile(join(root, 'surface.json'), 'utf8'), /"sha256"/);
    const again = await s.call('import_surface', { format: 'har', input: 'capture.har', out: 'surface.json' });
    assert.equal(again.result.isError, true, 'existing output is refused');
    for (const bad of ['../outside.json', join(outside, 'x.json'), '.']) {
      const escaped = await s.call('import_surface', { format: 'har', input: 'capture.har', out: bad });
      assert.equal(escaped.result.isError, true, bad);
      assert.match(escaped.result.content[0].text, /outside the workspace root/);
    }
    await assert.rejects(readFile(join(outside, 'x.json')), /ENOENT/);
    assert.equal((await s.call('import_surface', { format: 'har', input: 'capture.har' })).error.code, -32602, 'missing argument');
    assert.equal((await s.call('import_surface', { format: 'har', input: 'capture.har', out: 'o', extra: 'x' })).error.code, -32602, 'extra argument');
    assert.equal((await s.call('import_surface', { format: 'har', input: 'capture.har', out: 5 as unknown as string })).error.code, -32602, 'wrong type');
    assert.equal((await s.call('nope', {})).error.code, -32602);
    const parse = s.nextNull();
    s.raw('{not json');
    assert.equal((await parse).error.code, -32700);
    assert.deepEqual((await s.request('ping')).result, {}, 'still serving after a parse error');
  } finally { assert.equal(await s.close(), 0); await rm(root, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});

test('MCP does not follow a link inside the root to a directory outside it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bba-mcp-'));
  const outside = await mkdtemp(join(tmpdir(), 'bba-outside-'));
  const s = server(root);
  try {
    await writeFile(join(root, 'capture.har'), JSON.stringify(har));
    await writeFile(join(outside, 'secret.har'), JSON.stringify(har));
    await symlink(outside, join(root, 'link'), 'junction');
    await symlink(join(outside, 'missing'), join(root, 'dangling'), 'junction');
    for (const args of [{ input: 'link/secret.har', out: 'ok.json' }, { input: 'capture.har', out: 'link/written.json' }, { input: 'capture.har', out: 'dangling/written.json' }]) {
      const answer = await s.call('import_surface', { format: 'har', ...args });
      assert.equal(answer.result.isError, true, JSON.stringify(args));
      assert.match(answer.result.content[0].text, /outside the workspace root/);
    }
    await assert.rejects(readFile(join(outside, 'written.json')), /ENOENT/);
    await assert.rejects(readFile(join(root, 'ok.json')), /ENOENT/);
    assert.equal((await s.call('import_surface', { format: 'har', input: 'capture.har', out: 'fine.json' })).result.isError, false, 'normal paths still work');
  } finally { assert.equal(await s.close(), 0); await rm(root, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});

test('MCP with --allow-network runs a plan and evaluates it without exposing credentials', async () => {
  const lab = await startRoleLab('vulnerable');
  const root = await mkdtemp(join(tmpdir(), 'bba-mcp-'));
  const s = server(root, ['--allow-network'], { BBA_TOKEN_ADMIN: lab.credentials.admin, BBA_TOKEN_USER: lab.credentials.user });
  try {
    assert.ok((await s.request('tools/list')).result.tools.some((t: { name: string }) => t.name === 'run'));
    const url = lab.origin + '/admin/users';
    await writeFile(join(root, 'scope.json'), JSON.stringify({ schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'BBA role lab', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin: lab.origin, paths: ['/admin/users'] }], excluded: [],
      limits: { maxRequests: 3, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 } }));
    await writeFile(join(root, 'plan.json'), JSON.stringify({ schemaVersion: 1, steps: [
      { id: 'control', method: 'GET', url, credentialEnv: null }, { id: 'baseline', method: 'GET', url, credentialEnv: 'BBA_TOKEN_ADMIN' },
      { id: 'probe', method: 'GET', url, credentialEnv: 'BBA_TOKEN_USER' }] }));
    await writeFile(join(root, 'checks.json'), JSON.stringify({ schemaVersion: 1, checks: [{ id: 'admin-users', class: 'bfla', control: 'control', baseline: 'baseline', probe: 'probe' }] }));
    assert.equal((await s.call('scope_check', { scope: 'scope.json', plan: 'plan.json' })).result.isError, false);
    const ran = await s.call('run', { scope: 'scope.json', plan: 'plan.json', out: 'run' });
    assert.equal(ran.result.isError, false, JSON.stringify(ran));
    assert.equal(JSON.parse(ran.result.content[0].text).status, 'completed');
    const evaluated = await s.call('evaluate_run', { run: 'run', checks: 'checks.json', out: 'evaluation.md' });
    assert.deepEqual(JSON.parse(evaluated.result.content[0].text), [{ check: 'admin-users', class: 'bfla', status: 'needs-validation' }]);
    assert.deepEqual(JSON.parse((await s.call('inspect_run', { run: 'run' })).result.content[0].text).succeeded, 3);
    for (const secret of [lab.credentials.admin, lab.credentials.user]) assert.doesNotMatch(s.transcript() + await readFile(join(root, 'evaluation.md'), 'utf8'), new RegExp(secret));
  } finally { assert.equal(await s.close(), 0); await lab.close(); await rm(root, { recursive: true, force: true }); }
});

test('doctor reports local prerequisites and prints no secret value', async () => {
  const secret = 'doctor-secret-value-123456';
  const result = await promisify(execFile)(process.execPath, [cli, 'doctor'], { env: { ...process.env, BBA_TOKEN_DOCTOR: secret, BBA_HEADER_DOCTOR: secret } })
    .then(r => ({ code: 0, ...r }), (e: { code: number; stdout: string }) => ({ code: e.code, stdout: e.stdout }));
  const report = JSON.parse(result.stdout);
  const byName = Object.fromEntries(report.checks.map((c: { name: string; ok: boolean; detail: string }) => [c.name, c]));
  for (const name of ['node', 'sqlite', 'loopback', 'temp-directory']) assert.equal(byName[name].ok, true, name);
  assert.equal(result.code, report.ok ? 0 : 1);
  assert.match(byName.credentials.detail, /BBA_TOKEN_DOCTOR/);
  assert.match(byName.credentials.detail, /BBA_HEADER_DOCTOR/);
  assert.doesNotMatch(result.stdout, new RegExp(secret));
});

test('the built package runs without type stripping', async () => {
  const out = join(project, '.build-test');
  try {
    await mkdir(out, { recursive: true });
    await promisify(execFile)(process.execPath, [join(project, 'scripts', 'build.ts'), out], { cwd: project });
    const built = join(out, 'cli.js');
    assert.match((await readFile(built, 'utf8')).split('\n')[0], /^#!\/usr\/bin\/env node/);
    assert.doesNotMatch(await readFile(built, 'utf8'), /from '\.\/[\w-]+\.ts'/);
    const help = await promisify(execFile)(process.execPath, ['--no-experimental-strip-types', built, '--help']);
    const { version } = JSON.parse(await readFile(join(project, 'package.json'), 'utf8'));
    assert.ok(help.stdout.startsWith('BBA ' + version + ' '), help.stdout.slice(0, 40));
    const dir = await mkdtemp(join(tmpdir(), 'bba-built-'));
    try {
      await writeFile(join(dir, 'c.har'), JSON.stringify(har));
      const imported = await promisify(execFile)(process.execPath, ['--no-experimental-strip-types', built, 'import-surface', '--format', 'har', '--input', join(dir, 'c.har'), '--out', join(dir, 's.json')]);
      assert.equal(JSON.parse(imported.stdout).records, 1);
    } finally { await rm(dir, { recursive: true, force: true }); }
  } finally { await rm(out, { recursive: true, force: true }); }
});
