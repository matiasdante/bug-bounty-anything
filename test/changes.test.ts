import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pkg from '../package.json' with { type: 'json' };
import { SafeError, safeErrorMessage } from '../src/contracts.ts';
import { arr, bool, enm, int, obj, opt, str, validateWithSchema } from '../src/schema.ts';
import { extractLangFlag, parseLang } from '../src/i18n.ts';
import { openAppendJournal } from '../src/journal.ts';
import { assertAuthorized, assertRequestAllowed, validateScope } from '../src/scope.ts';
import type { Scope } from '../src/scope.ts';
import { importSurface, projectCapturedHar } from '../src/surface.ts';
import { importCandidates } from '../src/candidates.ts';
import { createSession, exportSession, inspectSession } from '../src/session.ts';
import { evaluateChecks, evaluationMarkdown } from '../src/checks.ts';
import { sealArtifact, artifactView } from '../src/artifacts.ts';
import { evidenceViewFile } from '../src/evidence.ts';
import { setupMcp } from '../src/mcp-setup.ts';
import { buildProject } from '../scripts/build.ts';
import { packageSkill } from '../scripts/package-skill.ts';
import { doctor } from '../src/doctor.ts';

const cliPath = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const runCli = (args: string[]) => spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8', timeout: 15000 });

const validWindow = () => ({
  reference: 'Policy ref 2026',
  validFrom: new Date(Date.now() - 5000).toISOString(),
  validUntil: new Date(Date.now() + 600000).toISOString(),
});

const defaultLimits = () => ({
  maxRequests: 10,
  minIntervalMs: 0,
  timeoutMs: 2000,
  maxResponseBytes: 4096,
  maxDurationMs: 60000,
});

test('Change #4: declarative schema reports exact nested field paths via SafeError and projects JSON Schema', () => {
  const ruleSchema = obj({
    name: str({ minLength: 2, maxLength: 32 }),
    retries: int({ min: 0, max: 3 }),
    mode: enm(['strict', 'quarantine'] as const),
    enabled: opt(bool()),
  });
  const docSchema = obj({
    rules: arr(ruleSchema, { minItems: 1, maxItems: 5 }),
  });

  const parsed = validateWithSchema(docSchema, {
    rules: [{ name: 'alpha', retries: 1, mode: 'strict' }],
  });
  assert.equal(parsed.rules[0].mode, 'strict');

  assert.throws(
    () => validateWithSchema(docSchema, { rules: [{ name: 'alpha', retries: 1, mode: 'invalid' }] }),
    (err: unknown) => err instanceof SafeError && safeErrorMessage(err) === 'Field [rules.0.mode] failed: expected one of strict, quarantine',
  );

  assert.throws(
    () => validateWithSchema(docSchema, { rules: [{ name: 'alpha', retries: 1, mode: 'strict', extra: 'secret' }] }),
    (err: unknown) => err instanceof SafeError && safeErrorMessage(err) === 'Field [rules.0.extra] failed: unexpected property',
  );

  const jsonSchema = docSchema.toJsonSchema();
  assert.equal(jsonSchema.type, 'object');
  assert.equal(jsonSchema.additionalProperties, false);
  assert.deepEqual(jsonSchema.required, ['rules']);
  assert.deepEqual(jsonSchema.properties?.rules.items?.properties?.mode.enum, ['strict', 'quarantine']);
});

test('Change #2 & #8: unified CLI subcommands, per-command help, and --lang es|en reports', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-chg-cli-'));
  try {
    const enHelp = runCli(['--help', '--lang', 'en']);
    assert.equal(enHelp.status, 0);
    assert.match(enHelp.stdout, /BBA .* — investigations, captures and surface/);

    const subHelp = runCli(['campaign', 'open', '--help', '--lang', 'en']);
    assert.equal(subHelp.status, 0);
    assert.match(subHelp.stdout, /help for campaign-open/);

    const campDir = join(dir, 'camp');
    const opened = runCli(['campaign', 'open', '--target', 'https://example.test/', '--out', campDir]);
    assert.equal(opened.status, 0, opened.stderr);
    const status = runCli(['campaign', 'status', campDir]);
    assert.equal(status.status, 0, status.stderr);
    assert.equal(JSON.parse(status.stdout).target, 'https://example.test/');

    const badLang = runCli(['capabilities', '--lang', 'fr']);
    assert.equal(badLang.status, 2);
    assert.throws(() => parseLang('de'), SafeError);
    assert.deepEqual(extractLangFlag(['--lang', 'en', 'doctor']), { lang: 'en', rest: ['doctor'] });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Change #3 & #7: cross-routing between evidenceViewFile and artifactView + producerVersion stamping', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-chg-views-'));
  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: validWindow(),
      allowed: [{ origin: 'http://127.0.0.1:43210', paths: ['/items'] }],
      excluded: [],
      limits: defaultLimits(),
    };
    const runDir = join(dir, 'run');
    createSession(runDir, scope, {
      schemaVersion: 1,
      steps: [{ id: 's1', method: 'GET', url: 'http://127.0.0.1:43210/items', credentialEnv: null }],
    });
    const session = inspectSession(runDir);
    assert.equal(session.producerVersion, pkg.version);

    // artifactView sobre una carpeta de sesión SQLite redirige limpiamente a evidenceView.
    const crossRunSummary = artifactView(runDir, { kind: 'summary', offset: 0, limit: 10 });
    assert.equal(crossRunSummary.parentEvidenceId, session.id);

    const enRunMd = join(dir, 'run-en.md');
    exportSession(runDir, enRunMd, 'markdown', 'en');
    assert.match(await readFile(enRunMd, 'utf8'), /# BBA — execution/);

    const evalRes = evaluateChecks(session, {
      schemaVersion: 1,
      checks: [],
    } as any);
    assert.fail('Should reject empty checks');
  } catch (err) {
    assert.match(String(err), /Invalid checks/);
  } finally {
    // Continúa probando artifact sellado con journal append-only.
    const artDir = join(dir, 'art');
    await mkdir(artDir, { recursive: true });
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: validWindow(),
      allowed: [{ origin: 'http://127.0.0.1:43210', paths: ['/a'] }],
      excluded: [],
      limits: defaultLimits(),
    };
    const config = { sample: 1 };
    const id = '11111111-1111-4111-8111-111111111111';
    await writeFile(join(artDir, 'scope.json'), JSON.stringify(scope));
    await writeFile(join(artDir, 'config.json'), JSON.stringify(config));
    const journal = openAppendJournal(artDir);
    journal.append({ event: 'start', id });
    journal.append({ event: 'finish', requests: 0, stopped: null });
    journal.close();
    const { digest } = await import('../src/contracts.ts');
    const resultObj = { id, status: 'not-reproduced' };
    await writeFile(join(artDir, 'race-check.json'), JSON.stringify({ result: resultObj, sha256: digest(resultObj) }));
    sealArtifact(artDir, { kind: 'race-check', id, scopeDigest: digest(scope), configDigest: digest(config) });

    // evidenceViewFile sobre carpeta de artefacto sellado redirige limpiamente a artifactView.
    const crossArt = evidenceViewFile(artDir, { kind: 'summary', offset: 0, limit: 10 }) as any;
    assert.equal(crossArt.artifactKind, 'race-check');
    assert.equal(crossArt.producerVersion, pkg.version);

    await rm(dir, { recursive: true, force: true });
  }
});

test('Change #7 & #8: Evaluation stamps producerVersion and renders English Markdown', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-chg-eval-'));
  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: validWindow(),
      allowed: [{ origin: 'http://127.0.0.1:43211', paths: ['/doc'] }],
      excluded: [],
      limits: defaultLimits(),
    };
    const runDir = join(dir, 'run');
    createSession(runDir, scope, {
      schemaVersion: 1,
      steps: [
        { id: 'ctrl', method: 'GET', url: 'http://127.0.0.1:43211/doc', credentialEnv: null },
        { id: 'base', method: 'GET', url: 'http://127.0.0.1:43211/doc', credentialEnv: 'BBA_TOKEN_A' },
        { id: 'prob', method: 'GET', url: 'http://127.0.0.1:43211/doc', credentialEnv: 'BBA_TOKEN_B' },
      ],
    });
    const evaluation = evaluateChecks(inspectSession(runDir), {
      schemaVersion: 1,
      checks: [{ id: 'bola-doc', class: 'bola', control: 'ctrl', baseline: 'base', probe: 'prob' }],
    });
    assert.equal(evaluation.producerVersion, pkg.version);
    assert.match(evaluationMarkdown(evaluation, 'en'), /# Hypothesis evaluation/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Change #5: buildProject compiles nested subdirectories, preserves non-import .ts strings, and blocks symlinks', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-chg-build-'));
  try {
    const srcRoot = join(dir, 'src');
    const nested = join(srcRoot, 'nested');
    const outRoot = join(dir, 'dist');
    await mkdir(nested, { recursive: true });
    await writeFile(join(nested, 'helper.ts'), "export const label: string = 'keep ./literal.ts untouched';\n");
    await writeFile(join(srcRoot, 'cli.ts'), "import { label } from './nested/helper.ts';\nconsole.log(label);\n");

    const count = buildProject(outRoot, dir);
    assert.equal(count, 2);
    const cliJs = await readFile(join(outRoot, 'cli.js'), 'utf8');
    assert.match(cliJs, /^#!\/usr\/bin\/env node\n/);
    assert.match(cliJs, /from '\.\/nested\/helper\.js'/);
    const helperJs = await readFile(join(outRoot, 'nested', 'helper.js'), 'utf8');
    assert.match(helperJs, /keep \.\/literal\.ts untouched/);

    // Control negativo: rechaza destinos fuera de dist/.build-test y rechaza symlinks en src.
    assert.throws(() => buildProject(join(dir, 'other'), dir), /Build output must be dist or \.build-test/);
    const outside = await mkdtemp(join(tmpdir(), 'bba-chg-outside-'));
    try {
      await symlink(outside, join(srcRoot, 'linked'), 'junction');
      assert.throws(() => buildProject(join(dir, '.build-test'), dir), /Symbolic link not allowed/);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Change #9: Scope pathPrefixes, {param} templates, bracketed query params, and strict boundary controls', () => {
  const scope: Scope = {
    schemaVersion: 1,
    mode: 'public-https',
    authorization: validWindow(),
    allowed: [{
      origin: 'https://api.example.test',
      paths: ['/v1/users/{userId}/profile'],
      pathPrefixes: ['/api/orders'],
    }],
    excluded: [{
      origin: 'https://api.example.test',
      paths: [],
      pathPrefixes: ['/api/orders/internal'],
    }],
    requestRules: [{
      origin: 'https://api.example.test',
      pathPrefix: '/api/orders',
      method: 'POST',
      queryNames: ['filter[status]', 'page[size]'],
      bodyFormats: ['json'],
    }],
    limits: defaultLimits(),
  };

  validateScope(scope);
  assert.equal(assertAuthorized(scope, 'https://api.example.test/v1/users/42/profile').pathname, '/v1/users/42/profile');
  assert.equal(assertAuthorized(scope, 'https://api.example.test/api/orders').pathname, '/api/orders');
  assert.equal(assertAuthorized(scope, 'https://api.example.test/api/orders/99/items').pathname, '/api/orders/99/items');

  // Controles negativos de frontera de segmento y precedencia de exclusiones:
  assert.throws(() => assertAuthorized(scope, 'https://api.example.test/api/orders-admin'), /outside scope/);
  assert.throws(() => assertAuthorized(scope, 'https://api.example.test/api/orders/internal/audit'), /outside scope/);
  assert.throws(() => assertAuthorized(scope, 'https://api.example.test/v1/users/42/other'), /outside scope/);

  // RequestRule con pathPrefix + parámetros query con corchetes:
  assert.equal(
    assertRequestAllowed(scope, 'https://api.example.test/api/orders/99', {
      method: 'POST',
      query: [{ name: 'filter[status]', valueEnv: 'BBA_INPUT_STATUS' }],
      body: { format: 'json', valueEnv: 'BBA_BODY_ORDER' },
    }).pathname,
    '/api/orders/99',
  );

  // Importación de candidatos respeta pathPrefixes del Scope:
  const candidates = importCandidates(
    JSON.stringify({ 'matched-at': 'https://api.example.test/api/orders/77', 'template-id': 'info-test', info: { name: 'Info', severity: 'info' } }),
    'nuclei',
    scope,
  );
  assert.equal(candidates.producerVersion, pkg.version);
  assert.equal(candidates.candidates[0].scopeStatus, 'in-scope');
});

test('Change #10: doctor verifies Node >= 22.13 and package.json declares engines.node >=22.13.0', async () => {
  assert.equal(pkg.engines.node, '>=22.13.0');
  const report = await doctor();
  const nodeCheck = report.checks.find(c => c.name === 'node');
  assert.ok(nodeCheck?.ok);
});

test('Change #11: multi-client setupMcp (claude & gemini) with backup/replace guards + cross-platform packageSkill ZIP', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-chg-mcp-'));
  try {
    const workspace = join(dir, 'ws');
    await mkdir(workspace, { recursive: true });

    // Preview sin --apply no crea archivos:
    const preview = setupMcp(workspace, { client: 'claude', apply: false });
    assert.equal(preview.status, 'ready');
    assert.equal(preview.client, 'claude');

    // Instalación real en .mcp.json (Claude Code):
    const installed = setupMcp(workspace, { client: 'claude', apply: true });
    assert.equal(installed.status, 'installed');
    const claudeDoc = JSON.parse(await readFile(join(workspace, '.mcp.json'), 'utf8'));
    assert.equal(claudeDoc.mcpServers.bba.type, 'stdio');

    // Idempotencia:
    assert.equal(setupMcp(workspace, { client: 'claude', apply: true }).status, 'already-present');

    // Cambio a --allow-network exige --replace y genera backup:
    assert.throws(() => setupMcp(workspace, { client: 'claude', apply: true, allowNetwork: true }), /use --replace/);
    const updated = setupMcp(workspace, { client: 'claude', apply: true, allowNetwork: true, replace: true });
    assert.equal(updated.status, 'updated');
    assert.ok(updated.backup);

    // Instalación en .gemini/settings.json preservando claves previas:
    await mkdir(join(workspace, '.gemini'), { recursive: true });
    await writeFile(join(workspace, '.gemini', 'settings.json'), JSON.stringify({ theme: 'dark' }));
    const geminiInstalled = setupMcp(workspace, { client: 'gemini', apply: true });
    assert.equal(geminiInstalled.status, 'installed');
    const geminiDoc = JSON.parse(await readFile(join(workspace, '.gemini', 'settings.json'), 'utf8'));
    assert.equal(geminiDoc.theme, 'dark');
    assert.ok(geminiDoc.mcpServers.bba.command);

    // Empaquetado multiplataforma PKZIP a ruta temporal (sin tocar archivos del usuario):
    const zipPath = join(dir, 'skill-test.zip');
    const packaged = packageSkill({ outputPath: zipPath, includeNodeModules: false });
    assert.ok(packaged.entries >= 55);
    const zipBytes = await readFile(zipPath);
    assert.equal(zipBytes.readUInt32LE(0), 0x04034b50);
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/SKILL.md')));
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/SKILL.es.md')));
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/README.en.md')));
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/docs/ROADMAP.en.md')));
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/INSTALL-CLAUDE-CODE.md')));
    assert.ok(zipBytes.includes(Buffer.from('bug-bounty-anything/INSTALL-CLAUDE-CODE.es.md')));
    assert.throws(() => packageSkill({ outputPath: zipPath, includeNodeModules: false }), /Archive already exists/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Change #12: importSurface supports bracketed parameters, quarantine mode, and O(N) projectCapturedHar', () => {
  const harWithBracketsAndNoise = {
    log: {
      version: '1.2',
      entries: [
        {
          request: {
            method: 'GET',
            url: 'https://api.example.test/v1/items?filter%5Bid%5D=10&page%5Bnumber%5D=1',
            headers: [],
            queryString: [{ name: 'filter[id]', value: '10' }, { name: 'page[number]', value: '1' }],
          },
          response: { status: 200 },
        },
        {
          request: {
            method: 'GET',
            url: 'chrome-extension://abcdef/popup.html',
            headers: [],
            queryString: [],
          },
          response: { status: 200 },
        },
      ],
    },
  };

  // Sin quarantine rechaza entradas no representables:
  assert.throws(() => importSurface(harWithBracketsAndNoise, 'har'));

  // Con quarantine saltea la entrada inválida y conserva los parámetros con corchetes:
  const quarantined = importSurface(harWithBracketsAndNoise, 'har', { quarantine: true });
  assert.equal(quarantined.producerVersion, pkg.version);
  assert.equal(quarantined.entries.length, 1);
  assert.equal(quarantined.skipped, 1);
  assert.deepEqual(quarantined.entries[0].parameters.map(p => p.name), ['filter[id]', 'page[number]']);

  // projectCapturedHar proyecta en una sola pasada O(N):
  const projected = projectCapturedHar(harWithBracketsAndNoise.log.entries);
  assert.equal(projected.surface.entries.length, 1);
  assert.equal(projected.unrepresentable, 1);
  assert.deepEqual(projected.keptIndices, [0]);
});
