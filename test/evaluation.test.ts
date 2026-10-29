import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FROZEN_DIGEST, frozenManifest, runEvaluation } from '../src/evaluation.ts';

test('the frozen set is unchanged and every mandatory case passes with the expected metrics', async () => {
  assert.equal(frozenManifest(), FROZEN_DIGEST, 'ids, groups and expectations are frozen; change the digest only on purpose');
  const report = await runEvaluation();
  assert.deepEqual(report.cases.filter(c => !c.passed), []);
  assert.deepEqual({ ...report.metrics, requests: 0, ms: 0 }, {
    cases: 18, passed: 18, requests: 0, ms: 0, detections: 3, omissions: 0, falsePositives: 0, unresolvedAsExpected: 3,
    scopeViolations: 0, secretOccurrences: 0, repeatedRequests: 0,
  });
  for (const group of ['detection', 'inconclusive', 'scope', 'secrets', 'recovery']) assert.ok(report.cases.some(c => c.group === group), group);
  assert.match(report.limitations.join(' '), /do not estimate detection rates/);
});

test('CLI eval writes a Markdown report, exits 0 and refuses to overwrite', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-eval-cli-'));
  try {
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const run = (...args: string[]) => promisify(execFile)(process.execPath, [cli, ...args])
      .then(r => ({ status: 0, ...r }), (e: { code: number; stdout: string; stderr: string }) => ({ status: e.code, stdout: e.stdout, stderr: e.stderr }));
    const first = await run('eval', '--out', join(dir, 'e.md'));
    assert.equal(first.status, 0, first.stdout + first.stderr);
    assert.equal(JSON.parse(first.stdout).passed, 18);
    assert.match(await readFile(join(dir, 'e.md'), 'utf8'), /\*\*18\/18\*\* casos esperados/);
    assert.equal((await run('eval', '--out', join(dir, 'e.md'))).status, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
