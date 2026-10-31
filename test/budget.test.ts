import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFile, readFile } from 'node:fs/promises';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { fixture } from './support.ts';
import { withProgramBudget, inspectBudget, usingScopeBudget } from '../src/budget.ts';
import { createSession, inspectSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import type { Plan } from '../src/scope.ts';
import { DatabaseSync } from 'node:sqlite';

test('shared program budget survives distinct run folders and enforces spacing, count and immutable limits', async () => {
  const hits: number[] = [];
  await fixture((_req, res) => { hits.push(Date.now()); res.end('ok'); }, async (scope, folder) => {
    scope.budgetId = 'same-program'; scope.limits.maxRequests = 3; scope.limits.minIntervalMs = 30;
    const scopePath = join(folder, 'scope.json'); await writeFile(scopePath, JSON.stringify(scope));
    const plan: Plan = { schemaVersion: 1, steps: ['one', 'two'].map(id => ({ id, method: 'GET', url: scope.allowed[0].origin + '/', credentialEnv: null })) };
    for (const phase of ['discovery', 'investigation']) {
      createSession(join(folder, phase), scope, plan);
      const state = await usingScopeBudget(scope, scopePath, budget => executeSession(join(folder, phase), scope, { budget }));
      assert.equal(state.status, phase === 'discovery' ? 'completed' : 'stopped');
      if (phase === 'investigation') assert.equal(state.stopReason, 'budget-exhausted');
    }
    assert.equal(hits.length, 3); for (let i = 1; i < hits.length; i++) assert.ok(hits[i] - hits[i - 1] >= 29);
    const location = join(folder, '.bba-budgets', 'same-program');
    assert.equal(inspectBudget(location).reservedRequests, 3);
    const changed = structuredClone(scope); changed.limits.maxRequests = 4;
    await assert.rejects(withProgramBudget(location, changed, async () => {}), /limits changed/);
    createSession(join(folder, 'unbound'), scope, plan); await assert.rejects(executeSession(join(folder, 'unbound'), scope), /budget runtime/);
    assert.equal(inspectSession(join(folder, 'unbound')).attempts.length, 0);
  });
});

test('paused runs reject another shared ledger location and a competing phase cannot acquire the budget', async () => {
  const controller = new AbortController();
  await fixture((_req, res) => { controller.abort(); res.end('ok'); }, async (scope, folder) => {
    scope.budgetId = 'locked-program';
    const plan: Plan = { schemaVersion: 1, steps: ['one', 'two'].map(id => ({ id, method: 'GET', url: scope.allowed[0].origin + '/', credentialEnv: null })) };
    createSession(join(folder, 'run'), scope, plan);
    await withProgramBudget(join(folder, 'budget'), scope, async budget => {
      await assert.rejects(withProgramBudget(join(folder, 'budget'), scope, async () => {}), /already active/);
      const paused = await executeSession(join(folder, 'run'), scope, { budget, signal: controller.signal }); assert.equal(paused.status, 'paused');
    });
    await assert.rejects(withProgramBudget(join(folder, 'different-budget'), scope, budget => executeSession(join(folder, 'run'), scope, { budget })), /location changed/);
    const result = await withProgramBudget(join(folder, 'budget'), scope, budget => executeSession(join(folder, 'run'), scope, { budget }));
    assert.ok(['completed', 'partial'].includes(result.status));
    assert.equal(inspectBudget(join(folder, 'budget')).reservedRequests, 2);
  });
});

test('process death retains uncertain reservations, releases the shared lock and detects journal corruption', async () => {
  await fixture((_req, res) => res.end(), async (scope, folder) => {
    scope.limits.timeoutMs = 50;
    const moduleUrl = new URL('../src/budget.ts', import.meta.url).href;
    const code = `import {withProgramBudget} from ${JSON.stringify(moduleUrl)}; await withProgramBudget(process.env.BBA_TEST_FOLDER,JSON.parse(process.env.BBA_TEST_SCOPE),async b=>{await b.beforeRequest('orphan');console.log('reserved');setInterval(()=>{},1000);await new Promise(()=>{});});`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', code], { env: { ...process.env, BBA_TEST_FOLDER: join(folder, 'budget'), BBA_TEST_SCOPE: JSON.stringify(scope) }, stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      await once(child.stdout, 'data'); const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
      assert.equal(inspectBudget(join(folder, 'budget')).uncertainRequests, 1);
      await withProgramBudget(join(folder, 'budget'), scope, async b => { await b.beforeRequest('next'); b.complete('next'); });
      assert.equal(inspectBudget(join(folder, 'budget')).reservedRequests, 2);
      const db = new DatabaseSync(join(folder, 'budget', 'budget.sqlite')); db.prepare('UPDATE events SET hash=? WHERE sequence=2').run('0'.repeat(64)); db.close();
      assert.throws(() => inspectBudget(join(folder, 'budget')), /chain/);
    } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  });
});

test('concurrent pair reserves both slots and retains both as uncertain after interruption', async () => {
  await fixture((_req, res) => res.end(), async (scope, folder) => {
    scope.limits.minIntervalMs = 0;
    scope.limits.maxRequests = 2;
    const location = join(folder, 'concurrent-budget');
    await withProgramBudget(location, scope, async budget => {
      await budget.beforeConcurrentPair(['first', 'second']);
      assert.equal(inspectBudget(location).uncertainRequests, 2);
      assert.equal(inspectBudget(location).reservedRequests, 2);
      await assert.rejects(budget.beforeRequest('third'), /budget-exhausted/);
    });
    await withProgramBudget(location, scope, async budget => {
      await assert.rejects(budget.beforeConcurrentPair(['first', 'second']), /cannot be replayed|Invalid concurrent pair/);
    });
    assert.equal(inspectBudget(location).uncertainRequests, 2);
  });
});
