import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fixture } from './support.ts';
import { createSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import { evidenceView, compareSessions } from '../src/evidence.ts';
import type { Plan } from '../src/scope.ts';

test('evidence pages have stable IDs, bounded selection, revision checks and queryable facts', async () => {
  let version = 1;
  await fixture((_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ id: 'secret-id', version })); }, async (scope, folder) => {
    const plan: Plan = { schemaVersion: 1, steps: ['one', 'two'].map(id => ({ id, method: 'GET', url: scope.allowed[0].origin + '/', credentialEnv: null,
      observe: [{ name: 'identity', pointer: '/id' }, { name: 'version', pointer: '/version' }] })) };
    createSession(join(folder, 'before'), scope, plan); const a = await executeSession(join(folder, 'before'), scope);
    const summary = evidenceView(a, { kind: 'summary', offset: 0, limit: 10 });
    assert.equal(summary.parentEvidenceId, a.id);
    const page: any = evidenceView(a, { kind: 'fields', offset: 0, limit: 1, expectedDigest: summary.revisionDigest });
    const next: any = evidenceView(a, { kind: 'fields', offset: page.nextOffset, limit: 1, expectedDigest: page.revisionDigest });
    assert.equal(page.total, 4); assert.notEqual(page.items[0].evidenceId, next.items[0].evidenceId);
    assert.equal(page.items[0].parentEvidenceId, a.id + ':one'); assert.equal(page.items[0].pointer, '/id');
    assert.ok(!JSON.stringify(page).includes('secret-id'));
    assert.throws(() => evidenceView(a, { kind: 'attempts', offset: 0, limit: 51 }));
    assert.throws(() => evidenceView(a, { kind: 'attempts', offset: 0, limit: 1, expectedDigest: 'stale' }), /revision changed/);
    version = 2; createSession(join(folder, 'after'), scope, plan); const b = await executeSession(join(folder, 'after'), scope);
    const comparison = compareSessions(a, b);
    assert.equal(comparison.steps[0].inputsComparable, true); assert.equal(comparison.steps[0].bodyDigestEqual, false);
    assert.equal(comparison.steps[0].fields[0].digestEqual, true); assert.equal(comparison.steps[0].fields[1].digestEqual, false);
  });
});
