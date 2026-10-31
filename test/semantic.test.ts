import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { createSession, inspectSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import type { Plan } from '../src/scope.ts';
import { semanticClasses, evaluateSemantic, evaluateSemanticFile, validateSemanticChecks, semanticMarkdown } from '../src/semantic.ts';
import type { SemanticClass, SemanticChecks } from '../src/semantic.ts';
import { writeFile } from 'node:fs/promises';

export function semanticPlan(origin: string, kind: SemanticClass): { plan: Plan; checks: SemanticChecks } {
  const identity = [{ name: 'identity', pointer: '/id' }, { name: 'role', pointer: '/role' }, { name: 'tenant', pointer: '/tenant' }];
  const fields = [{ name: 'protected', pointer: '/private/value' }, { name: 'owner', pointer: '/owner' }, { name: 'resource-tenant', pointer: '/tenant' }];
  return {
    plan: { schemaVersion: 1, steps: [
      { id: 'identity-a', method: 'GET', url: origin + '/me', credentialEnv: 'BBA_TOKEN_A', observe: identity },
      { id: 'identity-b', method: 'GET', url: origin + '/me', credentialEnv: 'BBA_TOKEN_B', observe: identity },
      { id: 'control', method: 'GET', url: origin + '/resource', credentialEnv: null },
      { id: 'baseline', method: 'GET', url: origin + '/resource', credentialEnv: 'BBA_TOKEN_A', observe: fields },
      { id: 'probe', method: 'GET', url: origin + '/resource', credentialEnv: 'BBA_TOKEN_B', observe: fields },
    ] }, checks: { schemaVersion: 1, checks: [{ id: 'boundary', class: kind, control: 'control', baseline: 'baseline', probe: 'probe',
      identities: { baseline: 'identity-a', probe: 'identity-b', fact: 'identity' }, protectedFact: 'protected',
      policy: kind === 'bola' ? { reference: 'synthetic owner-only rule', boundary: 'owner-only', ownerFact: 'owner' }
        : kind === 'tenant-isolation' ? { reference: 'synthetic tenant-only rule', boundary: 'tenant-private', tenantFact: 'tenant', resourceTenantFact: 'resource-tenant' }
        : { reference: 'synthetic role-only rule', boundary: 'role-private', roleFact: 'role', baselineRole: 'admin', probeRole: 'member' } }] },
  };
}

for (const kind of semanticClasses) for (const variant of ['vulnerable', 'denied', 'filtered', 'different', 'public', 'same-identity', 'wrong-role', 'same-tenant', 'expired', 'wrong-owner', 'malformed', 'budget']) {
  test(`${kind} semantic proof: ${variant}`, async () => {
    await fixture((req, res) => {
      const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a' : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
      const json = (status: number, body: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.url === '/me') return json(200, { id: variant === 'same-identity' ? 'a' : actor, role: actor === 'a' || variant === 'wrong-role' ? 'admin' : 'member', tenant: actor === 'a' || variant === 'same-tenant' ? 'tenant-a' : 'tenant-b' });
      if (!actor && variant !== 'public') return json(401, {});
      if (actor === 'b' && variant === 'denied') return json(403, {});
      if (actor === 'b' && variant === 'expired') return json(401, {});
      if (actor === 'b' && variant === 'malformed') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{'); return; }
      return json(200, { owner: variant === 'wrong-owner' ? 'unknown-owner' : 'a', tenant: 'tenant-a',
        ...(actor === 'b' && variant === 'filtered' ? {} : { private: { value: actor === 'b' && variant === 'different' ? 'different' : 'SYNTHETIC_PROTECTED_VALUE' } }),
        nonce: actor === 'b' ? 'different-whole-body' : 'baseline-whole-body' });
    }, async (scope, folder) => {
      const origin = scope.allowed[0].origin; scope.allowed[0].paths = ['/me', '/resource'];
      if (variant === 'budget') scope.limits.maxRequests = 4;
      const { plan, checks } = semanticPlan(origin, kind);
      createSession(join(folder, 'run'), scope, plan);
      const state = await executeSession(join(folder, 'run'), scope, { credentials: { BBA_TOKEN_A: 'synthetic-a', BBA_TOKEN_B: 'synthetic-b' } });
      const result = evaluateSemantic(state, checks);
      const expected = ['denied', 'filtered'].includes(variant) ? 'not-reproduced'
        : ['different', 'public', 'same-identity', 'expired', 'malformed', 'budget'].includes(variant)
          || variant === 'wrong-role' && ['bfla', 'property-exposure', 'mass-assignment'].includes(kind)
          || variant === 'same-tenant' && kind === 'tenant-isolation' || variant === 'wrong-owner' && kind === 'bola' ? 'unresolved' : 'confirmed';
      assert.equal(result.findings[0].status, expected, JSON.stringify(result));
      assert.ok(result.findings[0].evidence.every(id => id.startsWith(state.id + ':')));
      assert.ok(!JSON.stringify(state).includes('SYNTHETIC_PROTECTED_VALUE'));
      assert.deepEqual(evaluateSemantic(inspectSession(join(folder, 'run')), checks), result);
      if (variant === 'vulnerable') {
        assert.notEqual(state.attempts[3].response!.sha256, state.attempts[4].response!.sha256, 'whole-body equality is unnecessary');
        const invalid = structuredClone(checks); invalid.checks[0].identities.probe = 'identity-a'; assert.throws(() => validateSemanticChecks(invalid, state));
        const changed = structuredClone(state); changed.plan.steps[4].observe![0].pointer = '/other'; assert.throws(() => validateSemanticChecks(checks, changed), /selectors differ/);
        await writeFile(join(folder, 'checks.json'), JSON.stringify(checks));
        evaluateSemanticFile(join(folder, 'run'), join(folder, 'checks.json'), join(folder, 'report.md'));
        const report = await readFile(join(folder, 'report.md'), 'utf8');
        assert.equal(report, semanticMarkdown(result));
        for (const heading of ['Qué es', 'Cómo se encontró', 'Demostración de explotabilidad', 'Cómo reproducirlo', 'Cómo corregirlo'])
          assert.ok(report.includes('### ' + heading), heading);
        assert.throws(() => evaluateSemanticFile(join(folder, 'run'), join(folder, 'checks.json'), join(folder, 'report.md')), /EEXIST/);
      }
    });
  });
}
