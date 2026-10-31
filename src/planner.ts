import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fields, optionalFields, assertAuthorized, strictUrl, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope, Step, RequestSpec } from './scope.ts';
import { validateProjections } from './observations.ts';
import type { Projection } from './observations.ts';
import { semanticClasses, validatePolicy, validateSemanticChecks, evaluateSemantic, semanticMarkdown } from './semantic.ts';
import type { Policy, SemanticClass, SemanticChecks } from './semantic.ts';
import { validateSurfaceBundle } from './surface.ts';
import { createSession, inspectSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import { executeSession } from './execution.ts';
import { digest } from './contracts.ts';
import type { ProgramBudget } from './budget.ts';

export type Profile = { schemaVersion: 1; accounts: [string, string]; identity: { url: string; fact: string; observe: Projection[] };
  rules: { class: SemanticClass; origin: string; pathPrefix: string; protectedPointer: string; subjectPointer: string | null; query: NonNullable<RequestSpec['query']>; policy: Policy }[];
  bindings?: { entryId: string; url: string }[] };

export function compileInvestigation(scope: Scope, bundle: unknown, input: unknown) {
  validateScope(scope); validateSurfaceBundle(bundle);
  optionalFields(input, ['schemaVersion', 'accounts', 'identity', 'rules'], ['bindings']);
  if (input.schemaVersion !== 1 || !Array.isArray(input.accounts) || input.accounts.length !== 2 || new Set(input.accounts).size !== 2
    || input.accounts.some((n: unknown) => typeof n !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(n))
    || !Array.isArray(input.rules) || !input.rules.length || input.rules.length > 20) throw new Error('Invalid investigation profile');
  fields(input.identity, ['url', 'fact', 'observe']); validateProjections(input.identity.observe); assertAuthorized(scope, input.identity.url);
  if (!input.identity.observe.some((p: Projection) => p.name === input.identity.fact)) throw new Error('Identity fact is not projected');
  const profile = input as Profile;
  const bindings = new Map<string, string>();
  if (profile.bindings !== undefined) {
    if (!Array.isArray(profile.bindings) || profile.bindings.length > 100) throw new Error('Invalid surface bindings');
    for (const binding of profile.bindings) {
      fields(binding, ['entryId', 'url']);
      const e = bundle.surface.entries.find(e => e.id === binding.entryId);
      if (!e || bindings.has(binding.entryId)) throw new Error('Unknown or duplicate surface binding');
      const url = assertAuthorized(scope, binding.url);
      const template = e.path.split('/'), actual = url.pathname.split('/');
      if (e.origin !== null && e.origin !== url.origin || template.length !== actual.length
        || template.some((part, i) => /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(part) ? !actual[i] : part !== actual[i])) throw new Error('Binding does not match the recorded surface');
      bindings.set(binding.entryId, binding.url);
    }
  }
  for (const r of profile.rules) {
    fields(r, ['class', 'origin', 'pathPrefix', 'protectedPointer', 'subjectPointer', 'query', 'policy']);
    if (!semanticClasses.includes(r.class) || typeof r.origin !== 'string' || typeof r.pathPrefix !== 'string'
      || strictUrl(r.origin + r.pathPrefix).origin !== r.origin || !Array.isArray(r.query) || r.query.length > 20) throw new Error('Invalid profile rule');
    const queryNames = new Set<string>();
    for (const q of r.query) {
      fields(q, ['name', 'valueEnv']);
      if (typeof q.name !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(q.name) || queryNames.has(q.name)
        || typeof q.valueEnv !== 'string' || !/^BBA_INPUT_[A-Z0-9_]{1,50}$/.test(q.valueEnv)) throw new Error('Invalid profile query binding');
      queryNames.add(q.name);
    }
    validatePolicy(r.policy, r.class);
    validateProjections([{ name: 'protected', pointer: r.protectedPointer }]);
    if (r.subjectPointer !== null) validateProjections([{ name: 'subject', pointer: r.subjectPointer }]);
  }
  const plan: Plan = { schemaVersion: 1, steps: profile.accounts.map((credentialEnv, i) => ({ id: i ? 'identity-b' : 'identity-a', method: 'GET', url: profile.identity.url, credentialEnv, observe: profile.identity.observe })) };
  const checks: SemanticChecks = { schemaVersion: 1, checks: [] };
  const coverage: { surfaceId: string; checkId: string | null; disposition: 'planned' | 'unresolved'; reason: string; source: { basis: string; locator: string } }[] = [];
  const used = new Set<string>();
  const entries = [...bundle.surface.entries].sort((a, b) => ((a.status === 200 ? 0 : 1) - (b.status === 200 ? 0 : 1)) || a.id.localeCompare(b.id));
  for (const e of entries) {
    const record = (checkId: string | null, reason: string) => coverage.push({ surfaceId: e.id, checkId, disposition: checkId ? 'planned' : 'unresolved', reason, source: { basis: e.basis, locator: e.locator } });
    const url = bindings.get(e.id) ?? (e.origin !== null && e.pathKind === 'literal' ? e.origin + e.path : null);
    if (!url) { record(null, 'Concrete controlled URL required for template or unknown origin.'); continue; }
    try { assertAuthorized(scope, url); } catch { record(null, 'Outside scope or excluded.'); continue; }
    if (url === profile.identity.url) { record(null, 'Identity endpoint used for controls; its other classes remain untested.'); continue; }
    if (e.method !== 'GET') { record(null, 'Semantic generators currently cover read-only GET.'); continue; }
    const location = strictUrl(url);
    const matching = profile.rules.filter(r => r.origin === location.origin && (location.pathname === r.pathPrefix || location.pathname.startsWith(r.pathPrefix.endsWith('/') ? r.pathPrefix : r.pathPrefix + '/')));
    if (!matching.length) { record(null, 'No declared business-boundary rule applies.'); continue; }
    for (const rule of matching) {
      const key = digest({ url, rule }), id = 'h-' + key.slice(0, 24);
      if (used.has(key)) { record(id, 'Same hypothesis reuses its existing comparison.'); continue; }
      if (e.parameters.some(p => p.location === 'query' && !rule.query.some(q => q.name === p.name))) { record(null, 'Recorded query parameters need explicit input bindings.'); continue; }
      if (plan.steps.length + 3 > Math.min(scope.limits.maxRequests, 100)) { record(null, 'Insufficient request budget for another complete comparison.'); continue; }
      const observe: Projection[] = [{ name: 'protected', pointer: rule.protectedPointer }];
      if (rule.policy.boundary === 'owner-only' || rule.policy.boundary === 'tenant-private') {
        if (rule.subjectPointer === null) throw new Error('Owner and tenant policies require a subject selector');
        observe.push({ name: rule.policy.boundary === 'owner-only' ? rule.policy.ownerFact : rule.policy.resourceTenantFact, pointer: rule.subjectPointer });
      }
      const steps: Step[] = [null, profile.accounts[0], profile.accounts[1]].map((credentialEnv, i) => ({
        id: id + ['-control', '-baseline', '-probe'][i], method: 'GET', url, credentialEnv, ...(rule.query.length ? { query: rule.query } : {}), ...(i ? { observe } : {}),
      }));
      try { validatePlan({ schemaVersion: 1, steps }, scope); } catch { record(null, 'Request inputs or method are not permitted by scope.'); continue; }
      plan.steps.push(...steps);
      checks.checks.push({ id, class: rule.class, control: steps[0].id, baseline: steps[1].id, probe: steps[2].id,
        identities: { baseline: 'identity-a', probe: 'identity-b', fact: profile.identity.fact }, protectedFact: 'protected', policy: rule.policy });
      used.add(key); record(id, 'Planned from recorded surface and operator-declared policy.');
    }
  }
  if (checks.checks.length) { validatePlan(plan, scope); validateSemanticChecks(checks, { plan } as Session); }
  return { schemaVersion: 1, scopeDigest: digest(scope), surfaceDigest: bundle.sha256, profileDigest: digest(profile),
    checksDigest: digest(checks), plan: checks.checks.length ? plan : null, checks, coverage,
    limitations: ['Offline planning does not verify policy truth or execute recorded URLs.', 'Template bindings must refer to controlled test resources.', 'Coverage records planning, not successful testing. Non-selected classes remain unresolved.'] };
}

export async function resumeInvestigation(folder: string, scope: Scope, output: string, options: { credentials?: Record<string, string | undefined>; signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateScope(scope);
  const envelope = readJson(join(folder, 'coverage.json')); fields(envelope, ['coverage', 'sha256']);
  const checks = readJson(join(folder, 'checks.json'));
  if (envelope.sha256 !== digest(envelope.coverage) || envelope.coverage.scopeDigest !== digest(scope)
    || envelope.coverage.checksDigest !== digest(checks)) throw new Error('Investigation definition integrity mismatch');
  const before = inspectSession(join(folder, 'run'));
  if (before.scopeDigest !== digest(scope)) throw new Error('Investigation run scope mismatch');
  validateSemanticChecks(checks, before);
  const stopWhen = (s: Session) => evaluateSemantic(s, checks).findings.some(f => f.status === 'confirmed');
  const session = before.status === 'stopped' && before.stopReason === 'proof-complete' ? before
    : await executeSession(join(folder, 'run'), scope, { ...options, stopWhen });
  const result = evaluateSemantic(session, checks);
  writeFileSync(output, output.endsWith('.md') ? semanticMarkdown(result) : JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  return { requests: session.attempts.length, newRequests: session.attempts.length - before.attempts.length, stopped: session.stopReason, findings: result.findings };
}

export function prepareCompiled(folder: string, scope: Scope, bundle: unknown, profile: unknown) {
  const compiled = compileInvestigation(scope, bundle, profile);
  const { plan, checks, ...coverage } = compiled;
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  for (const [name, value] of Object.entries({ scope, plan, checks, profile, coverage: { coverage, sha256: digest(coverage) } })) {
    writeFileSync(join(folder, name + '.json'), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  return compiled;
}

export async function investigateSurface(folder: string, scope: Scope, bundle: unknown, profile: unknown, options: { credentials?: Record<string, string | undefined>; signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  const compiled = prepareCompiled(folder, scope, bundle, profile);
  if (!compiled.plan) {
    writeFileSync(join(folder, 'report.md'), '# BBA — sin hipótesis ejecutables\n\nNo se enviaron solicitudes. Consultá coverage.json para las brechas de alcance, configuración y presupuesto. No hay conclusión sobre seguridad.\n', { flag: 'wx' });
    return { requests: 0, stopped: 'no-testable-hypotheses', findings: [] };
  }
  createSession(join(folder, 'run'), scope, compiled.plan);
  const session = await executeSession(join(folder, 'run'), scope, { ...options, stopWhen: s => evaluateSemantic(s, compiled.checks).findings.some(f => f.status === 'confirmed') });
  const result = evaluateSemantic(session, compiled.checks);
  writeFileSync(join(folder, 'semantic.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'report.md'), semanticMarkdown(result) + '\n\nConsultá coverage.json: las hipótesis sin evidencia completa y las clases no seleccionadas siguen pendientes.\n', { flag: 'wx', mode: 0o600 });
  return { requests: session.attempts.length, stopped: session.stopReason, findings: result.findings };
}
