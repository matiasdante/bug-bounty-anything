import { writeFileSync } from 'node:fs';
import { digest } from './contracts.ts';
import { fields, requestSpec } from './scope.ts';
import type { Step } from './scope.ts';
import { inspectSession, readJson, validateSession } from './session.ts';
import type { Session } from './session.ts';
import type { Fact } from './observations.ts';
import type { Lang } from './i18n.ts';

export const semanticClasses = ['bola', 'bfla', 'property-exposure', 'tenant-isolation'] as const;
export type SemanticClass = typeof semanticClasses[number];
export type Policy = { reference: string } & (
  { boundary: 'owner-only'; ownerFact: string }
  | { boundary: 'role-private'; roleFact: string; baselineRole: string; probeRole: string }
  | { boundary: 'tenant-private'; tenantFact: string; resourceTenantFact: string });
export type SemanticCheck = { id: string; class: SemanticClass; control: string; baseline: string; probe: string;
  identities: { baseline: string; probe: string; fact: string }; protectedFact: string; policy: Policy };
export type SemanticChecks = { schemaVersion: 1; checks: SemanticCheck[] };
export type SemanticFinding = { id: string; class: SemanticClass; url: string; status: 'confirmed' | 'not-reproduced' | 'unresolved';
  reason: string; policy: Policy; evidence: string[]; signature: string };
export type SemanticResult = { schemaVersion: 1; sessionId: string; scopeDigest: string; checksDigest: string; findings: SemanticFinding[]; limitations: string[] };

const name = (s: unknown) => typeof s === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(s);
const projection = (s: Step, field: string) => s.observe?.find(p => p.name === field);
export function validatePolicy(value: unknown, kind: SemanticClass): asserts value is Policy {
  if (!value || typeof value !== 'object') throw new Error('Invalid semantic policy');
  const p = value as Record<string, any>;
  if (typeof p.reference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(p.reference)) throw new Error('Invalid semantic policy reference');
  if (kind === 'bola') {
    fields(p, ['reference', 'boundary', 'ownerFact']);
    if (p.boundary !== 'owner-only' || !name(p.ownerFact)) throw new Error('Invalid owner policy');
  } else if (kind === 'tenant-isolation') {
    fields(p, ['reference', 'boundary', 'tenantFact', 'resourceTenantFact']);
    if (p.boundary !== 'tenant-private' || !name(p.tenantFact) || !name(p.resourceTenantFact)) throw new Error('Invalid tenant policy');
  } else {
    fields(p, ['reference', 'boundary', 'roleFact', 'baselineRole', 'probeRole']);
    if (p.boundary !== 'role-private' || !name(p.roleFact) || typeof p.baselineRole !== 'string' || typeof p.probeRole !== 'string'
      || !/^[A-Za-z0-9_.-]{1,64}$/.test(p.baselineRole) || !/^[A-Za-z0-9_.-]{1,64}$/.test(p.probeRole) || p.baselineRole === p.probeRole) throw new Error('Invalid role policy');
  }
}
export function validateSemanticChecks(value: unknown, session: Session): asserts value is SemanticChecks {
  fields(value, ['schemaVersion', 'checks']);
  if (value.schemaVersion !== 1 || !Array.isArray(value.checks) || !value.checks.length || value.checks.length > 50) throw new Error('Invalid semantic checks');
  const steps = new Map(session.plan.steps.map((s, i) => [s.id, { ...s, index: i }]));
  const ids = new Set<string>();
  for (const check of value.checks) {
    fields(check, ['id', 'class', 'control', 'baseline', 'probe', 'identities', 'protectedFact', 'policy']);
    if (!name(check.id) || ids.has(check.id) || !semanticClasses.includes(check.class) || !name(check.protectedFact)) throw new Error('Invalid semantic check');
    ids.add(check.id);
    fields(check.identities, ['baseline', 'probe', 'fact']);
    if (!name(check.identities.fact)) throw new Error('Invalid identity fact');
    const [control, baseline, probe, identityA, identityB] = [check.control, check.baseline, check.probe, check.identities.baseline, check.identities.probe].map(id => steps.get(id));
    if (!control || !baseline || !probe || !identityA || !identityB
      || new Set([control.id, baseline.id, probe.id, identityA.id, identityB.id]).size !== 5) throw new Error('Five distinct evidence steps are required');
    if ([control, baseline, probe, identityA, identityB].some(s => s.method !== 'GET')) throw new Error('Semantic checks require read-only GET comparisons');
    if (control.credentialEnv !== null || !baseline.credentialEnv || !probe.credentialEnv || baseline.credentialEnv === probe.credentialEnv
      || identityA.credentialEnv !== baseline.credentialEnv || identityB.credentialEnv !== probe.credentialEnv) throw new Error('Semantic identities do not match request credentials');
    if (identityA.url !== identityB.url || digest(requestSpec(identityA)) !== digest(requestSpec(identityB))
      || new URL(identityA.url).origin !== new URL(baseline.url).origin
      || Math.max(identityA.index, identityB.index) >= Math.min(control.index, baseline.index, probe.index)) throw new Error('Identity controls must precede comparisons on the same origin and identity endpoint');
    if (control.url !== baseline.url || baseline.url !== probe.url || digest(requestSpec(control)) !== digest(requestSpec(baseline))
      || digest(requestSpec(baseline)) !== digest(requestSpec(probe))) throw new Error('Semantic comparisons require the same request');
    const requireFact = (s: Step, field: string) => { if (!name(field) || !projection(s, field)) throw new Error('Semantic proof requires declared projections'); };
    requireFact(identityA, check.identities.fact); requireFact(identityB, check.identities.fact);
    if (projection(identityA, check.identities.fact)!.pointer !== projection(identityB, check.identities.fact)!.pointer) throw new Error('Identity selectors differ');
    requireFact(baseline, check.protectedFact); requireFact(probe, check.protectedFact);
    if (projection(baseline, check.protectedFact)!.pointer !== projection(probe, check.protectedFact)!.pointer) throw new Error('Protected selectors differ');
    const p = check.policy;
    validatePolicy(p, check.class);
    if (p.boundary === 'owner-only') {
      requireFact(baseline, p.ownerFact); requireFact(probe, p.ownerFact);
      if (projection(baseline, p.ownerFact)!.pointer !== projection(probe, p.ownerFact)!.pointer) throw new Error('Owner selectors differ');
    } else if (p.boundary === 'tenant-private') {
      for (const s of [identityA, identityB]) requireFact(s, p.tenantFact);
      for (const s of [baseline, probe]) requireFact(s, p.resourceTenantFact);
      if (projection(identityA, p.tenantFact)!.pointer !== projection(identityB, p.tenantFact)!.pointer
        || projection(baseline, p.resourceTenantFact)!.pointer !== projection(probe, p.resourceTenantFact)!.pointer) throw new Error('Tenant selectors differ');
    } else {
      for (const s of [identityA, identityB]) requireFact(s, p.roleFact);
      if (projection(identityA, p.roleFact)!.pointer !== projection(identityB, p.roleFact)!.pointer) throw new Error('Role selectors differ');
    }
  }
}

const scalar = (f: Fact | undefined) => !!f?.meaningful && ['string', 'number'].includes(f.kind);
const equal = (a: Fact | undefined, b: Fact | undefined) => !!a?.meaningful && !!b?.meaningful && a.kind === b.kind && a.sha256 === b.sha256;
export function evaluateSemantic(session: Session, value: unknown): SemanticResult {
  validateSession(session); validateSemanticChecks(value, session);
  const response = (id: string) => session.attempts.find(a => a.stepId === id && a.outcome === 'succeeded')?.response;
  const fact = (id: string, name: string) => response(id)?.facts?.find(f => f.name === name);
  const findings = value.checks.map((c): SemanticFinding => {
    const url = session.plan.steps.find(s => s.id === c.baseline)!.url;
    const evidence = [c.identities.baseline, c.identities.probe, c.control, c.baseline, c.probe].map(id => session.id + ':' + id);
    const result: SemanticFinding = { id: c.id, class: c.class, url, status: 'unresolved', reason: 'Required evidence is incomplete.', policy: c.policy, evidence,
      signature: digest({ class: c.class, url, policy: c.policy, pointer: session.plan.steps.find(s => s.id === c.baseline)!.observe!.find(p => p.name === c.protectedFact)!.pointer }) };
    const a = c.identities.baseline, b = c.identities.probe;
    const identityA = fact(a, c.identities.fact), identityB = fact(b, c.identities.fact);
    if (response(a)?.status !== 200 || response(b)?.status !== 200 || !scalar(identityA) || !scalar(identityB)
      || identityA!.kind !== identityB!.kind || equal(identityA, identityB)) { result.reason = 'Two distinct server identities were not established.'; return result; }
    const p = c.policy;
    if (p.boundary === 'role-private') {
      if (fact(a, p.roleFact)?.sha256 !== digest(p.baselineRole) || fact(b, p.roleFact)?.sha256 !== digest(p.probeRole)
        || fact(a, p.roleFact)?.kind !== 'string' || fact(b, p.roleFact)?.kind !== 'string') { result.reason = 'Required privileged and restricted server roles were not established.'; return result; }
    } else if (p.boundary === 'tenant-private') {
      const ta = fact(a, p.tenantFact), tb = fact(b, p.tenantFact);
      if (!scalar(ta) || !scalar(tb) || ta!.kind !== tb!.kind || equal(ta, tb)) { result.reason = 'Distinct server tenants were not established.'; return result; }
    }
    if (!response(c.control) || !response(c.baseline) || !response(c.probe)) return result;
    if (![401, 403, 404].includes(response(c.control)!.status)) { result.reason = 'The anonymous boundary was not established.'; return result; }
    const protectedA = fact(c.baseline, c.protectedFact), protectedB = fact(c.probe, c.protectedFact);
    if (response(c.baseline)!.status !== 200 || !protectedA?.meaningful) { result.reason = 'The authorized protected-field baseline was not established.'; return result; }
    if (p.boundary === 'owner-only' && !equal(fact(c.baseline, p.ownerFact), identityA)) { result.reason = 'Baseline ownership did not match the server identity.'; return result; }
    if (p.boundary === 'tenant-private' && !equal(fact(c.baseline, p.resourceTenantFact), fact(a, p.tenantFact))) { result.reason = 'Baseline resource tenant did not match the server tenant.'; return result; }
    if ([403, 404].includes(response(c.probe)!.status)) { result.status = 'not-reproduced'; result.reason = 'The controlled restricted identity was denied for this comparison.'; return result; }
    if (response(c.probe)!.status !== 200) { result.reason = 'Probe failed or authentication may have expired.'; return result; }
    if (protectedB?.kind === 'missing') { result.status = 'not-reproduced'; result.reason = 'This protected JSON property was absent; other fields remain untested.'; return result; }
    if (!equal(protectedA, protectedB)) { result.reason = 'Matching protected data was not demonstrated; partial exposure remains unknown.'; return result; }
    if (p.boundary === 'owner-only' && !equal(fact(c.probe, p.ownerFact), identityA)) { result.reason = 'Probe resource ownership was not established.'; return result; }
    if (p.boundary === 'tenant-private' && !equal(fact(c.probe, p.resourceTenantFact), fact(a, p.tenantFact))) { result.reason = 'Probe resource tenant was not established.'; return result; }
    result.status = 'confirmed'; result.reason = 'The controlled restricted identity received the protected field matching the authorized baseline under the declared policy.';
    return result;
  });
  return { schemaVersion: 1, sessionId: session.id, scopeDigest: session.scopeDigest, checksDigest: digest(value), findings,
    limitations: ['Policy semantics, controlled-account ownership and absence of shared grants are operator preconditions.',
      'This confirms only the recorded read exposure. It does not establish writes, other fields, broader coverage or bounty eligibility.',
      'Field digests and server-identity/role/tenant controls are retained; raw values and credentials are not. Low-entropy digests can be guessed.',
      'Identity controls describe the observed requests; sessions and application state must remain consistent between requests.'] };
}

export function semanticMarkdown(r: SemanticResult, lang: Lang = 'es'): string {
  if (lang === 'en') {
    return '# BBA — semantic checks\n\nSession: `' + r.sessionId + '`. Local draft for review; not submitted.\n\n'
      + r.findings.map(f => `## ${f.id}: ${f.class} — ${f.status}\n\n`
        + `### What it is\n\nAccess comparison on \`${f.url}\` under declared rule ${f.policy.reference} (${f.policy.boundary}). `
        + (f.status === 'confirmed' ? 'Protected field exposure to the restricted identity was observed on this controlled resource.'
          : 'Evidence from this comparison does not confirm exploitation.') + '\n\n'
        + `### How it was found\n\nImported surface and profile rule generated the anonymous control, authorized baseline, and restricted probe. See \`coverage.json\` for route provenance and untested checks.\n\n`
        + `### Exploitability proof\n\nStatus: **${f.status}**. ${f.reason} Verifiable evidence: ${f.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
        + `### Reproduction\n\n1. Confirm authorization, scope, and test accounts.\n2. Execute the retained plan with anonymous control, owner identity, and restricted identity against the same resource.\n3. Compare the protected field and declared identity/role/tenant facts in \`checks.json\`; never replay uncertain reservations.\n\n`
        + `### Remediation\n\nEnforce resource, role, tenant, or property authorization before serializing protected fields.\n`).join('\n')
      + '\n## Limitations\n\n' + r.limitations.map(l => '- ' + l).join('\n') + '\n';
  }
  return '# BBA — comprobaciones semánticas\n\nSesión: `' + r.sessionId + '`. Borrador para revisión; no enviado.\n\n'
    + r.findings.map(f => `## ${f.id}: ${f.class} — ${f.status}\n\n`
      + `### Qué es\n\nComparación de acceso al recurso \`${f.url}\` bajo la regla declarada ${f.policy.reference} (${f.policy.boundary}). `
      + (f.status === 'confirmed' ? 'Se observó lectura del campo protegido por la identidad restringida en este recurso controlado.'
        : 'La evidencia de esta comparación no confirma explotación.') + '\n\n'
      + `### Cómo se encontró\n\nLa superficie importada y la regla del perfil generaron el control anónimo, el baseline autorizado y la sonda restringida. Consultá \`coverage.json\` para la procedencia exacta de la ruta y los checks no ejecutados.\n\n`
      + `### Demostración de explotabilidad\n\nEstado: **${f.status}**. ${f.reason} Evidencia verificable: ${f.evidence.map(id => '`' + id + '`').join(', ')}. `
      + (f.status === 'confirmed' ? 'El efecto demostrado se limita a la lectura de este campo; no prueba acceso a otros recursos o acciones.'
        : 'No se debe afirmar impacto o severidad a partir de este resultado.') + '\n\n'
      + `### Cómo reproducirlo\n\n1. Confirmar autorización, scope y cuentas de prueba del expediente.\n2. Ejecutar el plan retenido con control anónimo, identidad propietaria y otra identidad controlada sobre el mismo recurso.\n3. Comparar el campo protegido y los hechos de identidad, rol o tenant declarados en \`checks.json\`; verificar los IDs anteriores en la sesión SQLite. No repetir reservas inciertas.\n\n`
      + `### Cómo corregirlo\n\nAplicar autorización por recurso, rol, tenant o propiedad antes de serializar el campo protegido, según la frontera declarada. Agregar una regresión con las dos identidades y el control anónimo; la sonda restringida debe ser denegada o no recibir el campo. La severidad depende del contexto real y del programa.\n`).join('\n')
    + '\n## Límites\n\n' + r.limitations.map(l => '- ' + l).join('\n') + '\n';
}

export function evaluateSemanticFile(folder: string, checksPath: string, output: string, lang: Lang = 'es'): SemanticResult {
  const result = evaluateSemantic(inspectSession(folder), readJson(checksPath));
  writeFileSync(output, output.endsWith('.md') ? semanticMarkdown(result, lang) : JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return result;
}
