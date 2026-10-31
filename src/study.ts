import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonical, digest } from './contracts.ts';
import { jwtIntegrityCheck, validateJwtIntegrity } from './jwt-integrity.ts';
import type { JwtIntegrityConfig, JwtIntegrityResult } from './jwt-integrity.ts';
import { fields, integer, isoDate, methods, strictUrl, validateScope } from './scope.ts';
import type { RequestSpec, Scope } from './scope.ts';
import { validateSurfaceBundle } from './surface.ts';
import type { ProgramBudget } from './budget.ts';
import type { Surface } from './surface.ts';
import { inspectSession, readJson } from './session.ts';

type Asset = { origin: string; pathPrefixes: string[] };
export type StudyPolicy = { schemaVersion: 1; mode: Scope['mode']; sourceUrl: string; reviewedAt: string;
  authorization: Scope['authorization']; assets: Asset[]; excluded: Asset[];
  techniques: ['jwt-signature-integrity']; budgetId: string; limits: Scope['limits'] };
type StudyCase = { schemaVersion: 1; id: string; title: string; author: string; published: string; sourceUrl: string;
  class: 'jwt-signature-integrity'; referenceOnly: true };
type Historical = { schemaVersion: 1; sourceUrl: string; capturedAt: string; routes: { path: string; clue: 'routing-definition' | 'endpoint-reference' }[] };
type Profile = { schemaVersion: 1; credentialEnv: string; proofPointer: string; request: RequestSpec;
  mutation: JwtIntegrityConfig['mutation'] };
export type StudyBundle = { schemaVersion: 1; case: StudyCase; policy: StudyPolicy;
  surface: { surface: Surface; sha256: string }; historical: Historical; profile: Profile };
type Candidate = { id: string; url: string; method: string; locator: string; historical: boolean };
export type StudyCompilation = { schemaVersion: 1; bundleDigest: string; status: 'ready' | 'unresolved'; reason: string;
  candidates: Candidate[]; selected: string | null; scope: Scope | null; config: JwtIntegrityConfig | null;
  graph: { nodes: { id: string; kind: string; basis: string }[]; edges: { from: string; to: string; relation: string }[] } };

function sourceUrl(value: unknown): void {
  if (typeof value !== 'string' || value.length > 512) throw new Error('Invalid source URL');
  let url: URL; try { url = new URL(value); } catch { throw new Error('Invalid source URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('Invalid source URL');
}
function prefix(value: unknown): string {
  if (typeof value !== 'string' || value.length > 512 || !value.startsWith('/') || value.startsWith('//')
    || /[%\\?#@\s{}]/.test(value) || value.split('/').some(part => part === '.' || part === '..')) throw new Error('Invalid path prefix');
  return value;
}
function asset(value: unknown, mode: Scope['mode']): asserts value is Asset {
  fields(value, ['origin', 'pathPrefixes']);
  const u = strictUrl(value.origin + '/');
  if (u.origin !== value.origin || (mode === 'public-https' ? u.protocol !== 'https:'
    : u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || !u.port)) throw new Error('Invalid policy asset');
  if (!Array.isArray(value.pathPrefixes) || !value.pathPrefixes.length || value.pathPrefixes.length > 30
    || new Set(value.pathPrefixes).size !== value.pathPrefixes.length) throw new Error('Invalid policy prefixes');
  value.pathPrefixes.forEach(prefix);
}
export function validateStudyPolicy(value: unknown): asserts value is StudyPolicy {
  fields(value, ['schemaVersion', 'mode', 'sourceUrl', 'reviewedAt', 'authorization', 'assets', 'excluded', 'techniques', 'budgetId', 'limits']);
  if (value.schemaVersion !== 1 || !['loopback-lab', 'public-https'].includes(value.mode)) throw new Error('Invalid study policy');
  sourceUrl(value.sourceUrl); isoDate(value.reviewedAt);
  fields(value.authorization, ['reference', 'validFrom', 'validUntil']);
  isoDate(value.authorization.validFrom); isoDate(value.authorization.validUntil);
  if (value.authorization.validFrom >= value.authorization.validUntil
    || typeof value.authorization.reference !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.authorization.reference)) throw new Error('Invalid policy authorization');
  if (!Array.isArray(value.assets) || !value.assets.length || value.assets.length > 20
    || !Array.isArray(value.excluded) || value.excluded.length > 20) throw new Error('Invalid policy assets');
  value.assets.forEach((a: unknown) => asset(a, value.mode));
  value.excluded.forEach((a: unknown) => asset(a, value.mode));
  if (!Array.isArray(value.techniques) || value.techniques.length !== 1 || value.techniques[0] !== 'jwt-signature-integrity'
    || typeof value.budgetId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value.budgetId)) throw new Error('Invalid study technique or budget');
  fields(value.limits, ['maxRequests', 'minIntervalMs', 'timeoutMs', 'maxResponseBytes', 'maxDurationMs']);
  integer(value.limits.maxRequests, 4, 100); integer(value.limits.minIntervalMs, 0, 60000);
  integer(value.limits.timeoutMs, 1, 60000); integer(value.limits.maxResponseBytes, 1, 1024 * 1024);
  integer(value.limits.maxDurationMs, 1, 86400000);
}
function matchPrefix(path: string, start: string): boolean {
  return start === '/' || path === start || path.startsWith(start.endsWith('/') ? start : start + '/');
}
function policyAllows(policy: StudyPolicy, origin: string, path: string): boolean {
  const match = (a: Asset) => a.origin === origin && a.pathPrefixes.some(p => matchPrefix(path, p));
  return policy.assets.some(match) && !policy.excluded.some(match);
}
export function validateStudyBundle(value: unknown): asserts value is StudyBundle {
  fields(value, ['schemaVersion', 'case', 'policy', 'surface', 'historical', 'profile']);
  if (value.schemaVersion !== 1) throw new Error('Invalid study bundle');
  fields(value.case, ['schemaVersion', 'id', 'title', 'author', 'published', 'sourceUrl', 'class', 'referenceOnly']);
  const c = value.case;
  if (c.schemaVersion !== 1 || typeof c.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(c.id)
    || typeof c.title !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 .,:'!?-]{0,119}$/.test(c.title)
    || typeof c.author !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 .'-]{0,79}$/.test(c.author)
    || !/^\d{4}-\d\d-\d\d$/.test(c.published) || Number.isNaN(Date.parse(c.published))
    || c.class !== 'jwt-signature-integrity' || c.referenceOnly !== true) throw new Error('Invalid published case');
  sourceUrl(c.sourceUrl); validateStudyPolicy(value.policy); validateSurfaceBundle(value.surface);
  fields(value.historical, ['schemaVersion', 'sourceUrl', 'capturedAt', 'routes']);
  if (value.historical.schemaVersion !== 1 || !Array.isArray(value.historical.routes) || value.historical.routes.length > 50) throw new Error('Invalid historical hints');
  sourceUrl(value.historical.sourceUrl); isoDate(value.historical.capturedAt);
  for (const route of value.historical.routes) {
    fields(route, ['path', 'clue']); prefix(route.path);
    if (!['routing-definition', 'endpoint-reference'].includes(route.clue)) throw new Error('Invalid historical clue');
  }
  fields(value.profile, ['schemaVersion', 'credentialEnv', 'proofPointer', 'request', 'mutation']);
  if (value.profile.schemaVersion !== 1 || typeof value.profile.credentialEnv !== 'string'
    || !/^BBA_TOKEN_[A-Z0-9_]{1,50}$/.test(value.profile.credentialEnv)
    || typeof value.profile.proofPointer !== 'string') throw new Error('Invalid study profile');
  if (!value.profile.request || !methods.includes(value.profile.request.method)) throw new Error('Invalid study request');
}

export function assembleStudyBundle(input: { caseFile: string; policy: string; surface: string; historical: string; profile: string }, output: string): StudyBundle {
  const bundle = { schemaVersion: 1, case: readJson(input.caseFile), policy: readJson(input.policy),
    surface: readJson(input.surface), historical: readJson(input.historical), profile: readJson(input.profile) };
  validateStudyBundle(bundle);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(bundle, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return bundle;
}

export function compileStudy(value: unknown): StudyCompilation {
  validateStudyBundle(value);
  const bundle = value, policy = bundle.policy, surface = bundle.surface.surface;
  const candidates: Candidate[] = [];
  for (const entry of surface.entries) {
    if (entry.basis !== 'declared' || entry.pathKind !== 'literal' || !entry.origin
      || entry.authentication !== 'declared-optional' || entry.method !== bundle.profile.request.method
      || !policyAllows(policy, entry.origin, entry.path)) continue;
    const siblingRequired = surface.entries.some(other => other.origin === entry.origin && other.authentication === 'declared-required');
    if (!siblingRequired) continue;
    candidates.push({ id: entry.id, url: entry.origin + entry.path, method: entry.method, locator: entry.locator,
      historical: bundle.historical.routes.some(r => r.path === entry.path) });
  }
  const narrowed = candidates.some(c => c.historical) ? candidates.filter(c => c.historical) : candidates;
  const selected = narrowed.length === 1 ? narrowed[0] : null;
  let status: StudyCompilation['status'] = 'unresolved';
  let reason = candidates.length ? 'More than one plausible authentication exception; bind one candidate explicitly.'
    : 'No in-policy optional-auth operation with a protected sibling was declared.';
  let scope: Scope | null = null, config: JwtIntegrityConfig | null = null;
  if (selected) {
    const u = strictUrl(selected.url);
    scope = { schemaVersion: 1, mode: policy.mode, authorization: policy.authorization,
      allowed: [{ origin: u.origin, paths: [u.pathname] }], excluded: [], budgetId: policy.budgetId,
      requestRules: [{ origin: u.origin, path: u.pathname, method: bundle.profile.request.method,
        queryNames: (bundle.profile.request.query ?? []).map(q => q.name),
        bodyFormats: bundle.profile.request.body ? [bundle.profile.request.body.format] : [] }], limits: policy.limits };
    validateScope(scope);
    config = { schemaVersion: 1, policyReference: policy.authorization.reference, boundary: 'jwt-signature-integrity',
      url: selected.url, request: bundle.profile.request, credentialEnv: bundle.profile.credentialEnv,
      proofPointer: bundle.profile.proofPointer, mutation: bundle.profile.mutation };
    validateJwtIntegrity(config, scope, false);
    status = 'ready'; reason = selected.historical
      ? 'One declared authentication exception matched the policy and historical clue.'
      : 'One declared authentication exception matched the policy; no historical route corroborated it.';
  }
  const nodes = [{ id: 'source:api:' + surface.sourceDigest, kind: 'source', basis: 'declared' },
    { id: 'source:historical:' + digest(bundle.historical), kind: 'source', basis: 'historical' },
    ...surface.entries.map(e => ({ id: e.id, kind: 'endpoint', basis: e.basis })),
    { id: 'hypothesis:jwt-signature-integrity', kind: 'hypothesis', basis: 'inference' }];
  const edges = surface.entries.map(e => ({ from: 'source:api:' + surface.sourceDigest, to: e.id, relation: 'declares' }));
  for (const c of candidates.filter(c => c.historical)) edges.push({ from: 'source:historical:' + digest(bundle.historical), to: c.id, relation: 'hints' });
  if (selected) edges.push({ from: selected.id, to: 'hypothesis:jwt-signature-integrity', relation: 'suggests' });
  return { schemaVersion: 1, bundleDigest: digest(bundle), status, reason, candidates, selected: selected?.id ?? null, scope, config,
    graph: { nodes, edges } };
}

function report(bundle: StudyBundle, compiled: StudyCompilation, result: JwtIntegrityResult | null): string {
  const selected = compiled.candidates.find(c => c.id === compiled.selected);
  const evidence = result?.evidence.map(id => `\`${id}\``).join(', ') ?? 'Sin solicitudes de prueba.';
  const outcome = result?.status ?? 'unresolved';
  return `# BBA — estudio ${bundle.case.id} (${outcome})\n\n` +
    `Borrador para revisión; no enviado. Caso publicado: ${bundle.case.author}, [${bundle.case.title}](${bundle.case.sourceUrl}) (${bundle.case.published}). ` +
    `La publicación es una referencia metodológica, no autoriza pruebas sobre el servicio original.\n\n` +
    `## Qué es\n\nHipótesis: un endpoint que declara autenticación opcional entre operaciones protegidas podría aceptar JWT con claims alterados y firma sin actualizar. ` +
    `${result?.reason ?? compiled.reason}\n\n` +
    `## Cómo se encontró\n\nSuperficie API importada offline: digest \`${bundle.surface.surface.sourceDigest}\`; ` +
    `${compiled.candidates.length} excepciones de autenticación dentro de la política. ` +
    `Pista histórica estructurada: ${bundle.historical.sourceUrl} (${bundle.historical.capturedAt}); esa fuente no prueba estado actual. ` +
    `${selected ? `Candidato elegido: \`${selected.url}\`, operación \`${selected.locator}\`.` : 'No se eligió un candidato único.'}\n\n` +
    `## Demostración de explotación\n\n${result?.status === 'confirmed'
      ? 'El control anónimo fue denegado y el JWT alterado, conservando la firma anterior, recibió el mismo hecho protegido que el token válido antes y después.'
      : result?.status === 'not-reproduced' ? 'La mutación declarada fue denegada mientras el token original siguió vigente. No hay vulnerabilidad confirmada para esta comparación.'
        : 'La evidencia disponible no demuestra una vulnerabilidad explotable.'} ` +
    `Evidencia: ${evidence}\n\n` +
    `## Cómo reproducirlo\n\n1. Usar una cuenta de prueba propia y la política registrada en el expediente.\n` +
    `2. Preparar el cuerpo inocuo en la variable de entorno declarada y el JWT propio en \`${bundle.profile.credentialEnv}\`.\n` +
    `3. Ejecutar el mismo request anónimo, con JWT válido, con JWT alterado sin volver a firmarlo y nuevamente con JWT válido; comparar el hecho JSON \`${bundle.profile.proofPointer}\`.\n` +
    `4. Revisar el plan y los checkpoints en \`jwt/run\`; no repetir reservas inciertas.\n\n` +
    `## Cómo corregirlo\n\nVerificar la firma criptográfica y el algoritmo permitido antes de utilizar claims para autenticación o autorización. ` +
    `Agregar una regresión que rechace el JWT alterado y mantenga válido el token original. ` +
    `La severidad depende del dato y privilegio realmente demostrados; este estudio no acredita acceso a otras cuentas ni una escala de registros.\n\n` +
    `## Alcance y límites\n\nPolítica declarada: ${bundle.policy.sourceUrl}, revisada ${bundle.policy.reviewedAt}; ` +
    `referencia ${bundle.policy.authorization.reference}. La herramienta verifica el contrato, no la legitimidad de esa declaración. ` +
    `Los valores de tokens, cuerpos y respuestas no se guardan.\n`;
}
function save(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify({ value, sha256: digest(value) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
function verifySaved(path: string, value: unknown): void {
  const saved = readJson(path); fields(saved, ['value', 'sha256']);
  if (saved.sha256 !== digest(value) || canonical(saved.value) !== canonical(value)) throw new Error('Study artifact integrity mismatch');
}
export function prepareStudy(folder: string, bundle: StudyBundle): StudyCompilation {
  const compiled = compileStudy(bundle);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  save(join(folder, 'bundle.json'), bundle);
  save(join(folder, 'analysis.json'), compiled);
  if (compiled.scope && compiled.config) {
    save(join(folder, 'scope.json'), compiled.scope);
    save(join(folder, 'jwt-config.json'), compiled.config);
  } else writeFileSync(join(folder, 'report.md'), report(bundle, compiled, null), { flag: 'wx', mode: 0o600 });
  return compiled;
}
export async function executeStudy(folder: string, bundle: StudyBundle, options: {
  budget?: ProgramBudget; signal?: AbortSignal; environment?: Record<string, string | undefined>; resume?: boolean;
} = {}): Promise<{ analysis: StudyCompilation; result: JwtIntegrityResult | null; report: string | null }> {
  const compiled = compileStudy(bundle);
  if (options.resume) {
    verifySaved(join(folder, 'bundle.json'), bundle);
    verifySaved(join(folder, 'analysis.json'), compiled);
    if (compiled.scope && compiled.config) {
      verifySaved(join(folder, 'scope.json'), compiled.scope);
      verifySaved(join(folder, 'jwt-config.json'), compiled.config);
    }
  } else prepareStudy(folder, bundle);
  if (!compiled.scope || !compiled.config) {
    const path = join(folder, 'report.md');
    if (options.resume && readFileSync(path, 'utf8') !== report(bundle, compiled, null)) throw new Error('Study report integrity mismatch');
    return { analysis: compiled, result: null, report: path };
  }
  const result = await jwtIntegrityCheck(join(folder, 'jwt'), compiled.scope, compiled.config,
    { budget: options.budget, signal: options.signal, environment: options.environment, resume: options.resume });
  if (inspectSession(join(folder, 'jwt', 'run')).status !== 'completed') return { analysis: compiled, result, report: null };
  const path = join(folder, 'report.md'), body = report(bundle, compiled, result);
  if (existsSync(path)) {
    if (readFileSync(path, 'utf8') !== body) throw new Error('Study report integrity mismatch');
  } else writeFileSync(path, body, { flag: 'wx', mode: 0o600 });
  return { analysis: compiled, result, report: path };
}
