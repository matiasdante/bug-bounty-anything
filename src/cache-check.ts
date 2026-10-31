import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { fields, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope, Step } from './scope.ts';
import { createSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';

export type CacheCheck = { schemaVersion: 1; class: 'cross-identity-cache'; policyReference: string;
  identityUrl: string; identityPointer: string; resourceUrl: string; protectedPointer: string;
  accountA: string; accountB: string; bustQueryName: string; bustTokens: [string, string] };
const refs = ['BBA_INPUT_CACHE_A', 'BBA_INPUT_CACHE_B'] as const;

function plan(c: CacheCheck): Plan {
  const identity = (id: string, credentialEnv: string): Step => ({ id, method: 'GET', url: c.identityUrl, credentialEnv,
    observe: [{ name: 'identity', pointer: c.identityPointer }] });
  const resource = (id: string, credentialEnv: string | null, bust?: string): Step => ({ id, method: 'GET', url: c.resourceUrl,
    credentialEnv, ...(bust ? { query: [{ name: c.bustQueryName, valueEnv: bust }] } : {}),
    observe: [{ name: 'protected', pointer: c.protectedPointer }] });
  return { schemaVersion: 1, steps: [identity('identity-a', c.accountA), identity('identity-b', c.accountB),
    resource('anonymous', null), resource('a-bust', c.accountA, refs[0]), resource('b-bust', c.accountB, refs[1]),
    resource('a-prime', c.accountA), resource('b-shared', c.accountB)] };
}
export function validateCacheCheck(value: unknown, scope: Scope): asserts value is CacheCheck {
  validateScope(scope);
  fields(value, ['schemaVersion', 'class', 'policyReference', 'identityUrl', 'identityPointer', 'resourceUrl', 'protectedPointer',
    'accountA', 'accountB', 'bustQueryName', 'bustTokens']);
  if (value.schemaVersion !== 1 || value.class !== 'cross-identity-cache'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.bustQueryName !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(value.bustQueryName)
    || typeof value.identityPointer !== 'string' || typeof value.protectedPointer !== 'string'
    || !/^(\/(?:[^~]|~[01])*)?$/.test(value.identityPointer) || !/^(\/(?:[^~]|~[01])*)?$/.test(value.protectedPointer)
    || value.accountA === value.accountB || [value.accountA, value.accountB].some((n: unknown) => typeof n !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(n))
    || !Array.isArray(value.bustTokens) || value.bustTokens.length !== 2 || value.bustTokens[0] === value.bustTokens[1]
    || value.bustTokens.some((n: unknown) => typeof n !== 'string' || !/^[A-Za-z0-9_-]{12,64}$/.test(n)))
    throw new Error('Invalid cache check');
  if (scope.limits.maxRequests < 7) throw new Error('Cache proof needs seven request reservations');
  validatePlan(plan(value as CacheCheck), scope);
  if (new URL(value.identityUrl).origin !== new URL(value.resourceUrl).origin || value.identityUrl === value.resourceUrl)
    throw new Error('Identity and resource endpoints must be distinct on one origin');
}
function inputs(c: CacheCheck): Record<string, string | undefined> {
  return { ...process.env, [refs[0]]: c.bustTokens[0], [refs[1]]: c.bustTokens[1] };
}
export function evaluateCache(session: Session, c: CacheCheck) {
  if (digest(session.plan) !== digest(plan(c))) throw new Error('Cache plan changed');
  const response = (id: string) => session.attempts.find(a => a.stepId === id && a.outcome === 'succeeded')?.response;
  const fact = (id: string, name: string) => response(id)?.facts?.find(f => f.name === name && f.meaningful);
  const denied = (id: string) => [401, 403, 404].includes(response(id)?.status ?? 0);
  const same = (x: ReturnType<typeof fact>, y: ReturnType<typeof fact>) => !!x && !!y && x.kind === y.kind && x.sha256 === y.sha256;
  const idA = fact('identity-a', 'identity'), idB = fact('identity-b', 'identity');
  const aBust = fact('a-bust', 'protected'), aPrime = fact('a-prime', 'protected'), bShared = fact('b-shared', 'protected');
  const controls = response('identity-a')?.status === 200 && response('identity-b')?.status === 200
    && idA && idB && !same(idA, idB) && denied('anonymous') && response('a-bust')?.status === 200
    && denied('b-bust') && response('a-prime')?.status === 200 && same(aBust, aPrime);
  const status = !controls ? 'unresolved' : response('b-shared')?.status === 200 && same(aPrime, bShared) ? 'confirmed'
    : denied('b-shared') ? 'not-reproduced' : 'unresolved';
  return { schemaVersion: 1, class: c.class, status, sessionId: session.id, scopeDigest: session.scopeDigest,
    configDigest: digest(c), evidence: plan(c).steps.map(s => session.id + ':' + s.id),
    reason: status === 'confirmed' ? 'The second controlled identity received the first identity’s protected field on the shared URL, while its cache-busted request was denied and the anonymous control was denied.'
      : status === 'not-reproduced' ? 'The second identity was denied on the shared URL after priming.'
        : 'Identity, anonymous, cache-busted or protected-field controls were incomplete or ambiguous.',
    limitations: ['This is a cache-correlated exposure, not proof of a particular cache layer or key implementation.',
      'The operator must establish that the bust parameter is semantically inert and that the accounts have no shared grant.',
      'Only one controlled resource and two accounts were tested; no other data or write actions were probed.'] };
}
function report(result: ReturnType<typeof evaluateCache>, c: CacheCheck): string {
  return `# BBA — cross-identity-cache: ${result.status}\n\nBorrador no enviado.\n\n`
    + `## Qué es\n\nExposición de un campo protegido entre dos cuentas propias en \`${c.resourceUrl}\`, correlacionada con la URL compartida bajo la regla ${c.policyReference}.\n\n`
    + `## Cómo se encontró\n\nSe verificaron identidades distintas y denegación anónima, luego lecturas con cache busting y la URL compartida.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
    + `## Cómo reproducirlo\n\nUsar dos cuentas y un recurso propios. Confirmar que el parámetro \`${c.bustQueryName}\` no cambia la operación, ejecutar el plan exacto y comparar solo el campo proyectado; no repetir reservas inciertas.\n\n`
    + `## Cómo corregirlo\n\nMarcar respuestas privadas como no compartibles y segmentar cualquier cache por identidad/autorización. Validar permisos antes de servir respuestas almacenadas; agregar regresión con dos cuentas y la URL compartida.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}
function save(folder: string, name: string, session: Session, c: CacheCheck) {
  const result = evaluateCache(session, c);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, c), { flag: 'wx', mode: 0o600 });
  return result;
}
export async function cacheCheck(folder: string, scope: Scope, c: CacheCheck, options: { signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateCacheCheck(c, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(c, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(c));
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: inputs(c) });
  return save(folder, 'cache-check', session, c);
}
export async function resumeCacheCheck(folder: string, scope: Scope, c: CacheCheck, options: { signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateCacheCheck(c, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope) || digest(readJson(join(folder, 'config.json'))) !== digest(c))
    throw new Error('Cache definition changed');
  if (existsSync(join(folder, 'cache-resumed.json')) || existsSync(join(folder, 'cache-resumed.md')))
    throw new Error('Resumed cache result already exists');
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: inputs(c) });
  return save(folder, 'cache-resumed', session, c);
}
