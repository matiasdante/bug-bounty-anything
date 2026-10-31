import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { fields, strictUrl, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';

export type SsrfCallback = { schemaVersion: 1; class: 'outbound-fetch'; policyReference: string;
  triggerUrl: string; queryName: string; credentialEnv: string | null;
  callbackUrl: string; receiptUrl: string; receiptPointer: string };
const callbackRef = 'BBA_INPUT_SSRF_CALLBACK';

function plan(config: SsrfCallback): Plan {
  return { schemaVersion: 1, steps: [
    { id: 'receipt-before', method: 'GET', url: config.receiptUrl, credentialEnv: null,
      observe: [{ name: 'seen', pointer: config.receiptPointer }] },
    { id: 'trigger', method: 'GET', url: config.triggerUrl, credentialEnv: config.credentialEnv,
      query: [{ name: config.queryName, valueEnv: callbackRef }] },
    ...['receipt-after-a', 'receipt-after-b'].map(id => ({ id, method: 'GET' as const, url: config.receiptUrl,
      credentialEnv: null, observe: [{ name: 'seen', pointer: config.receiptPointer }] })),
  ] };
}
export function validateSsrfCallback(value: unknown, scope: Scope): asserts value is SsrfCallback {
  validateScope(scope);
  fields(value, ['schemaVersion', 'class', 'policyReference', 'triggerUrl', 'queryName', 'credentialEnv', 'callbackUrl', 'receiptUrl', 'receiptPointer']);
  if (value.schemaVersion !== 1 || value.class !== 'outbound-fetch'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.queryName !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(value.queryName)
    || value.credentialEnv !== null && (typeof value.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(value.credentialEnv))
    || typeof value.receiptPointer !== 'string' || !/^(\/(?:[^~]|~[01])*)?$/.test(value.receiptPointer))
    throw new Error('Invalid SSRF callback config');
  const trigger = strictUrl(value.triggerUrl), callback = strictUrl(value.callbackUrl), receipt = strictUrl(value.receiptUrl);
  if (trigger.origin === callback.origin || callback.origin !== receipt.origin
    || callback.pathname === receipt.pathname || callback.pathname.length < 14
    || !/\/[A-Za-z0-9_-]{12,}$/.test(callback.pathname)) throw new Error('Distinct owned callback with an opaque path token is required');
  if (!scope.allowed.some(rule => rule.origin === callback.origin && rule.paths.includes(callback.pathname))
    || scope.excluded.some(rule => rule.origin === callback.origin && rule.paths.includes(callback.pathname)))
    throw new Error('Owned callback URL must be declared in scope');
  if (scope.limits.maxRequests < 4) throw new Error('Callback proof needs four request reservations');
  validatePlan(plan(value as SsrfCallback), scope);
}
function input(config: SsrfCallback): Record<string, string | undefined> {
  return { ...process.env, [callbackRef]: config.callbackUrl };
}
export function evaluateSsrfCallback(session: Session, config: SsrfCallback) {
  if (digest(session.plan) !== digest(plan(config))) throw new Error('Callback plan changed');
  const response = (id: string) => session.attempts.find(a => a.stepId === id && a.outcome === 'succeeded' && a.response?.status === 200)?.response;
  const seen = (id: string, value: boolean) => response(id)?.facts?.find(f => f.name === 'seen' && f.kind === 'boolean')?.sha256 === digest(value);
  const baseline = seen('receipt-before', false), trigger = !!response('trigger');
  const observed = seen('receipt-after-a', true) || seen('receipt-after-b', true);
  const absent = seen('receipt-after-a', false) && seen('receipt-after-b', false);
  const status = !baseline || !trigger ? 'unresolved' : observed ? 'confirmed' : absent ? 'not-reproduced' : 'unresolved';
  return { schemaVersion: 1, class: config.class, status, sessionId: session.id, scopeDigest: session.scopeDigest,
    configDigest: digest(config), evidence: ['receipt-before', 'trigger', 'receipt-after-a', 'receipt-after-b'].map(id => session.id + ':' + id),
    reason: status === 'confirmed' ? 'The owned receiver changed from unseen to seen after the target request, using an opaque callback URL. This establishes an outbound fetch to that destination under the declared policy.'
      : status === 'not-reproduced' ? 'The owned receiver remained unseen in both bounded follow-up polls.'
        : 'The initial control, trigger or receiver observations were incomplete or ambiguous.',
    limitations: ['This only tests outbound access to the operator-owned callback; it does not prove access to internal networks, metadata endpoints or response disclosure.',
      'The operator must verify that the receiver reports only actual inbound callbacks for this opaque path, and that the application policy forbids this destination.',
      'The receiver may get one extra server-side request outside the BBA client budget; its own logs and policy remain the operator responsibility.'] };
}
function report(result: ReturnType<typeof evaluateSsrfCallback>, config: SsrfCallback): string {
  return `# BBA — outbound-fetch: ${result.status}\n\nBorrador no enviado.\n\n`
    + `## Qué es\n\nPosible fetch del servidor hacia un destino externo propio bajo la regla declarada ${config.policyReference}.\n\n`
    + `## Cómo se encontró\n\nSe presentó una URL opaca del receptor propio en el parámetro \`${config.queryName}\` de \`${config.triggerUrl}\` y se comparó el recibo antes y después.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
    + `## Cómo reproducirlo\n\nCon el mismo scope, configurar un receptor propio que informe un booleano por token único; comprobar que está vacío, llamar al endpoint exacto con la URL propia y consultar el recibo dos veces como máximo. No usar destinos internos ni repetir reservas inciertas.\n\n`
    + `## Cómo corregirlo\n\nValidar destinos permitidos en el servidor antes del fetch; bloquear direcciones privadas, loopback, metadatos y redirects hacia destinos excluidos, y verificar DNS al conectar. Agregar una regresión con un receptor externo no autorizado.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}
function save(folder: string, name: string, session: Session, config: SsrfCallback) {
  const result = evaluateSsrfCallback(session, config);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, config), { flag: 'wx', mode: 0o600 });
  return result;
}
export async function ssrfCallbackCheck(folder: string, scope: Scope, config: SsrfCallback,
  options: { signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateSsrfCallback(config, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(config));
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: input(config),
    stopWhen: state => evaluateSsrfCallback(state, config).status === 'confirmed' });
  return save(folder, 'ssrf-callback', session, config);
}
export async function resumeSsrfCallbackCheck(folder: string, scope: Scope, config: SsrfCallback,
  options: { signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateSsrfCallback(config, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope)
    || digest(readJson(join(folder, 'config.json'))) !== digest(config)) throw new Error('Callback definition changed');
  if (existsSync(join(folder, 'ssrf-resumed.json')) || existsSync(join(folder, 'ssrf-resumed.md')))
    throw new Error('Resumed callback result already exists');
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: input(config),
    stopWhen: state => evaluateSsrfCallback(state, config).status === 'confirmed' });
  return save(folder, 'ssrf-resumed', session, config);
}
