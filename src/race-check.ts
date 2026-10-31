import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { scopedHttp2Pair, scopedRequest, credentialFor } from './http.ts';
import { digest } from './contracts.ts';
import { assertRequestAllowed, optionalFields, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { projectJson } from './observations.ts';
import { validateHeaderEnvironment } from './headers.ts';
import type { ProgramBudget } from './budget.ts';
import { sealArtifact } from './artifacts.ts';
import { openAppendJournal } from './journal.ts';
import type { Lang } from './i18n.ts';

export type RaceCheck = { schemaVersion: 1; class: 'single-use-race'; policyReference: string;
  credentialEnv: string; actionUrl: string; actionField: string;
  controlResourceId: string; raceResourceId: string; controlStateUrl: string; raceStateUrl: string;
  countPointer: string; transport?: 'http1' | 'http2' };
const bodyRefs = ['BBA_BODY_RACE_CONTROL', 'BBA_BODY_RACE_PROBE'] as const;
type Reply = { status: number; factDigest: string | null; factKind: string | null; startedAt: number; endedAt: number };

export function validateRaceCheck(value: unknown, scope: Scope): asserts value is RaceCheck {
  validateScope(scope);
  optionalFields(value, ['schemaVersion', 'class', 'policyReference', 'credentialEnv', 'actionUrl', 'actionField',
    'controlResourceId', 'raceResourceId', 'controlStateUrl', 'raceStateUrl', 'countPointer'], ['transport']);
  if (value.schemaVersion !== 1 || value.class !== 'single-use-race'
    || (value.transport !== undefined && value.transport !== 'http1' && value.transport !== 'http2')
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(value.credentialEnv)
    || typeof value.actionField !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(value.actionField)
    || typeof value.controlResourceId !== 'string' || typeof value.raceResourceId !== 'string'
    || !/^[A-Za-z0-9_-]{8,64}$/.test(value.controlResourceId) || !/^[A-Za-z0-9_-]{8,64}$/.test(value.raceResourceId)
    || value.controlResourceId === value.raceResourceId
    || typeof value.countPointer !== 'string' || !/^(\/(?:[^~]|~[01])*)?$/.test(value.countPointer))
    throw new Error('Invalid race check');
  const urls = [value.actionUrl, value.controlStateUrl, value.raceStateUrl].map((url: string) =>
    assertRequestAllowed(scope, url, { method: url === value.actionUrl ? 'POST' : 'GET',
      ...(url === value.actionUrl ? { body: { format: 'json', valueEnv: bodyRefs[0] } } : {}) }));
  if (new Set(urls.map(url => url.href)).size !== 3 || new Set(urls.map(url => url.origin)).size !== 1)
    throw new Error('Race actions and state URLs must be distinct on one origin');
  if (scope.limits.minIntervalMs !== 0 || scope.limits.maxRequests < 7)
    throw new Error('Race proof requires an explicit zero interval and seven request reservations');
}
export async function raceCheck(folder: string, scope: Scope, config: RaceCheck,
  options: { signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang } = {}) {
  const lang = options.lang ?? 'es';
  validateRaceCheck(config, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  const env: Record<string, string | undefined> = { ...process.env, ...options.credentials,
    [bodyRefs[0]]: JSON.stringify({ [config.actionField]: config.controlResourceId }),
    [bodyRefs[1]]: JSON.stringify({ [config.actionField]: config.raceResourceId }) };
  validateHeaderEnvironment(scope, env);
  if (!env[config.credentialEnv]) throw new Error('Missing controlled credential');
  const credential = credentialFor(config.credentialEnv, env[config.credentialEnv]!);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  const journal = openAppendJournal(folder);
  const append = (event: Record<string, unknown>) => journal.append(event);
  const id = randomUUID(), started = Date.now(), deadline = started + scope.limits.maxDurationMs;
  let used = 0, stopped: string | null = null;
  const replies = new Map<string, Reply>();
  append({ event: 'start', id, scopeDigest: digest(scope), configDigest: digest(config) });
  const send = async (stepId: string, url: string, method: 'GET' | 'POST', bodyEnv?: string, preReserved = false) => {
    const reference = id + ':' + stepId;
    let sharedReserved = preReserved;
    try {
      if (options.signal?.aborted || Date.now() >= deadline || used >= 7) throw new Error('cancelled-or-budget');
      const spec = method === 'GET' ? { method } as const : { method, body: { format: 'json' as const, valueEnv: bodyEnv! } };
      const ordinal = ++used;
      append({ event: 'reserved', ordinal, stepId, at: new Date().toISOString() });
      if (options.budget && !preReserved) { await options.budget.beforeRequest(reference, options.signal); sharedReserved = true; }
      const sentAt = performance.timeOrigin + performance.now();
      const r = await scopedRequest(scope, url, { ...credential, request: spec, environment: env, signal: options.signal,
        remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity) });
      const fact = method === 'GET' ? projectJson(r.body, r.contentType, [{ name: 'count', pointer: config.countPointer }])[0] : null;
      const reply: Reply = { status: r.status, factDigest: fact?.sha256 ?? null, factKind: fact?.kind ?? null,
        startedAt: sentAt, endedAt: performance.timeOrigin + performance.now() };
      replies.set(stepId, reply);
      append({ event: 'response', ordinal, stepId, status: r.status, bodyDigest: createHash('sha256').update(r.body).digest('hex'),
        factDigest: reply.factDigest, factKind: reply.factKind, startedAt: sentAt, endedAt: reply.endedAt });
      if (r.status >= 300 && r.status < 400 || r.status === 429 || r.status >= 500) throw new Error('unsafe-response');
      return reply;
    } finally { if (sharedReserved && options.budget) options.budget.complete(reference); }
  };
  const count = (step: string, expected: number) => replies.get(step)?.status === 200
    && replies.get(step)?.factKind === 'number' && replies.get(step)?.factDigest === digest(expected);
  const accepted = (step: string) => [200, 201, 204].includes(replies.get(step)?.status ?? 0);
  const denied = (step: string) => [400, 403, 409, 422].includes(replies.get(step)?.status ?? 0);
  try {
    await send('control-before', config.controlStateUrl, 'GET');
    if (!count('control-before', 0)) throw new Error('control-precondition');
    await send('control-first', config.actionUrl, 'POST', bodyRefs[0]);
    if (!accepted('control-first')) throw new Error('control-precondition');
    await send('control-second', config.actionUrl, 'POST', bodyRefs[0]);
    if (!denied('control-second')) throw new Error('control-precondition');
    await send('race-before', config.raceStateUrl, 'GET');
    if (!count('race-before', 0)) throw new Error('control-precondition');
    const pair: [string, string] = [id + ':race-a', id + ':race-b'];
    if (config.transport === 'http2') {
      if (options.signal?.aborted || Date.now() >= deadline || used + 2 > 7) throw new Error('cancelled-or-budget');
      const ordA = ++used, ordB = ++used;
      const nowIso = new Date().toISOString();
      append({ event: 'reserved', ordinal: ordA, stepId: 'race-a', at: nowIso, transport: 'http2' });
      append({ event: 'reserved', ordinal: ordB, stepId: 'race-b', at: nowIso, transport: 'http2' });
      let pairReserved = false;
      try {
        if (options.budget) { await options.budget.beforeConcurrentPair(pair, options.signal); pairReserved = true; }
        const spec = { method: 'POST' as const, body: { format: 'json' as const, valueEnv: bodyRefs[1] } };
        const [resA, resB] = await scopedHttp2Pair(scope, config.actionUrl, [spec, spec], {
          ...credential,
          environment: env,
          signal: options.signal,
          remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity),
        });
        for (const [stepId, ord, r] of [['race-a', ordA, resA], ['race-b', ordB, resB]] as const) {
          const reply: Reply = { status: r.status, factDigest: null, factKind: null, startedAt: r.startedAt, endedAt: r.endedAt };
          replies.set(stepId, reply);
          append({ event: 'response', ordinal: ord, stepId, status: r.status, bodyDigest: createHash('sha256').update(r.body).digest('hex'),
            factDigest: null, factKind: null, startedAt: r.startedAt, endedAt: r.endedAt, transport: 'http2' });
          if ((r.status >= 300 && r.status < 400) || r.status === 429 || r.status >= 500) throw new Error('unsafe-response');
        }
      } finally {
        if (pairReserved && options.budget) {
          options.budget.complete(pair[0]);
          options.budget.complete(pair[1]);
        }
      }
    } else {
      if (options.budget) await options.budget.beforeConcurrentPair(pair, options.signal);
      const outcomes = await Promise.allSettled([send('race-a', config.actionUrl, 'POST', bodyRefs[1], !!options.budget),
        send('race-b', config.actionUrl, 'POST', bodyRefs[1], !!options.budget)]);
      if (outcomes.some(outcome => outcome.status === 'rejected')) throw new Error('concurrent-request-failed');
    }
    await send('race-after', config.raceStateUrl, 'GET');
  } catch (error) { stopped = options.signal?.aborted ? 'cancelled' : error instanceof Error ? error.message : 'execution-failed'; }
  finally { append({ event: 'finish', requests: used, stopped }); journal.close(); }
  const a = replies.get('race-a'), b = replies.get('race-b');
  const overlap = !!a && !!b && a.startedAt < b.endedAt && b.startedAt < a.endedAt;
  const status = stopped ? 'unresolved' : accepted('race-a') && accepted('race-b') && count('race-after', 2) && overlap ? 'confirmed'
    : overlap && ((accepted('race-a') && denied('race-b')) || (accepted('race-b') && denied('race-a'))) && count('race-after', 1)
      ? 'not-reproduced' : 'unresolved';
  const result = { schemaVersion: 1, id, class: config.class, status, stopped, requests: used, overlap,
    evidence: ['control-before', 'control-first', 'control-second', 'race-before', 'race-a', 'race-b', 'race-after'].map(step => id + ':' + step),
    limitations: ['Only two explicitly declared concurrent actions against disposable controlled resources were tested.',
      'A server-side single-use invariant and cleanup of both owned resources are operator preconditions.',
      'The observed double effect does not establish broader financial impact or reliability under other concurrency levels.'] };
  writeFileSync(join(folder, 'race-check.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  const md = lang === 'en'
    ? `# BBA — single-use-race: ${status}\n\nLocal draft; not submitted.\n\n`
      + `## What it is\n\nPotential violation of single-use rule ${config.policyReference}.\n\n`
      + `## How it was found\n\nTwo disposable owned resources: sequential control rejected the second action; two concurrent actions were sent to the second resource.\n\n`
      + `## Exploitability proof\n\nStatus: **${status}**. Measured overlap: ${overlap}. Double-effect final state: ${count('race-after', 2)}. Evidence: ${result.evidence.map(e => '`' + e + '`').join(', ')}.\n\n`
      + `## Reproduction\n\nUse only the two declared owned resources, verify initial zero counters, run the sequential control and, if the second use is denied, send two concurrent actions; compare final counter. Never replay an interrupted action.\n\n`
      + `## Remediation\n\nEnforce the single-use transition atomically on the server using a uniqueness constraint or conditional transactional update.\n\n`
      + `## Limitations\n\n${result.limitations.map(x => '- ' + x).join('\n')}\n`
    : `# BBA — single-use-race: ${status}\n\nBorrador no enviado.\n\n`
      + `## Qué es\n\nPosible violación de la regla de uso único ${config.policyReference}.\n\n`
      + `## Cómo se encontró\n\nDos recursos descartables propios: el control secuencial rechazó la segunda acción; se enviaron exactamente dos acciones concurrentes al segundo recurso.\n\n`
      + `## Demostración de explotabilidad\n\nEstado: **${status}**. Solapamiento medido: ${overlap}. Estado final de doble efecto: ${count('race-after', 2)}. Evidencia: ${result.evidence.map(e => '`' + e + '`').join(', ')}.\n\n`
      + `## Cómo reproducirlo\n\nUsar solo los dos recursos propios declarados, comprobar contadores iniciales en cero, ejecutar el control secuencial y, si rechaza el segundo uso, enviar las dos acciones simultáneas; comparar el contador final. No repetir una acción interrumpida.\n\n`
      + `## Cómo corregirlo\n\nAplicar la transición de uso único de forma atómica en el servidor, con restricción de unicidad o actualización condicional dentro de una transacción. Agregar regresión con dos solicitudes concurrentes.\n\n`
      + `## Límites\n\n${result.limitations.map(x => '- ' + x).join('\n')}\n`;
  writeFileSync(join(folder, 'report.md'), md, { flag: 'wx', mode: 0o600 });
  sealArtifact(folder, { kind: 'race-check', id, scopeDigest: digest(scope), configDigest: digest(config) });
  return result;
}
