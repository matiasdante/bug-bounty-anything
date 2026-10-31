import { createHash, randomUUID } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, writeFileSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchIsolated } from './capture.ts';
import { digest } from './contracts.ts';
import { scopedRequest, credentialFor } from './http.ts';
import { projectJson } from './observations.ts';
import { assertRequestAllowed, fields, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { validateHeaderEnvironment } from './headers.ts';
import type { ProgramBudget } from './budget.ts';
import { sealArtifact } from './artifacts.ts';

export type CsrfCheck = { schemaVersion: 1; class: 'cross-origin-form'; policyReference: string;
  attackerPageUrl: string; stateUrl: string; actionUrl: string; cookieEnv: string; sameSite: 'Strict' | 'Lax' | 'None';
  formField: string; formValue: string; statePointer: string; beforeValue: string; afterValue: string };
const bodyRef = 'BBA_BODY_CSRF_FORM';

export function validateCsrfCheck(value: unknown, scope: Scope): asserts value is CsrfCheck {
  validateScope(scope);
  fields(value, ['schemaVersion', 'class', 'policyReference', 'attackerPageUrl', 'stateUrl', 'actionUrl', 'cookieEnv',
    'sameSite', 'formField', 'formValue', 'statePointer', 'beforeValue', 'afterValue']);
  if (value.schemaVersion !== 1 || value.class !== 'cross-origin-form'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.cookieEnv !== 'string' || !/^BBA_COOKIE_[A-Z0-9_]{1,50}$/.test(value.cookieEnv)
    || !['Strict', 'Lax', 'None'].includes(value.sameSite)
    || typeof value.formField !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(value.formField)
    || typeof value.formValue !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value.formValue)
    || typeof value.statePointer !== 'string' || !/^(\/(?:[^~]|~[01])*)?$/.test(value.statePointer)
    || [value.beforeValue, value.afterValue].some((n: unknown) => typeof n !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(n))
    || value.beforeValue === value.afterValue) throw new Error('Invalid CSRF check');
  const attacker = assertRequestAllowed(scope, value.attackerPageUrl, { method: 'GET' });
  const state = assertRequestAllowed(scope, value.stateUrl, { method: 'GET' });
  const action = assertRequestAllowed(scope, value.actionUrl, { method: 'POST', body: { format: 'form', valueEnv: bodyRef } });
  if (attacker.origin === action.origin || state.origin !== action.origin || state.href === action.href)
    throw new Error('Distinct attacker and victim origins with a separate state endpoint are required');
  if (scope.limits.maxRequests < 5) throw new Error('CSRF proof needs five request reservations');
}

export async function csrfCheck(folder: string, scope: Scope, config: CsrfCheck,
  options: { signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined> } = {}) {
  validateCsrfCheck(config, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  const env: Record<string, string | undefined> = { ...process.env, ...options.credentials,
    [bodyRef]: new URLSearchParams([[config.formField, config.formValue]]).toString() };
  validateHeaderEnvironment(scope, env);
  if (!env[config.cookieEnv]) throw new Error('Missing controlled cookie');
  const cookie = credentialFor(config.cookieEnv, env[config.cookieEnv]!).cookie!;
  const victimOrigin = new URL(config.actionUrl).origin, attackerOrigin = new URL(config.attackerPageUrl).origin;
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  const fd = openSync(join(folder, 'requests.jsonl'), 'wx', 0o600);
  const append = (event: unknown) => { writeSync(fd, JSON.stringify(event) + '\n'); fsyncSync(fd); };
  const id = randomUUID(), deadline = Date.now() + scope.limits.maxDurationMs;
  let used = 0, blocked = 0, stopped: string | null = null, browserStatus: number | null = null;
  let cookieDelivered = false, originMatched = false;
  const state = { before: null as string | null, after: null as string | null, anonymousStatus: null as number | null };
  append({ event: 'start', id, scopeDigest: digest(scope), configDigest: digest(config) });
  const send = async (stepId: string, url: string, method: 'GET' | 'POST', withCookie: boolean, origin?: string) => {
    if (options.signal?.aborted || Date.now() >= deadline || used >= 5) throw new Error('cancelled-or-budget');
    const ordinal = ++used, reference = id + ':' + stepId;
    append({ event: 'reserved', ordinal, stepId, at: new Date().toISOString() });
    let reserved = false;
    try {
      if (options.budget) { await options.budget.beforeRequest(reference, options.signal); reserved = true; }
      const r = await scopedRequest(scope, url, { ...(withCookie ? { cookie } : {}),
        request: method === 'GET' ? { method } : { method, body: { format: 'form', valueEnv: bodyRef } },
        environment: env, browserOrigin: origin, browserCredentials: true,
        signal: options.signal, remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity) });
      const fact = url === config.stateUrl && method === 'GET'
        ? projectJson(r.body, r.contentType, [{ name: 'state', pointer: config.statePointer }])[0] : null;
      append({ event: 'response', ordinal, stepId, status: r.status,
        bodyDigest: createHash('sha256').update(r.body).digest('hex'), factDigest: fact?.sha256 ?? null, factKind: fact?.kind ?? null });
      if (r.status >= 300 && r.status < 400 || r.status === 429 || r.status >= 500) throw new Error('unsafe-response');
      return { response: r, fact };
    } finally { if (reserved) options.budget!.complete(reference); }
  };
  let browser: Awaited<ReturnType<typeof launchIsolated>> | undefined;
  try {
    const before = await send('state-before', config.stateUrl, 'GET', true);
    state.before = before.response.status === 200 && before.fact?.kind === 'string' ? before.fact.sha256 : null;
    if (state.before !== digest(config.beforeValue)) throw new Error('state-precondition');
    state.anonymousStatus = (await send('anonymous-action', config.actionUrl, 'POST', false, attackerOrigin)).response.status;
    if (![401, 403, 404].includes(state.anonymousStatus)) throw new Error('anonymous-action-not-denied');
    browser = await launchIsolated();
    const context = await browser.browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    try {
      await context.addCookies(cookie.split('; ').map(pair => {
        const index = pair.indexOf('='); return { name: pair.slice(0, index), value: pair.slice(index + 1),
          url: victimOrigin + '/', sameSite: config.sameSite, secure: victimOrigin.startsWith('https:') };
      }));
      await context.routeWebSocket('**/*', ws => ws.close());
      let formDone!: () => void;
      const formPromise = new Promise<void>(resolve => { formDone = resolve; });
      await context.route('**/*', async route => {
        const request = route.request(), url = request.url();
        try {
          if (request.method() === 'GET' && url === config.attackerPageUrl) {
            const r = (await send('attacker-page', url, 'GET', false)).response;
            await route.fulfill({ status: r.status, contentType: r.contentType || undefined, body: r.body }); return;
          }
          if (request.method() === 'POST' && url === config.actionUrl) {
            const headers = await request.allHeaders();
            originMatched = headers.origin === attackerOrigin;
            cookieDelivered = !!headers.cookie && headers.cookie === cookie;
            if (!originMatched || request.postData() !== env[bodyRef]) { blocked++; await route.abort('blockedbyclient'); formDone(); return; }
            const r = (await send('browser-action', url, 'POST', cookieDelivered, attackerOrigin)).response;
            browserStatus = r.status;
            await route.fulfill({ status: r.status, contentType: r.contentType || undefined, body: r.body });
            formDone(); return;
          }
          blocked++; await route.abort('blockedbyclient');
        } catch { blocked++; await route.abort('failed').catch(() => {}); formDone(); }
      });
      const page = await context.newPage();
      await page.goto(config.attackerPageUrl, { waitUntil: 'networkidle', timeout: Math.max(1, deadline - Date.now()) });
      await page.evaluate(({ action, field, value }) => {
        const form = document.createElement('form'); form.method = 'POST'; form.action = action;
        const input = document.createElement('input'); input.name = field; input.value = value;
        form.append(input); document.body.append(form); form.submit();
      }, { action: config.actionUrl, field: config.formField, value: config.formValue });
      await Promise.race([formPromise, delay(Math.min(2000, Math.max(1, deadline - Date.now())))]);
    } finally { await context.close(); }
    const after = await send('state-after', config.stateUrl, 'GET', true);
    state.after = after.response.status === 200 && after.fact?.kind === 'string' ? after.fact.sha256 : null;
  } catch (error) { stopped = options.signal?.aborted ? 'cancelled' : error instanceof Error ? error.message : 'execution-failed'; }
  finally { try { if (browser) await browser.close(); } finally { append({ event: 'finish', requests: used, blocked, stopped }); closeSync(fd); } }
  const status = !stopped && state.before === digest(config.beforeValue) && cookieDelivered && originMatched
    && browserStatus !== null && [200, 201, 204].includes(browserStatus) && state.after === digest(config.afterValue)
      ? 'confirmed' : !stopped && browserStatus !== null && state.after === digest(config.beforeValue)
        && (!cookieDelivered || [401, 403, 404].includes(browserStatus))
        ? 'not-reproduced' : 'unresolved';
  const result = { schemaVersion: 1, id, class: config.class, status, stopped, requests: used, blocked,
    anonymousStatus: state.anonymousStatus, browserStatus, cookieDelivered, originMatched,
    beforeDigest: state.before, afterDigest: state.after,
    evidence: ['state-before', 'anonymous-action', 'attacker-page', 'browser-action', 'state-after'].map(step => id + ':' + step),
    limitations: ['The operator must own the changed state and restore it after the proof; a same-site cross-origin lab does not establish cross-site cookie behavior.',
      'The declared attacker origin must be a real cross-site origin for a CSRF conclusion, and the action must require the authenticated user intent by policy.',
      'Only one simple form POST and one state field were tested. Browser cookie policy, token rotation and other actions may differ.'] };
  writeFileSync(join(folder, 'csrf-check.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'report.md'), `# BBA — cross-origin-form: ${status}\n\nBorrador no enviado.\n\n`
    + `## Qué es\n\nPosible cambio de estado autenticado iniciado desde \`${attackerOrigin}\` bajo la regla ${config.policyReference}.\n\n`
    + `## Cómo se encontró\n\nControl anónimo denegado, estado propio inicial y formulario real en Chromium desde otro origen.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${status}**. Cookie entregada por el navegador: ${cookieDelivered}. Origen observado: ${originMatched}. Acción HTTP: ${browserStatus ?? 'sin respuesta'}. Estado inicial/final comparado con hechos declarados. Evidencia: ${result.evidence.map(e => '`' + e + '`').join(', ')}.\n\n`
    + `## Cómo reproducirlo\n\nCon la cuenta y estado propios, verificar el valor inicial y la denegación anónima, abrir la página atacante declarada, enviar un formulario simple al endpoint autorizado y verificar el valor final. Restaurar el estado.\n\n`
    + `## Cómo corregirlo\n\nExigir token CSRF ligado a la sesión o validar Origin/Referer según el flujo, y configurar SameSite apropiadamente. Agregar regresión con un origen externo y un formulario sin token.\n\n`
    + `## Límites\n\n${result.limitations.map(x => '- ' + x).join('\n')}\n`, { flag: 'wx', mode: 0o600 });
  sealArtifact(folder, { kind: 'csrf-check', id, scopeDigest: digest(scope), configDigest: digest(config) });
  return result;
}
