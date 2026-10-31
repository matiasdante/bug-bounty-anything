import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { fields, integer, requestSpec, validatePlan, validateScope } from './scope.ts';
import type { Scope, Plan, Step } from './scope.ts';
import { resolveRequest } from './requests.ts';
import { scopedRequest, credentialFor } from './http.ts';
import { launchIsolated } from './capture.ts';
import { projectJson } from './observations.ts';
import { validateHeaderEnvironment } from './headers.ts';
import { digest } from './contracts.ts';
import type { ProgramBudget } from './budget.ts';
import { sealArtifact } from './artifacts.ts';
import { openAppendJournal, waitIntervalOrDeadline } from './journal.ts';

type Action = { kind: 'navigate'; stepId: string } | { kind: 'fill'; selector: string; valueEnv: string }
  | { kind: 'click' | 'wait'; selector: string };
export type BrowserScenario = { schemaVersion: 1; policyReference: string; boundary: 'controlled-workflow'; sessionOrigin: string;
  plan: Plan; actions: Action[]; maxRedirects: number; observe: { name: string; selector: string; attribute: string | null }[] };

export function validateScenario(value: unknown, scope: Scope): asserts value is BrowserScenario {
  fields(value, ['schemaVersion', 'policyReference', 'boundary', 'sessionOrigin', 'plan', 'actions', 'maxRedirects', 'observe']);
  if (value.schemaVersion !== 1 || value.boundary !== 'controlled-workflow' || typeof value.policyReference !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || !scope.allowed.some(r => r.origin === value.sessionOrigin)) throw new Error('Invalid browser scenario boundary');
  validatePlan(value.plan, scope); integer(value.maxRedirects, 0, 5);
  if (value.plan.steps.some((s: Step) => s.credentialEnv !== null || new URL(s.url).origin !== value.sessionOrigin && s.method !== 'GET')) throw new Error('Browser scenario credentials come from its isolated session; foreign requests must be GET');
  const selector = (s: unknown) => typeof s === 'string' && s.length > 0 && s.length <= 256 && !/[\x00-\x1f\x7f]/.test(s);
  if (!Array.isArray(value.actions) || !value.actions.length || value.actions.length > 30) throw new Error('Invalid scenario actions');
  for (const a of value.actions) {
    if (a.kind === 'navigate') {
      fields(a, ['kind', 'stepId']);
      if (!value.plan.steps.some((s: Step) => s.id === a.stepId && s.method === 'GET')) throw new Error('Invalid navigation step');
    } else if (a.kind === 'fill') {
      fields(a, ['kind', 'selector', 'valueEnv']);
      if (!selector(a.selector) || typeof a.valueEnv !== 'string' || !/^BBA_INPUT_[A-Z0-9_]{1,50}$/.test(a.valueEnv)) throw new Error('Invalid fill action');
    } else {
      fields(a, ['kind', 'selector']);
      if (!['click', 'wait'].includes(a.kind) || !selector(a.selector)) throw new Error('Invalid scenario action');
    }
  }
  if (value.actions[0].kind !== 'navigate') throw new Error('Scenario must start with declared navigation');
  if (!Array.isArray(value.observe) || value.observe.length > 20) throw new Error('Invalid DOM observations');
  const names = new Set<string>();
  for (const o of value.observe) {
    fields(o, ['name', 'selector', 'attribute']);
    if (typeof o.name !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(o.name) || names.has(o.name) || !selector(o.selector)
      || o.attribute !== null && (typeof o.attribute !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(o.attribute))) throw new Error('Invalid DOM selector');
    names.add(o.name);
  }
}

export async function captureScenario(folder: string, scope: Scope, config: BrowserScenario, options: { credentials?: Record<string, string | undefined>; signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateScope(scope); validateScenario(config, scope); validateHeaderEnvironment(scope, options.credentials);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  const env = options.credentials ?? process.env;
  const requests = config.plan.steps.map(step => ({ step, resolved: resolveRequest(scope, step.url, requestSpec(step), env) }));
  for (const a of config.actions) if (a.kind === 'fill' && (env[a.valueEnv] === undefined || Buffer.byteLength(env[a.valueEnv]!) > 4096)) throw new Error('Missing or oversized scenario input');
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  for (const [name, value] of Object.entries({ scope, config })) writeFileSync(join(folder, name + '.json'), JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 });
  const journal = openAppendJournal(folder);
  const append = (event: Record<string, unknown>) => journal.append(event);
  const id = randomUUID(), deadline = Date.now() + scope.limits.maxDurationMs;
  let used = 0, lastEnd = 0, blocked = 0, redirects = 0, setCookieCount = 0, completedActions = 0, stopped: string | null = null, queue = Promise.resolve();
  const facts: { name: string; present: boolean; sha256: string | null; truncated: boolean }[] = [];
  let isolated: Awaited<ReturnType<typeof launchIsolated>> | undefined;
  const failure = (e: unknown) => options.signal?.aborted ? 'cancelled' : e instanceof Error && ['deadline', 'budget-exhausted', 'authorization-expired', 'redirect-not-declared', 'redirect-limit', 'unsafe-response'].includes(e.message) ? e.message : 'browser-action-failed';
  append({ event: 'start', id, scopeDigest: digest(scope), configDigest: digest(config) });
  try {
    isolated = await launchIsolated();
    const context = await isolated.browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    try {
      await context.routeWebSocket('**/*', ws => ws.close());
      const page = await context.newPage();
      const client = await context.newCDPSession(page);
      // Playwright routing covers only the first URL in a redirect chain.
      // Fetch interception sees every hop; the proxy still blocks unrouted traffic.
      await client.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
      client.on('Fetch.requestPaused', event => {
        queue = queue.then(async () => {
          const request = event.request;
          const abort = () => client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
          const entry = requests.find(e => e.step.method === request.method && e.resolved.url.href === request.url
            && (e.resolved.body?.toString('utf8') ?? '') === (request.postData ?? ''));
          if (!entry || stopped) { blocked++; await abort(); return; }
          const reference = id + ':' + (used + 1); let sharedReserved = false;
          try {
            if (options.signal?.aborted) throw new Error('cancelled');
            if (used >= scope.limits.maxRequests) throw new Error('budget-exhausted');
            await waitIntervalOrDeadline(lastEnd, scope.limits.minIntervalMs, deadline, options.signal);
            used++; append({ event: 'reserved', id: reference, stepId: entry.step.id, method: entry.step.method, url: entry.step.url, at: new Date().toISOString() });
            if (options.budget) { await options.budget.beforeRequest(reference, options.signal); sharedReserved = true; }
            const headers = Object.fromEntries(Object.entries(request.headers).map(([name, value]) => [name.toLowerCase(), String(value)]));
            const sameOrigin = new URL(entry.step.url).origin === config.sessionOrigin;
            const credential = sameOrigin ? { ...(headers.cookie ? { cookie: headers.cookie } : {}),
              ...(headers.authorization?.startsWith('Bearer ') ? credentialFor('BBA_TOKEN_BROWSER', headers.authorization.slice(7)) : {}) } : {};
            const r = await scopedRequest(scope, entry.step.url, { ...credential, request: requestSpec(entry.step), browserOrigin: headers.origin, environment: env,
              browserCredentials: true, signal: options.signal, remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity) });
            append({ event: 'response', id: reference, status: r.status, bytes: r.body.length, sha256: createHash('sha256').update(r.body).digest('hex'), credentialPresent: Object.keys(credential).length > 0,
              ...(entry.step.observe ? { facts: projectJson(r.body, r.contentType, entry.step.observe) } : {}) });
            if (r.status === 429 || r.status >= 500) throw new Error('unsafe-response');
            let location: string | undefined;
            if (r.status >= 300 && r.status < 400) {
              if (++redirects > config.maxRedirects) throw new Error('redirect-limit');
              if (!r.location) throw new Error('redirect-not-declared');
              const redirected = new URL(r.location, entry.resolved.url).href;
              if (!requests.some(e => e.resolved.url.href === redirected)) throw new Error('redirect-not-declared');
              location = redirected;
            }
            const cookies = sameOrigin ? r.setCookies : undefined;
            setCookieCount += cookies?.length ?? 0;
            const responseHeaders = Object.entries({ ...r.browserHeaders, ...(r.contentType ? { 'content-type': r.contentType } : {}), ...(location ? { location } : {}) }).map(([name, value]) => ({ name, value }));
            responseHeaders.push(...(cookies ?? []).map(value => ({ name: 'set-cookie', value })));
            await client.send('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: r.status, responseHeaders, body: r.body.toString('base64') });
          } catch (e) { stopped = failure(e); await abort(); }
          finally { if (sharedReserved) options.budget!.complete(reference); lastEnd = Date.now(); }
        });
      });
      page.on('requestfailed', request => {
        const reason = request.failure()?.errorText ?? '';
        append({ event: 'browser-request-failed', stepId: requests.find(e => e.resolved.url.href === request.url())?.step.id ?? null,
          reason: /^net::ERR_[A-Z_]+$/.test(reason) ? reason : 'browser-network-failed' });
      });
      for (const a of config.actions) {
        if (stopped) break;
        if (options.signal?.aborted) throw new Error('cancelled');
        const timeout = Math.min(scope.limits.timeoutMs, deadline - Date.now(), options.budget?.remainingMs() ?? Infinity);
        if (timeout <= 0) throw new Error('deadline');
        if (a.kind === 'navigate') await page.goto(requests.find(e => e.step.id === a.stepId)!.resolved.url.href, { waitUntil: 'networkidle', timeout });
        else if (a.kind === 'fill') await page.locator(a.selector).fill(env[a.valueEnv]!, { timeout });
        else if (a.kind === 'click') await page.locator(a.selector).click({ timeout });
        else await page.locator(a.selector).waitFor({ state: 'visible', timeout });
        await queue; if (!stopped) { completedActions++; append({ event: 'action-complete', index: completedActions, kind: a.kind }); }
      }
      if (!stopped && completedActions === config.actions.length) for (const o of config.observe) {
        const locator = page.locator(o.selector).first();
        if (!await locator.count()) { facts.push({ name: o.name, present: false, sha256: null, truncated: false }); continue; }
        const value = await locator.evaluate((el, attribute) => {
          const text = attribute === null ? el.textContent : el.getAttribute(attribute);
          return text === null ? null : { text: text.slice(0, 4096), truncated: text.length > 4096 };
        }, o.attribute);
        facts.push({ name: o.name, present: value !== null, sha256: value === null ? null : digest(value.text), truncated: value?.truncated ?? false });
      }
    } finally { await context.close(); }
  } catch (e) { stopped ??= failure(e); }
  finally {
    try { await queue.catch(() => {}); if (isolated) await isolated.close(); } finally { append({ event: 'finish', requests: used, stopped }); journal.close(); }
  }
  const result = { schemaVersion: 1, id, status: stopped ? 'unresolved' : 'completed', stopped, requests: used, blocked, redirects, setCookieCount, completedActions, facts,
    limitations: ['Observed controlled workflow only; no vulnerability is automatically confirmed.', 'Every request URL/method/body is predeclared. Dynamic unbound inputs, undeclared redirects and foreign writes are blocked.',
      'Session cookies and Bearer headers originate in the isolated browser and are forwarded only to sessionOrigin; session material is never persisted.',
      'DOM facts retain a digest of at most 4096 characters and indicate truncation. Request/response bodies and fill values are not retained.',
      'No browser-session resume after process loss; review the durable journal and shared budget before restarting.'] };
  writeFileSync(join(folder, 'scenario.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  sealArtifact(folder, { kind: 'scenario', id, scopeDigest: digest(scope), configDigest: digest(config) });
  return result;
}
