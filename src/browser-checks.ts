import { mkdirSync, openSync, writeSync, fsyncSync, closeSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { launchIsolated } from './capture.ts';
import { credentialFor, scopedRequest } from './http.ts';
import { fields, integer, requestSpec, validatePlan, validateScope } from './scope.ts';
import type { Scope, Step } from './scope.ts';
import { resolveRequest } from './requests.ts';
import { validateProjections, projectJson } from './observations.ts';
import { digest } from './contracts.ts';
import { validateHeaderEnvironment } from './headers.ts';
import type { ProgramBudget } from './budget.ts';
import { sealArtifact } from './artifacts.ts';

type Base = { schemaVersion: 1; policyReference: string; resources: Step[]; observationMs: number };
export type BrowserCheck = Base & (
  { class: 'xss'; boundary: 'untrusted-input-script'; baseline: Step; probe: Step; markerEnv: string }
  | { class: 'cors'; boundary: 'private-cross-origin-read'; baseline: Step; probe: Step; target: Step;
    protectedPointer: string; cookie: { origin: string; valueEnv: string; sameSite: 'Strict' | 'Lax' | 'None' } });

export function validateBrowserCheck(value: unknown, scope: Scope): asserts value is BrowserCheck {
  if (!value || typeof value !== 'object') throw new Error('Invalid browser check');
  const c = value as BrowserCheck;
  fields(value, ['schemaVersion', 'class', 'policyReference', 'resources', 'observationMs', 'boundary', 'baseline', 'probe',
    ...(c.class === 'xss' ? ['markerEnv'] : ['target', 'protectedPointer', 'cookie'])]);
  if (c.schemaVersion !== 1 || !['xss', 'cors'].includes(c.class) || typeof c.policyReference !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(c.policyReference) || !Array.isArray(c.resources) || c.resources.length > 50) throw new Error('Invalid browser configuration');
  integer(c.observationMs, 50, 5000);
  const steps = [c.baseline, c.probe, ...c.resources, ...(c.class === 'cors' ? [c.target] : [])];
  validatePlan({ schemaVersion: 1, steps }, scope);
  if (steps.some(s => s.method !== 'GET' || s.body || s.observe)) throw new Error('Browser checks require explicit GET requests');
  if (c.class === 'xss') {
    if (c.boundary !== 'untrusted-input-script' || c.baseline.url !== c.probe.url || c.baseline.credentialEnv !== c.probe.credentialEnv
      || typeof c.markerEnv !== 'string' || !/^BBA_INPUT_[A-Z0-9_]{1,50}$/.test(c.markerEnv)) throw new Error('Invalid XSS comparison');
  } else {
    fields(c.cookie, ['origin', 'valueEnv', 'sameSite']);
    const targetOrigin = new URL(c.target.url).origin;
    if (c.boundary !== 'private-cross-origin-read' || new URL(c.baseline.url).origin !== targetOrigin
      || new URL(c.probe.url).origin === targetOrigin || c.cookie.origin !== targetOrigin
      || typeof c.cookie.valueEnv !== 'string' || !/^BBA_COOKIE_[A-Z0-9_]{1,50}$/.test(c.cookie.valueEnv)
      || c.target.credentialEnv !== c.cookie.valueEnv || !['Strict', 'Lax', 'None'].includes(c.cookie.sameSite)
      || steps.some(s => s.credentialEnv !== null && (s.credentialEnv !== c.cookie.valueEnv || new URL(s.url).origin !== targetOrigin))) throw new Error('Invalid CORS cookie or origin boundary');
    validateProjections([{ name: 'protected', pointer: c.protectedPointer }]);
  }
}

// Chromium evaluates SOP, CSP and cookie delivery. The relay permits only exact
// predeclared GETs and preserves the response headers needed for those policies.
export async function browserCheck(folder: string, scope: Scope, config: BrowserCheck, options: { credentials?: Record<string, string | undefined>; signal?: AbortSignal; budget?: ProgramBudget } = {}) {
  validateScope(scope); validateBrowserCheck(config, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  const env = options.credentials ?? process.env;
  validateHeaderEnvironment(scope, env);
  const all = [config.baseline, config.probe, ...config.resources, ...(config.class === 'cors' ? [config.target] : [])];
  const resolved = new Map(all.map(s => [s.id, resolveRequest(scope, s.url, requestSpec(s), env)]));
  for (const s of all) if (s.credentialEnv) {
    if (!env[s.credentialEnv]) throw new Error('Missing credential environment variable');
    credentialFor(s.credentialEnv, env[s.credentialEnv]!);
  }
  const marker = config.class === 'xss' ? env[config.markerEnv] : null;
  if (config.class === 'xss' && (!marker || !/^[A-Za-z0-9_-]{12,128}$/.test(marker)
    || resolved.get(config.baseline.id)!.url.href === resolved.get(config.probe.id)!.url.href)) throw new Error('Distinct XSS inputs and a unique opaque marker are required');
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  for (const [name, value] of Object.entries({ scope, config })) writeFileSync(join(folder, name + '.json'), JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 });
  const fd = openSync(join(folder, 'requests.jsonl'), 'wx', 0o600);
  const append = (value: unknown) => { writeSync(fd, JSON.stringify(value) + '\n'); fsyncSync(fd); };
  const id = randomUUID(), started = Date.now(), deadline = started + scope.limits.maxDurationMs;
  let used = 0, blocked = 0, lastEnd = 0, stopped: string | null = null, queue = Promise.resolve();
  const observations: { phase: string; complete: boolean; scriptExecuted: boolean; protectedDigest: string | null }[] = [];
  const targetReplies = new Map<string, { status: number; kind: string; sha256: string | null }>();
  const send = async (step: Step, phase: string, cookie?: string, browserOrigin?: string) => {
    if (options.signal?.aborted) throw new Error('cancelled');
    if (used >= scope.limits.maxRequests) throw new Error('budget-exhausted');
    const wait = Math.max(0, lastEnd + scope.limits.minIntervalMs - Date.now());
    if (Date.now() + wait >= deadline) throw new Error('deadline');
    if (wait) await delay(wait, undefined, { signal: options.signal });
    if (options.signal?.aborted) throw new Error('cancelled');
    if (Date.now() >= deadline) throw new Error('deadline');
    const requestId = ++used;
    append({ event: 'reserved', id: id + ':' + requestId, phase, stepId: step.id, url: step.url, at: new Date().toISOString() });
    const reference = id + ':' + requestId; let sharedReserved = false;
    try {
      if (options.budget) { await options.budget.beforeRequest(reference, options.signal); sharedReserved = true; }
      const credential = config.class === 'cors' ? (cookie ? { cookie } : {}) : step.credentialEnv ? credentialFor(step.credentialEnv, env[step.credentialEnv]!) : {};
      const r = await scopedRequest(scope, step.url, { ...credential, request: requestSpec(step), environment: env, browserOrigin, signal: options.signal, remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity) });
      append({ event: 'response', id: id + ':' + requestId, phase, status: r.status, bytes: r.body.length, bodyDigest: createHash('sha256').update(r.body).digest('hex') });
      if (r.status >= 300 && r.status < 400 || r.status === 429 || r.status >= 500) throw new Error('unsafe-response');
      return r;
    } finally { if (sharedReserved) options.budget!.complete(reference); lastEnd = Date.now(); }
  };
  let browser: Awaited<ReturnType<typeof launchIsolated>> | undefined;
  let anonymousStatus: number | null = null;
  append({ event: 'start', id, scopeDigest: digest(scope), configDigest: digest(config), inputBinding: digest({ id, inputs: all.map(s => { const r = resolved.get(s.id)!; return { method: r.method, url: r.url.href }; }) }) });
  try {
    if (config.class === 'cors') anonymousStatus = (await send({ ...config.target, credentialEnv: null }, 'anonymous-control')).status;
    browser = await launchIsolated();
    for (const [phase, seed] of [['baseline', config.baseline], ['probe', config.probe]] as const) {
      const observation = { phase, complete: false, scriptExecuted: false, protectedDigest: null as string | null }; observations.push(observation);
      const context = await browser.browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
      try {
        if (config.class === 'cors') {
          const value = env[config.cookie.valueEnv]!;
          await context.addCookies(value.split('; ').map(pair => { const split = pair.indexOf('='); return { name: pair.slice(0, split), value: pair.slice(split + 1), url: config.cookie.origin + '/', sameSite: config.cookie.sameSite, secure: config.cookie.origin.startsWith('https:') }; }));
        }
        await context.routeWebSocket('**/*', ws => ws.close());
        const allowed = [seed, ...config.resources, ...(config.class === 'cors' ? [config.target] : [])];
        await context.route('**/*', route => {
          queue = queue.then(async () => {
            const request = route.request();
            const step = allowed.find(s => request.method() === 'GET' && resolved.get(s.id)!.url.href === request.url());
            if (!step || stopped) { blocked++; await route.abort('blockedbyclient').catch(() => {}); return; }
            try {
              const actualHeaders = await request.allHeaders();
              const cookie = config.class === 'cors' && step.credentialEnv === config.cookie.valueEnv ? actualHeaders.cookie : undefined;
              const r = await send(step, phase, cookie, actualHeaders.origin);
              if (config.class === 'cors' && step.id === config.target.id) {
                const f = projectJson(r.body, r.contentType, [{ name: 'protected', pointer: config.protectedPointer }])[0];
                targetReplies.set(phase, { status: r.status, kind: f.kind, sha256: f.meaningful ? f.sha256 : null });
                append({ event: 'protected-response', phase, ...targetReplies.get(phase) });
              }
              await route.fulfill({ status: r.status, headers: { ...r.browserHeaders, ...(r.contentType ? { 'content-type': r.contentType } : {}) }, body: r.body });
            } catch (e) {
              stopped = options.signal?.aborted ? 'cancelled' : e instanceof Error && ['cancelled', 'budget-exhausted', 'deadline', 'unsafe-response'].includes(e.message) ? e.message : 'execution-failed';
              await route.abort('failed').catch(() => {});
            }
          }); return queue;
        });
        const page = await context.newPage();
        if (config.class === 'xss') await page.exposeBinding('__bbaProof', (source, value: unknown) => {
          try { if (value === marker && new URL(source.frame.url()).origin === new URL(seed.url).origin) observation.scriptExecuted = true; } catch { /* opaque frame */ }
        });
        await page.goto(resolved.get(seed.id)!.url.href, { waitUntil: 'networkidle', timeout: Math.max(1, deadline - Date.now()) });
        if (config.class === 'cors') {
          const value = await page.evaluate(async ({ url, pointer }) => {
            try {
              const response = await fetch(url, { credentials: 'include', mode: 'cors', cache: 'no-store' });
              if (response.status !== 200) return { available: false };
              let current = await response.json();
              for (const segment of pointer === '' ? [] : pointer.slice(1).split('/').map(s => s.replaceAll('~1', '/').replaceAll('~0', '~'))) {
                if (!current || typeof current !== 'object') return { available: false };
                if (Array.isArray(current)) {
                  if (!/^(?:0|[1-9]\d*)$/.test(segment)) return { available: false };
                  const idx = Number(segment);
                  if (!Number.isSafeInteger(idx) || idx >= current.length) return { available: false };
                  current = current[idx];
                } else {
                  if (!Object.hasOwn(current, segment)) return { available: false };
                  current = current[segment];
                }
              }
              return typeof current === 'string' && current.length || typeof current === 'number' && Number.isFinite(current) ? { available: true, value: current } : { available: false };
            } catch { return { available: false }; }
          }, { url: resolved.get(config.target.id)!.url.href, pointer: config.protectedPointer });
          if (value.available) observation.protectedDigest = digest(value.value);
        } else await page.waitForTimeout(Math.min(config.observationMs, Math.max(0, deadline - Date.now())));
        await queue; observation.complete = !stopped && !options.signal?.aborted && Date.now() < deadline;
      } finally { await context.close(); }
      if (stopped) break;
    }
  } catch (e) { stopped = options.signal?.aborted ? 'cancelled' : e instanceof Error && ['cancelled', 'budget-exhausted', 'deadline', 'unsafe-response'].includes(e.message) ? e.message : 'execution-failed'; }
  finally {
    try { await queue.catch(() => {}); if (browser) await browser.close(); } finally { append({ event: 'finish', requests: used, stopped }); closeSync(fd); }
  }
  const [baseline, probe] = observations;
  let status: 'confirmed' | 'not-reproduced' | 'unresolved' = 'unresolved';
  if (!stopped && baseline?.complete && probe?.complete) {
    if (config.class === 'xss') status = baseline.scriptExecuted ? 'unresolved' : probe.scriptExecuted ? 'confirmed' : blocked ? 'unresolved' : 'not-reproduced';
    else if (anonymousStatus !== null && [401, 403, 404].includes(anonymousStatus) && baseline.protectedDigest) {
      const reply = targetReplies.get('probe');
      status = probe.protectedDigest === baseline.protectedDigest ? 'confirmed'
        : !probe.protectedDigest && !blocked && reply?.status === 200 && (reply.kind === 'missing' || reply.sha256 === baseline.protectedDigest) ? 'not-reproduced' : 'unresolved';
    }
  }
  const result = { schemaVersion: 1, id, class: config.class, status, requests: used, blocked, stopped, anonymousStatus, observations, policyReference: config.policyReference,
    limitations: ['Business policy, controlled-account ownership and attacker control of the declared input/origin are operator preconditions.',
      'Finite browser observation only; negative results do not establish safety. CSP and CORS headers are preserved; external undeclared loads are blocked.',
      'CORS uses declared test-cookie SameSite settings and actual browser cookie delivery; these settings must match the service. No automatic login or cookie rotation is modeled.',
      'Only metadata, marker execution and protected-value digests are retained. No resume; durable reservations survive uncertain attempts.'] };
  writeFileSync(join(folder, 'browser-check.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'report.md'), `# BBA — ${config.class}: ${status}\n\nRegla: ${config.policyReference}. Requests: ${used}. Detención: ${stopped ?? 'ninguna'}. Borrador no enviado.\n\nLa configuración declarada y requests.jsonl identifican baseline y sonda. El resultado conserva la ejecución del marcador o la comparación de la propiedad protegida en Chromium; no conserva su valor.\n\n` + result.limitations.map(l => '- ' + l).join('\n'), { flag: 'wx', mode: 0o600 });
  sealArtifact(folder, { kind: 'browser-check', id, scopeDigest: digest(scope), configDigest: digest(config) });
  return result;
}
