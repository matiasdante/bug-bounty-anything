import { mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright-core';
import type { Route } from 'playwright-core';
import { digest } from './contracts.ts';
import { scopedRequest, RequestFailure, credentialFor } from './http.ts';
import { assertAuthorized, fields, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { requireNewDirectory } from './storage.ts';
import { importSurface } from './surface.ts';
import type { Surface } from './surface.ts';
import { validateHeaderEnvironment } from './headers.ts';
import type { ProgramBudget } from './budget.ts';
import { randomUUID } from 'node:crypto';
import { readJson } from './session.ts';

type PageLink = { path: string; inScope: boolean };
type PageForm = { action: string; method: string; inScope: boolean; fields: string[] };
export type PageSurface = { schemaVersion: 1; scopeDigest: string; planDigest: string; pages: {
  stepId: string; url: string; observed: boolean; links: PageLink[]; forms: PageForm[]; scripts: string[];
  omitted: { links: number; forms: number; scripts: number };
}[] };

function pagePath(raw: string, base: string, scope: Scope): PageLink | null {
  try {
    const url = new URL(raw, base), origin = new URL(base).origin;
    if (url.origin !== origin || /[%\\]/.test(url.pathname)) return null;
    const canonical = origin + url.pathname;
    const path = url.pathname.split('/').map(part => part.length > 24 || /^\d+$/.test(part) || /^[0-9a-f-]{20,}$/i.test(part) ? '{opaque}' : part).join('/');
    let inScope = false;
    try { assertAuthorized(scope, canonical); inScope = true; } catch { /* A discovered path does not expand scope. */ }
    return { path, inScope };
  } catch { return null; }
}

type Outcome = 'sent' | 'blocked' | 'not-sent' | 'failed';
export type Capture = {
  schemaVersion: 1; toolVersion: '0.5.0'; scopeDigest: string; planDigest: string;
  startedAt: string; endedAt: string; stopReason: string | null;
  counts: Record<Outcome | 'unrepresentable' | 'websocket-blocked' | 'leak-attempts', number>;
  // Aligned with surface.entries; requests whose URL cannot be projected are only counted.
  outcomes: Outcome[];
};

// Routed requests are sent by BBA, but Chromium can also open connections by itself
// (unrouted loads, WebRTC). TCP is forced into a loopback sink that refuses and counts
// it, name resolution is disabled and WebRTC may not use UDP outside the proxy.
// Preconnect and dns-prefetch hints did not connect in the pinned build, so they are not a tested vector.
export async function launchIsolated() {
  let leaks = 0;
  const sink = createServer(socket => { leaks++; socket.destroy(); });
  await new Promise<void>((resolve, reject) => { sink.once('error', reject); sink.listen(0, '127.0.0.1', resolve); });
  try {
    const browser = await chromium.launch({
      headless: true,
      proxy: { server: `http://127.0.0.1:${(sink.address() as AddressInfo).port}`, bypass: '<-loopback>' },
      args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],
    });
    return { browser, leaks: () => leaks, close: async () => { await browser.close(); sink.close(); } };
  } catch { sink.close(); throw new Error('Browser unavailable; run npx playwright-core install --only-shell chromium'); }
}

const har = (entries: unknown[]) => ({ log: { version: '1.2', entries } });

export async function captureSurface(folder: string, scope: Scope, plan: Plan, options: {
  signal?: AbortSignal; credentials?: Record<string, string | undefined>;
  budget?: ProgramBudget;
} = {}): Promise<{ capture: Capture; surface: Surface; pages: PageSurface }> {
  validateScope(scope); validatePlan(plan, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  if (plan.steps.some(s => s.method !== 'GET' || s.query || s.body || s.observe)) throw new Error('Browser capture requires a plain GET plan');
  validateHeaderEnvironment(scope, options.credentials);
  const out = await requireNewDirectory(folder);
  const credentials = new Map<string, { token?: string; cookie?: string }>();
  for (const step of plan.steps) if (step.credentialEnv) {
    const value = (options.credentials ?? process.env)[step.credentialEnv];
    if (!value) throw new Error('Missing credential environment variable');
    credentials.set(step.id, credentialFor(step.credentialEnv, value));
  }

  const startedAt = new Date().toISOString(), deadline = Date.now() + scope.limits.maxDurationMs;
  const entries: { method: string; url: string; credential: boolean; status: number | null; outcome: Outcome }[] = [];
  let used = 0, lastEnd = 0, websockets = 0, stopReason: string | null = null, queue = Promise.resolve();
  const captureId = randomUUID();
  const pages: PageSurface = { schemaVersion: 1, scopeDigest: digest(scope), planDigest: digest(plan), pages: [] };

  // Every browser request is decided here, one at a time. Allowed GETs are sent
  // by the shared scoped core (no redirects, size/time limits, no browser headers)
  // and the response is handed to the page; everything else never leaves.
  const handle = async (route: Route, credential: { token?: string; cookie?: string } | undefined) => {
    const request = route.request();
    const entry = { method: request.method(), url: request.url(), credential: false, status: null as number | null, outcome: 'not-sent' as Outcome };
    entries.push(entry);
    try {
      if (options.signal?.aborted) stopReason ??= 'cancelled';
      if (!stopReason) {
        try { if (entry.method !== 'GET') throw new Error(); assertAuthorized(scope, entry.url); }
        catch { entry.outcome = 'blocked'; return await route.abort('blockedbyclient'); }
        if (used >= scope.limits.maxRequests) stopReason = 'budget-exhausted';
        else if (Date.now() >= deadline) stopReason = 'deadline';
      }
      if (stopReason) return await route.abort('blockedbyclient');
      const wait = Math.max(0, lastEnd + scope.limits.minIntervalMs - Date.now());
      if (wait) await delay(wait);
      if (options.signal?.aborted || Date.now() >= deadline) {
        stopReason = options.signal?.aborted ? 'cancelled' : 'deadline';
        return await route.abort('blockedbyclient');
      }
      used++; entry.credential = credential !== undefined; entry.outcome = 'sent';
      const reference = captureId + ':' + used; let sharedReserved = false;
      try {
        if (options.budget) { await options.budget.beforeRequest(reference, options.signal); sharedReserved = true; }
        const result = await scopedRequest(scope, entry.url, { ...credential, signal: options.signal, remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity), environment: options.credentials });
        entry.status = result.status;
        if ((result.status >= 300 && result.status < 400) || result.status === 429 || result.status >= 500) {
          stopReason = result.status === 429 ? 'rate-limited' : result.status >= 500 ? 'server-error' : 'redirect';
        }
        await route.fulfill({ status: result.status, contentType: result.contentType || undefined, body: result.body });
      } catch (error) {
        entry.outcome = 'failed';
        stopReason = error instanceof RequestFailure ? error.code : 'browser-error';
        await route.abort('failed');
      } finally {
        if (sharedReserved) options.budget!.complete(reference);
      }
    } catch { /* The page may close while a route is pending; the entry is already recorded. */ }
    finally { lastEnd = Date.now(); }
  };

  const isolated = await launchIsolated();
  const browser = isolated.browser;
  try {
    for (const step of plan.steps) {
      if (options.signal?.aborted) stopReason ??= 'cancelled';
      if (stopReason) break;
      // One ephemeral context per step: no cookies or storage cross identities.
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        const credential = credentials.get(step.id);
        await context.route('**/*', route => {
          const sameOrigin = new URL(route.request().url()).origin === new URL(step.url).origin;
          queue = queue.then(() => handle(route, sameOrigin ? credential : undefined)); return queue;
        });
        // Without connectToServer the socket is mocked: no handshake leaves the browser.
        await context.routeWebSocket('**/*', ws => { websockets++; ws.close(); });
        const page = await context.newPage();
        const timeout = deadline - Date.now();
        if (timeout <= 0) { stopReason = 'deadline'; break; }
        // Blocked or failed loads are recorded by the route handler, not here.
        await page.goto(step.url, { waitUntil: 'networkidle', timeout }).catch(() => {});
        // Late fetches and browser-initiated connections show up just after idle.
        await page.waitForTimeout(Math.min(500, Math.max(0, deadline - Date.now()))).catch(() => {});
        const dom = page.url() === step.url ? await page.evaluate(() => ({
          links: Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(a => a.getAttribute('href') || ''),
          forms: Array.from(document.querySelectorAll('form')).slice(0, 100).map(form => ({
            action: form.getAttribute('action') || location.href, method: (form.getAttribute('method') || 'GET').toUpperCase(),
            fields: Array.from(form.querySelectorAll('[name]')).slice(0, 50).map(field => field.getAttribute('name') || '') })),
          scripts: Array.from(document.querySelectorAll('script[src]')).slice(0, 100).map(script => script.getAttribute('src') || ''),
          counts: { links: document.querySelectorAll('a[href]').length, forms: document.querySelectorAll('form').length,
            scripts: document.querySelectorAll('script[src]').length },
        })).catch(() => null) : null;
        const links = new Map<string, PageLink>();
        const forms: PageForm[] = [], scripts = new Set<string>();
        if (dom) {
          for (const raw of dom.links) { const found = pagePath(raw, step.url, scope); if (found && links.size < 100) links.set(found.path, found); }
          for (const form of dom.forms) {
            const action = pagePath(form.action, step.url, scope);
            if (!action || forms.length >= 30) continue;
            forms.push({ action: action.path, method: /^[A-Z]{1,12}$/.test(form.method) ? form.method : 'UNKNOWN',
              inScope: action.inScope, fields: [...new Set(form.fields.filter(name => /^[A-Za-z0-9_.-]{1,64}$/.test(name)))].slice(0, 30) });
          }
          for (const raw of dom.scripts) { const found = pagePath(raw, step.url, scope); if (found && scripts.size < 50) scripts.add(found.path); }
        }
        pages.pages.push({ stepId: step.id, url: step.url, observed: dom !== null,
          links: [...links.values()], forms, scripts: [...scripts],
          omitted: { links: Math.max(0, (dom?.counts.links ?? 0) - links.size), forms: Math.max(0, (dom?.counts.forms ?? 0) - forms.length),
            scripts: Math.max(0, (dom?.counts.scripts ?? 0) - scripts.size) } });
      } finally { await context.close(); }
    }
  } finally { await isolated.close(); }
  await queue;

  const projectable = entries.filter(e => {
    try { importSurface(har([harRecord(e)]), 'har'); return true; } catch { return false; }
  });
  const surface = importSurface(har(projectable.map(harRecord)), 'har');
  surface.limitations.push('Browser capture: status null means the request was blocked or not sent by BBA; see capture.json outcomes.',
    'Only GET to exact in-scope paths was sent, with the plan credential (Bearer or Cookie). Browser cookies and headers were not forwarded; Set-Cookie from responses is not applied, so a rotating session can end unauthenticated.');
  const count = (outcome: Outcome) => entries.filter(e => e.outcome === outcome).length;
  const capture: Capture = {
    schemaVersion: 1, toolVersion: '0.5.0', scopeDigest: digest(scope), planDigest: digest(plan),
    startedAt, endedAt: new Date().toISOString(), stopReason,
    counts: { sent: count('sent'), blocked: count('blocked'), 'not-sent': count('not-sent'), failed: count('failed'),
      unrepresentable: entries.length - projectable.length, 'websocket-blocked': websockets, 'leak-attempts': isolated.leaks() },
    outcomes: projectable.map(e => e.outcome),
  };
  mkdirSync(dirname(out), { recursive: true });
  mkdirSync(out); // Throws if another process created it meanwhile.
  writeFileSync(join(out, 'surface.json'), JSON.stringify({ surface, sha256: digest(surface) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(out, 'capture.json'), JSON.stringify({ capture, sha256: digest(capture) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(out, 'pages.json'), JSON.stringify({ pages, sha256: digest(pages) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { capture, surface, pages };
}

function harRecord(e: { method: string; url: string; credential: boolean; status: number | null }) {
  return { request: { method: e.method, url: e.url, queryString: [], headers: e.credential ? [{ name: 'Authorization', value: '' }] : [] },
    response: { status: e.status ?? 0 } };
}

export function readPageSurface(folder: string): PageSurface {
  const saved = readJson(join(folder, 'pages.json'));
  fields(saved, ['pages', 'sha256']);
  if (saved.sha256 !== digest(saved.pages) || saved.pages?.schemaVersion !== 1 || !Array.isArray(saved.pages.pages))
    throw new Error('Page surface integrity mismatch');
  return saved.pages as PageSurface;
}
