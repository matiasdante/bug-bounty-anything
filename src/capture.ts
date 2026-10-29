import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright-core';
import type { Route } from 'playwright-core';
import { digest } from './contracts.ts';
import { scopedRequest, RequestFailure } from './http.ts';
import { assertAuthorized, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { requireNewDirectory } from './storage.ts';
import { importSurface } from './surface.ts';
import type { Surface } from './surface.ts';

type Outcome = 'sent' | 'blocked' | 'not-sent' | 'failed';
export type Capture = {
  schemaVersion: 1; toolVersion: '0.4.0'; scopeDigest: string; planDigest: string;
  startedAt: string; endedAt: string; stopReason: string | null;
  counts: Record<Outcome | 'unrepresentable' | 'websocket-blocked', number>;
  // Aligned with surface.entries; requests whose URL cannot be projected are only counted.
  outcomes: Outcome[];
};

const har = (entries: unknown[]) => ({ log: { version: '1.2', entries } });

export async function captureSurface(folder: string, scope: Scope, plan: Plan, options: {
  signal?: AbortSignal; credentials?: Record<string, string | undefined>;
} = {}): Promise<{ capture: Capture; surface: Surface }> {
  validateScope(scope); validatePlan(plan, scope);
  // The browser resolves DNS itself, so the pinned public-address checks of the
  // core cannot be enforced here. shortcut: loopback only, until a BBA proxy exists.
  if (scope.mode !== 'loopback-lab') throw new Error('Browser capture only supports loopback-lab scopes');
  const out = await requireNewDirectory(folder);
  const tokens = new Map<string, string>();
  for (const step of plan.steps) if (step.credentialEnv) {
    const token = (options.credentials ?? process.env)[step.credentialEnv];
    if (!token) throw new Error('Missing credential environment variable');
    if (!/^[A-Za-z0-9._~+/-]{1,4096}={0,2}$/.test(token)) throw new Error('Invalid credential format');
    tokens.set(step.id, token);
  }

  const startedAt = new Date().toISOString(), deadline = Date.now() + scope.limits.maxDurationMs;
  const entries: { method: string; url: string; credential: boolean; status: number | null; outcome: Outcome }[] = [];
  let used = 0, lastEnd = 0, websockets = 0, stopReason: string | null = null, queue = Promise.resolve();

  // Every browser request is decided here, one at a time. Allowed GETs are sent
  // by the shared scoped core (no redirects, size/time limits, no browser headers)
  // and the response is handed to the page; everything else never leaves.
  const handle = async (route: Route, token: string | undefined) => {
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
      used++; entry.credential = token !== undefined; entry.outcome = 'sent';
      try {
        const result = await scopedRequest(scope, entry.url, { token, signal: options.signal, remainingMs: deadline - Date.now() });
        entry.status = result.status;
        if ((result.status >= 300 && result.status < 400) || result.status === 429 || result.status >= 500) {
          stopReason = result.status === 429 ? 'rate-limited' : result.status >= 500 ? 'server-error' : 'redirect';
        }
        await route.fulfill({ status: result.status, contentType: result.contentType || undefined, body: result.body });
      } catch (error) {
        entry.outcome = 'failed';
        stopReason = error instanceof RequestFailure ? error.code : 'browser-error';
        await route.abort('failed');
      }
    } catch { /* The page may close while a route is pending; the entry is already recorded. */ }
    finally { lastEnd = Date.now(); }
  };

  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { throw new Error('Browser unavailable; run npx playwright-core install --only-shell chromium'); }
  try {
    for (const step of plan.steps) {
      if (options.signal?.aborted) stopReason ??= 'cancelled';
      if (stopReason) break;
      // One ephemeral context per step: no cookies or storage cross identities.
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        const token = tokens.get(step.id);
        await context.route('**/*', route => { queue = queue.then(() => handle(route, token)); return queue; });
        // Without connectToServer the socket is mocked: no handshake leaves the browser.
        await context.routeWebSocket('**/*', ws => { websockets++; ws.close(); });
        const page = await context.newPage();
        const timeout = deadline - Date.now();
        if (timeout <= 0) { stopReason = 'deadline'; break; }
        // Blocked or failed loads are recorded by the route handler, not here.
        await page.goto(step.url, { waitUntil: 'networkidle', timeout }).catch(() => {});
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  await queue;

  const projectable = entries.filter(e => {
    try { importSurface(har([harRecord(e)]), 'har'); return true; } catch { return false; }
  });
  const surface = importSurface(har(projectable.map(harRecord)), 'har');
  surface.limitations.push('Browser capture: status null means the request was blocked or not sent by BBA; see capture.json outcomes.',
    'Only GET to exact in-scope paths was sent, with the plan Bearer token. Browser cookies and headers were not forwarded.');
  const count = (outcome: Outcome) => entries.filter(e => e.outcome === outcome).length;
  const capture: Capture = {
    schemaVersion: 1, toolVersion: '0.4.0', scopeDigest: digest(scope), planDigest: digest(plan),
    startedAt, endedAt: new Date().toISOString(), stopReason,
    counts: { sent: count('sent'), blocked: count('blocked'), 'not-sent': count('not-sent'), failed: count('failed'),
      unrepresentable: entries.length - projectable.length, 'websocket-blocked': websockets },
    outcomes: projectable.map(e => e.outcome),
  };
  mkdirSync(dirname(out), { recursive: true });
  mkdirSync(out); // Throws if another process created it meanwhile.
  writeFileSync(join(out, 'surface.json'), JSON.stringify({ surface, sha256: digest(surface) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(out, 'capture.json'), JSON.stringify({ capture, sha256: digest(capture) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { capture, surface };
}

function harRecord(e: { method: string; url: string; credential: boolean; status: number | null }) {
  return { request: { method: e.method, url: e.url, queryString: [], headers: e.credential ? [{ name: 'Authorization', value: '' }] : [] },
    response: { status: e.status ?? 0 } };
}
