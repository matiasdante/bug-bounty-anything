import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { digest } from './contracts.ts';
import { scopedRequest, RequestFailure, credentialFor } from './http.ts';
import { validateScope, assertAuthorized } from './scope.ts';
import type { Scope } from './scope.ts';
import { withSession } from './session.ts';
import type { Session, Attempt } from './session.ts';

export async function executeSession(folder: string, scope: Scope, options: {
  signal?: AbortSignal; credentials?: Record<string, string | undefined>;
} = {}): Promise<Session> {
  validateScope(scope);
  return withSession(folder, async (state, checkpoint) => {
    if (digest(scope) !== state.scopeDigest) throw new Error('Scope changed; create a new investigation');
    if (state.status === 'stopped') throw new Error('Session stopped; review the cause before a new investigation');
    if (['completed', 'partial'].includes(state.status)) return state;
    for (const step of state.plan.steps) assertAuthorized(scope, step.url);
    // Missing secrets fail before any reservation or network access. Only their
    // environment-variable names are stored; values live in memory for this call.
    const tokens = new Map<string, string>();
    for (const step of state.plan.steps.slice(state.attempts.length)) {
      if (step.credentialEnv) {
        const token = (options.credentials ?? process.env)[step.credentialEnv];
        if (!token) throw new Error('Missing credential environment variable');
        credentialFor(step.credentialEnv, token); // Validates the format; the value stays in memory only.
        tokens.set(step.id, token);
      }
    }
    const pending = state.attempts.at(-1);
    if (pending?.outcome === 'reserved') {
      pending.outcome = 'interrupted'; pending.reason = 'interrupted'; pending.endedAt = new Date().toISOString();
      state.status = 'paused'; state.stopReason = 'interrupted'; checkpoint(state);
    }
    const deadline = Date.parse(state.createdAt) + scope.limits.maxDurationMs;
    const stop = (reason: string, status: 'paused' | 'stopped' = 'stopped') => {
      state.status = status; state.stopReason = reason; checkpoint(state); return state;
    };
    for (const step of state.plan.steps.slice(state.attempts.length)) {
      if (options.signal?.aborted) return stop('cancelled', 'paused');
      if (state.attempts.length >= scope.limits.maxRequests) return stop('budget-exhausted');
      if (Date.now() >= deadline) return stop('deadline');
      const last = state.attempts.at(-1);
      const wait = last ? Math.max(0, Date.parse(last.endedAt ?? last.startedAt) + scope.limits.minIntervalMs - Date.now()) : 0;
      if (wait > 0) {
        if (Date.now() + wait >= deadline) return stop('deadline');
        try { await delay(wait, undefined, { signal: options.signal }); }
        catch { return stop('cancelled', 'paused'); }
      }
      try { assertAuthorized(scope, step.url); } catch { return stop('authorization-expired'); }
      if (options.signal?.aborted) return stop('cancelled', 'paused');
      const attempt: Attempt = { stepId: step.id, startedAt: new Date().toISOString(), endedAt: null, outcome: 'reserved', reason: null, response: null };
      state.attempts.push(attempt); state.status = 'running'; state.stopReason = null;
      checkpoint(state); // Durable intent before send: a crash never refunds it.
      try {
        const response = await scopedRequest(scope, step.url, {
          ...(step.credentialEnv ? credentialFor(step.credentialEnv, tokens.get(step.id)!) : {}), signal: options.signal, remainingMs: deadline - Date.now(),
        });
        attempt.response = { status: response.status, bytes: response.body.length,
          sha256: createHash('sha256').update(response.body).digest('hex') };
        const reason = response.status >= 300 && response.status < 400 ? 'redirect'
          : response.status === 429 ? 'rate-limited' : response.status >= 500 ? 'server-error' : null;
        attempt.endedAt = new Date().toISOString(); attempt.outcome = reason ? 'error' : 'succeeded'; attempt.reason = reason;
        if (reason) { state.status = 'stopped'; state.stopReason = reason; }
      } catch (error) {
        const reason = error instanceof RequestFailure ? error.code : 'network-error';
        attempt.endedAt = new Date().toISOString(); attempt.outcome = reason === 'cancelled' ? 'cancelled' : 'error'; attempt.reason = reason;
        state.status = reason === 'cancelled' ? 'paused' : 'stopped'; state.stopReason = reason;
      }
      // Storage failures must escape; never relabel them as network failures
      // or overwrite a reservation whose commit status is uncertain.
      checkpoint(state);
      if (state.status === 'stopped' || state.status === 'paused') return state;
    }
    state.status = state.attempts.every(a => a.outcome === 'succeeded') ? 'completed' : 'partial';
    state.stopReason = null; checkpoint(state);
    return state;
  });
}
