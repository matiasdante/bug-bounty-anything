import { assertRequestAllowed } from './scope.ts';
import type { RequestSpec, Scope, Plan } from './scope.ts';
import { digest } from './contracts.ts';

export function resolveRequest(scope: Scope, urlText: string, spec: RequestSpec = { method: 'GET' }, env: Record<string, string | undefined> = process.env) {
  const url = assertRequestAllowed(scope, urlText, spec);
  for (const q of spec.query ?? []) {
    const value = env[q.valueEnv];
    if (value === undefined || Buffer.byteLength(value) > 2048) throw new Error('Missing or invalid query input');
    url.searchParams.append(q.name, value);
  }
  if (url.href.length > 8192) throw new Error('Request URL exceeds limit');
  let body: Buffer | undefined, contentType: string | undefined;
  if (spec.body) {
    const value = env[spec.body.valueEnv];
    if (value === undefined || Buffer.byteLength(value) > 65536) throw new Error('Missing or oversized body input');
    if (spec.body.format === 'json') {
      try { JSON.parse(value); } catch { throw new Error('Invalid JSON body input'); }
      contentType = 'application/json';
    } else contentType = spec.body.format === 'form' ? 'application/x-www-form-urlencoded' : 'text/plain; charset=utf-8';
    body = Buffer.from(value);
  }
  return { url, method: spec.method, body, contentType };
}

export function bindInputs(plan: Plan, sessionId: string, env: Record<string, string | undefined> = process.env): string | undefined {
  const refs = [...new Set(plan.steps.flatMap(s => [...(s.query ?? []).map(q => q.valueEnv), ...(s.body ? [s.body.valueEnv] : [])]))].sort();
  if (!refs.length) return undefined;
  const values = refs.map(ref => {
    if (env[ref] === undefined) throw new Error('Missing request input environment variable');
    return [ref, env[ref]];
  });
  return digest({ sessionId, values });
}
