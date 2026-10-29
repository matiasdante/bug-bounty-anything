export type Scope = {
  schemaVersion: 1;
  mode: 'loopback-lab' | 'public-https';
  authorization: { reference: string; validFrom: string; validUntil: string };
  allowed: { origin: string; paths: string[] }[];
  excluded: { origin: string; paths: string[] }[];
  limits: { maxRequests: number; minIntervalMs: number; timeoutMs: number; maxResponseBytes: number; maxDurationMs: number };
};
export type Step = { id: string; method: 'GET'; url: string; credentialEnv: string | null };
export type Plan = { schemaVersion: 1; steps: Step[] };

export function fields(value: unknown, keys: string[]): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error('Invalid contract fields');
}
export function integer(value: unknown, min: number, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < min || Number(value) > max) throw new Error('Invalid limit');
}
export function isoDate(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error('Invalid timestamp');
}

// Conservative URL subset: no queries, escapes, credentials, fragments or
// normalization ambiguities. Paths are exact, case-sensitive matches.
export function strictUrl(value: unknown): URL {
  if (typeof value !== 'string' || value.length > 2048 || /[%\\\s?#@]/.test(value)) throw new Error('Invalid URL');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.href !== value
    || !/^\/[A-Za-z0-9._~/-]*$/.test(url.pathname)) throw new Error('Non-canonical URL');
  return url;
}

export function validateScope(value: unknown): asserts value is Scope {
  fields(value, ['schemaVersion', 'mode', 'authorization', 'allowed', 'excluded', 'limits']);
  if (value.schemaVersion !== 1 || !['loopback-lab', 'public-https'].includes(value.mode)) throw new Error('Unsupported scope');
  fields(value.authorization, ['reference', 'validFrom', 'validUntil']);
  const auth = value.authorization;
  if (typeof auth.reference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(auth.reference)) throw new Error('Invalid authorization reference');
  isoDate(auth.validFrom); isoDate(auth.validUntil);
  if (auth.validFrom >= auth.validUntil) throw new Error('Invalid authorization window');
  for (const key of ['allowed', 'excluded']) {
    const rules = value[key];
    if (!Array.isArray(rules) || rules.length > 20 || (key === 'allowed' && !rules.length)) throw new Error('Invalid scope rules');
    const origins = new Set();
    for (const rule of rules) {
      fields(rule, ['origin', 'paths']);
      const url = strictUrl(rule.origin + '/');
      if (url.origin !== rule.origin || origins.has(rule.origin)) throw new Error('Invalid scope origin');
      origins.add(rule.origin);
      if (value.mode === 'loopback-lab') {
        if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port) throw new Error('Invalid loopback origin');
      } else if (url.protocol !== 'https:') throw new Error('Public targets require HTTPS');
      if (!Array.isArray(rule.paths) || !rule.paths.length || rule.paths.length > 100
        || new Set(rule.paths).size !== rule.paths.length) throw new Error('Invalid scope paths');
      for (const path of rule.paths) {
        if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')
          || strictUrl(rule.origin + path).pathname !== path) throw new Error('Invalid scope path');
      }
    }
  }
  fields(value.limits, ['maxRequests', 'minIntervalMs', 'timeoutMs', 'maxResponseBytes', 'maxDurationMs']);
  integer(value.limits.maxRequests, 1, 100);
  integer(value.limits.minIntervalMs, 0, 60000);
  integer(value.limits.timeoutMs, 1, 60000);
  integer(value.limits.maxResponseBytes, 1, 1024 * 1024);
  integer(value.limits.maxDurationMs, 1, 86400000);
}

export function assertAuthorized(scope: Scope, urlText: string, now = Date.now()): URL {
  const url = strictUrl(urlText);
  if (now < Date.parse(scope.authorization.validFrom) || now >= Date.parse(scope.authorization.validUntil)) throw new Error('Authorization expired or not active');
  const match = (rule: Scope['allowed'][number]) => rule.origin === url.origin && rule.paths.includes(url.pathname);
  if (!scope.allowed.some(match) || scope.excluded.some(match)) throw new Error('Request blocked: outside scope');
  return url;
}

export function validatePlan(value: unknown, scope: Scope, checkTime = true): asserts value is Plan {
  fields(value, ['schemaVersion', 'steps']);
  if (value.schemaVersion !== 1 || !Array.isArray(value.steps) || !value.steps.length || value.steps.length > 100) throw new Error('Invalid plan');
  const ids = new Set();
  for (const step of value.steps) {
    fields(step, ['id', 'method', 'url', 'credentialEnv']);
    if (typeof step.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(step.id) || ids.has(step.id)) throw new Error('Invalid step ID');
    ids.add(step.id);
    if (step.method !== 'GET') throw new Error('Only GET is supported');
    if (step.credentialEnv !== null && (typeof step.credentialEnv !== 'string' || !/^BBA_TOKEN_[A-Z0-9_]{1,50}$/.test(step.credentialEnv))) throw new Error('Invalid credential reference');
    assertAuthorized(scope, step.url, checkTime ? Date.now() : Date.parse(scope.authorization.validFrom));
  }
}
