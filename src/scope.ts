import { validateProjections } from './observations.ts';
import type { Projection } from './observations.ts';

export const methods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type Method = typeof methods[number];
export type RequestSpec = { method: Method; query?: { name: string; valueEnv: string }[];
  body?: { format: 'json' | 'form' | 'text'; valueEnv: string } };
export type ScopeRule = { origin: string; paths: string[]; pathPrefixes?: string[] };
export type RequestRule = {
  origin: string;
  path?: string;
  pathPrefix?: string;
  method: Method;
  queryNames: string[];
  bodyFormats: ('json' | 'form' | 'text')[];
};
export type Scope = {
  schemaVersion: 1;
  mode: 'loopback-lab' | 'public-https';
  authorization: { reference: string; validFrom: string; validUntil: string };
  allowed: ScopeRule[];
  excluded: ScopeRule[];
  requestHeaders?: { origin: string; name: string; valueEnv: string }[];
  requestRules?: RequestRule[];
  budgetId?: string;
  limits: { maxRequests: number; minIntervalMs: number; timeoutMs: number; maxResponseBytes: number; maxDurationMs: number };
};
export type Step = RequestSpec & { id: string; url: string; credentialEnv: string | null; observe?: Projection[] };
export type Plan = { schemaVersion: 1; steps: Step[] };

export function fields(value: unknown, keys: string[]): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error('Invalid contract fields');
}
export function integer(value: unknown, min: number, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < min || Number(value) > max) throw new Error('Invalid limit');
}
export function optionalFields(value: unknown, required: string[], optional: string[]): asserts value is Record<string, any> {
  const present = value && typeof value === 'object' ? optional.filter(k => Object.hasOwn(value, k)) : [];
  fields(value, [...required, ...present]);
}
export function isoDate(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error('Invalid timestamp');
}

const pcharSegmentRegex = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-F]{2})*$/;
const forbiddenPercentEscapeRegex = /%(?:0[0-9A-F]|1[0-9A-F]|2E|2F|5C|7F)/i;

export function isCanonicalUrlPath(pathname: string): boolean {
  if (!pathname.startsWith('/') || pathname.length > 2048 || pathname.includes('//')) return false;
  if (forbiddenPercentEscapeRegex.test(pathname)) return false;
  const segments = pathname.slice(1).split('/');
  for (const segment of segments) {
    if (segment === '.' || segment === '..' || !pcharSegmentRegex.test(segment)) return false;
  }
  return true;
}

// Canonical RFC 3986 URL subset: no queries, userinfo, fragments, traversal or encoded separators.
export function strictUrl(value: unknown): URL {
  if (typeof value !== 'string' || value.length > 2048 || /[\\\s?#]/.test(value)) throw new Error('Invalid URL');
  const schemeSep = value.indexOf('://');
  if (schemeSep <= 0) throw new Error('Invalid URL');
  const pathStart = value.indexOf('/', schemeSep + 3);
  const authority = pathStart === -1 ? value.slice(schemeSep + 3) : value.slice(schemeSep + 3, pathStart);
  if (authority.includes('@')) throw new Error('Invalid URL');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.href !== value
    || !isCanonicalUrlPath(url.pathname)) throw new Error('Non-canonical URL');
  return url;
}

export const queryParamNameRegex = /^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]*\]){0,4}$/;
const templatePlaceholderRegex = /^\{[A-Za-z_][A-Za-z0-9_]{0,63}\}$/;

function validateScopePathPattern(origin: string, pattern: unknown): string {
  if (typeof pattern !== 'string' || !pattern.startsWith('/') || pattern.startsWith('//') || pattern.length > 2048) {
    throw new Error('Invalid scope path');
  }
  if (!pattern.includes('{') && !pattern.includes('}')) {
    if (strictUrl(origin + pattern).pathname !== pattern) throw new Error('Invalid scope path');
    return pattern;
  }
  const segments = pattern.slice(1).split('/');
  const concrete = '/' + segments.map(seg => {
    if (templatePlaceholderRegex.test(seg)) return 'sample';
    if (seg.includes('{') || seg.includes('}')) throw new Error('Invalid scope path');
    return seg;
  }).join('/');
  if (strictUrl(origin + concrete).pathname !== concrete) throw new Error('Invalid scope path');
  return pattern;
}

function validateScopePathPrefix(origin: string, prefix: unknown): string {
  if (typeof prefix !== 'string' || !prefix.startsWith('/') || prefix.startsWith('//') || prefix.length > 512
    || prefix.includes('{') || prefix.includes('}')) {
    throw new Error('Invalid scope path prefix');
  }
  if (strictUrl(origin + prefix).pathname !== prefix) throw new Error('Invalid scope path prefix');
  return prefix;
}

export function matchesPathPattern(pattern: string, pathname: string): boolean {
  if (!pattern.includes('{')) return pattern === pathname;
  const patParts = pattern.split('/');
  const actParts = pathname.split('/');
  if (patParts.length !== actParts.length) return false;
  for (let i = 1; i < patParts.length; i++) {
    if (templatePlaceholderRegex.test(patParts[i])) {
      if (!actParts[i]) return false;
    } else if (patParts[i] !== actParts[i]) {
      return false;
    }
  }
  return true;
}

export function matchesPathPrefix(prefix: string, pathname: string): boolean {
  if (prefix === '/') return pathname.startsWith('/');
  const clean = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  return pathname === clean || pathname.startsWith(clean + '/');
}

export function matchesScopeRule(rule: ScopeRule, url: URL): boolean {
  if (rule.origin !== url.origin) return false;
  if (rule.paths.some(p => matchesPathPattern(p, url.pathname))) return true;
  if (rule.pathPrefixes?.some(pref => matchesPathPrefix(pref, url.pathname))) return true;
  return false;
}

export function validateScope(value: unknown): asserts value is Scope {
  optionalFields(value, ['schemaVersion', 'mode', 'authorization', 'allowed', 'excluded', 'limits'], ['requestHeaders', 'requestRules', 'budgetId']);
  if (value.budgetId !== undefined && (typeof value.budgetId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value.budgetId))) throw new Error('Invalid shared budget ID');
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
      optionalFields(rule, ['origin', 'paths'], ['pathPrefixes']);
      const url = strictUrl(rule.origin + '/');
      if (url.origin !== rule.origin || origins.has(rule.origin)) throw new Error('Invalid scope origin');
      origins.add(rule.origin);
      if (value.mode === 'loopback-lab') {
        if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port) throw new Error('Invalid loopback origin');
      } else if (url.protocol !== 'https:') throw new Error('Public targets require HTTPS');
      const hasPrefixes = rule.pathPrefixes !== undefined;
      if (!Array.isArray(rule.paths) || rule.paths.length > 100
        || new Set(rule.paths).size !== rule.paths.length
        || (!hasPrefixes && !rule.paths.length)) throw new Error('Invalid scope paths');
      for (const path of rule.paths) validateScopePathPattern(rule.origin, path);
      if (rule.pathPrefixes !== undefined) {
        if (!Array.isArray(rule.pathPrefixes) || !rule.pathPrefixes.length || rule.pathPrefixes.length > 50
          || new Set(rule.pathPrefixes).size !== rule.pathPrefixes.length) throw new Error('Invalid scope path prefixes');
        for (const pref of rule.pathPrefixes) validateScopePathPrefix(rule.origin, pref);
      }
    }
  }
  if (value.requestHeaders !== undefined) {
    if (!Array.isArray(value.requestHeaders) || value.requestHeaders.length > 20) throw new Error('Invalid request headers');
    const seen = new Set<string>();
    for (const header of value.requestHeaders) {
      fields(header, ['origin', 'name', 'valueEnv']);
      if (!value.allowed.some((rule: ScopeRule) => rule.origin === header.origin)
        || typeof header.name !== 'string' || !/^(user-agent|x-[a-z0-9-]{1,60})$/.test(header.name)
        || typeof header.valueEnv !== 'string' || !/^BBA_HEADER_[A-Z0-9_]{1,50}$/.test(header.valueEnv)) throw new Error('Invalid identifying header');
      const key = header.origin + ':' + header.name;
      if (seen.has(key)) throw new Error('Duplicate identifying header');
      seen.add(key);
    }
  }
  if (value.requestRules !== undefined) {
    if (!Array.isArray(value.requestRules) || value.requestRules.length > 100) throw new Error('Invalid request rules');
    const seen = new Set<string>();
    for (const rule of value.requestRules) {
      optionalFields(rule, ['origin', 'method', 'queryNames', 'bodyFormats'], ['path', 'pathPrefix']);
      if (typeof rule.origin !== 'string' || !methods.includes(rule.method)
        || (rule.path === undefined) === (rule.pathPrefix === undefined)) throw new Error('Invalid request rule');
      let samplePath: string;
      let ruleKey: string;
      if (rule.path !== undefined) {
        validateScopePathPattern(rule.origin, rule.path);
        samplePath = '/' + rule.path.slice(1).split('/').map((s: string) => templatePlaceholderRegex.test(s) ? 'sample' : s).join('/');
        ruleKey = rule.origin + ':path:' + rule.path + ':' + rule.method;
      } else {
        validateScopePathPrefix(rule.origin, rule.pathPrefix);
        samplePath = rule.pathPrefix;
        ruleKey = rule.origin + ':prefix:' + rule.pathPrefix + ':' + rule.method;
      }
      assertAuthorized(value as Scope, rule.origin + samplePath, Date.parse(auth.validFrom));
      if (seen.has(ruleKey)) throw new Error('Duplicate request rule');
      seen.add(ruleKey);
      if (!Array.isArray(rule.queryNames) || rule.queryNames.length > 20 || new Set(rule.queryNames).size !== rule.queryNames.length
        || rule.queryNames.some((n: unknown) => typeof n !== 'string' || n.length > 64 || !queryParamNameRegex.test(n))) throw new Error('Invalid query names');
      if (!Array.isArray(rule.bodyFormats) || rule.bodyFormats.length > 3 || new Set(rule.bodyFormats).size !== rule.bodyFormats.length
        || rule.bodyFormats.some((f: unknown) => !['json', 'form', 'text'].includes(f as string))
        || (['GET', 'HEAD'].includes(rule.method) && rule.bodyFormats.length)) throw new Error('Invalid body formats');
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
  if (!scope.allowed.some(rule => matchesScopeRule(rule, url)) || scope.excluded.some(rule => matchesScopeRule(rule, url))) {
    throw new Error('Request blocked: outside scope');
  }
  return url;
}

export function validatePlan(value: unknown, scope: Scope, checkTime = true): asserts value is Plan {
  fields(value, ['schemaVersion', 'steps']);
  if (value.schemaVersion !== 1 || !Array.isArray(value.steps) || !value.steps.length || value.steps.length > 100) throw new Error('Invalid plan');
  const ids = new Set();
  for (const step of value.steps) {
    optionalFields(step, ['id', 'method', 'url', 'credentialEnv'], ['query', 'body', 'observe']);
    if (typeof step.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(step.id) || ids.has(step.id)) throw new Error('Invalid step ID');
    ids.add(step.id);
    if (step.credentialEnv !== null && (typeof step.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(step.credentialEnv))) throw new Error('Invalid credential reference');
    assertRequestAllowed(scope, step.url, requestSpec(step as Step), checkTime ? Date.now() : Date.parse(scope.authorization.validFrom));
    if (step.observe !== undefined) validateProjections(step.observe);
  }
}

export function requestSpec(step: RequestSpec): RequestSpec {
  return { method: step.method, ...(step.query === undefined ? {} : { query: step.query }), ...(step.body === undefined ? {} : { body: step.body }) };
}

export function assertRequestAllowed(scope: Scope, urlText: string, spec: RequestSpec, now = Date.now()): URL {
  const url = assertAuthorized(scope, urlText, now);
  optionalFields(spec, ['method'], ['query', 'body']);
  if (!methods.includes(spec.method)) throw new Error('Unsupported method');
  if (spec.query !== undefined) {
    if (!Array.isArray(spec.query) || !spec.query.length || spec.query.length > 20) throw new Error('Invalid query');
    const seen = new Set<string>();
    for (const q of spec.query) {
      fields(q, ['name', 'valueEnv']);
      if (typeof q.name !== 'string' || q.name.length > 64 || !queryParamNameRegex.test(q.name) || seen.has(q.name)
        || typeof q.valueEnv !== 'string' || !/^BBA_INPUT_[A-Z0-9_]{1,50}$/.test(q.valueEnv)) throw new Error('Invalid query reference');
      seen.add(q.name);
    }
  }
  if (spec.body !== undefined) {
    fields(spec.body, ['format', 'valueEnv']);
    if (['GET', 'HEAD'].includes(spec.method) || !['json', 'form', 'text'].includes(spec.body.format)
      || typeof spec.body.valueEnv !== 'string' || !/^BBA_BODY_[A-Z0-9_]{1,50}$/.test(spec.body.valueEnv)) throw new Error('Invalid body reference');
  }
  if (spec.method !== 'GET' || spec.query || spec.body) {
    const rule = scope.requestRules?.find(r =>
      r.origin === url.origin
      && r.method === spec.method
      && (r.path !== undefined ? matchesPathPattern(r.path, url.pathname) : r.pathPrefix !== undefined && matchesPathPrefix(r.pathPrefix, url.pathname)),
    );
    if (!rule || spec.query?.some(q => !rule.queryNames.includes(q.name)) || (spec.body && !rule.bodyFormats.includes(spec.body.format))) throw new Error('Request blocked: method or inputs outside scope');
  }
  return url;
}
