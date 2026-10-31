import { SafeError } from './contracts.ts';
import { credentialFor, scopedRequest } from './http.ts';
import { validateHeaderEnvironment } from './headers.ts';
import { validateProjections } from './observations.ts';
import { assertRequestAllowed, fields, optionalFields, validateScope } from './scope.ts';
import type { RequestSpec, Scope } from './scope.ts';
import type { ProgramBudget } from './budget.ts';

export type AuthBootstrapAccount = {
  targetEnv: string;
  url: string;
  request: RequestSpec;
  extract:
    | { from: 'json-pointer'; pointer: string }
    | { from: 'set-cookie'; cookieNames?: string[] };
};

export type AuthBootstrapConfig = {
  schemaVersion: 1;
  accounts: AuthBootstrapAccount[];
};

const arrayIndexRegex = /^(?:0|[1-9]\d{0,6})$/;
const cookieNameRegex = /^[A-Za-z0-9!#$%&'*+.^_`|~:-]{1,128}$/;

function readStringPointer(doc: unknown, pointer: string): string {
  let current: unknown = doc;
  const segments = pointer === '' ? [] : pointer.slice(1).split('/').map(s => s.replace(/~1/g, '/').replace(/~0/g, '~'));
  for (const segment of segments) {
    if (Array.isArray(current)) {
      if (!arrayIndexRegex.test(segment)) throw new SafeError('Auth bootstrap pointer array index is invalid');
      const idx = Number(segment);
      if (idx >= current.length) throw new SafeError('Auth bootstrap pointer not found in login response');
      current = current[idx];
    } else if (current && typeof current === 'object') {
      if (!Object.hasOwn(current, segment)) throw new SafeError('Auth bootstrap pointer not found in login response');
      current = (current as Record<string, unknown>)[segment];
    } else {
      throw new SafeError('Auth bootstrap pointer not found in login response');
    }
  }
  if (typeof current !== 'string' || !current) {
    throw new SafeError('Auth bootstrap JSON pointer did not yield a non-empty string credential');
  }
  return current;
}

function extractCookieHeader(setCookies: string[] | undefined, filterNames?: string[]): string {
  if (!setCookies?.length) throw new SafeError('Auth bootstrap login response contained no Set-Cookie headers');
  const pairs = new Map<string, string>();
  for (const raw of setCookies) {
    const first = raw.split(';', 1)[0]?.trim() ?? '';
    const eq = first.indexOf('=');
    if (eq < 1) continue;
    const cName = first.slice(0, eq);
    const cVal = first.slice(eq + 1);
    if (!cookieNameRegex.test(cName)) continue;
    if (filterNames && !filterNames.includes(cName)) continue;
    pairs.set(cName, `${cName}=${cVal}`);
  }
  if (filterNames) {
    for (const reqName of filterNames) {
      if (!pairs.has(reqName)) throw new SafeError(`Auth bootstrap missing expected cookie '${reqName}'`);
    }
  }
  if (!pairs.size) throw new SafeError('Auth bootstrap could not extract any valid cookie');
  return [...pairs.values()].join('; ');
}

export function validateAuthBootstrap(value: unknown, scope: Scope, checkTime = true): asserts value is AuthBootstrapConfig {
  validateScope(scope);
  fields(value, ['schemaVersion', 'accounts']);
  if (value.schemaVersion !== 1 || !Array.isArray(value.accounts) || !value.accounts.length || value.accounts.length > 6) {
    throw new Error('Invalid auth bootstrap config');
  }
  const seenTargets = new Set<string>();
  const now = checkTime ? Date.now() : Date.parse(scope.authorization.validFrom);
  for (const acc of value.accounts) {
    fields(acc, ['targetEnv', 'url', 'request', 'extract']);
    if (typeof acc.targetEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(acc.targetEnv) || seenTargets.has(acc.targetEnv)) {
      throw new Error('Invalid or duplicate auth bootstrap targetEnv');
    }
    seenTargets.add(acc.targetEnv);
    assertRequestAllowed(scope, acc.url, acc.request, now);
    if (!acc.extract || typeof acc.extract !== 'object' || Array.isArray(acc.extract)) {
      throw new Error('Invalid auth bootstrap extract rule');
    }
    const ext = acc.extract as Record<string, unknown>;
    if (ext.from === 'json-pointer') {
      fields(ext, ['from', 'pointer']);
      if (typeof ext.pointer !== 'string' || ext.pointer.length < 2) throw new Error('Invalid auth bootstrap JSON pointer');
      validateProjections([{ name: 'bootstrap', pointer: ext.pointer }]);
    } else if (ext.from === 'set-cookie') {
      if (!acc.targetEnv.startsWith('BBA_COOKIE_')) {
        throw new Error('set-cookie extraction requires a BBA_COOKIE_* targetEnv');
      }
      optionalFields(ext, ['from'], ['cookieNames']);
      if (ext.cookieNames !== undefined) {
        if (!Array.isArray(ext.cookieNames) || !ext.cookieNames.length || ext.cookieNames.length > 10
          || new Set(ext.cookieNames).size !== ext.cookieNames.length
          || ext.cookieNames.some((n: unknown) => typeof n !== 'string' || !cookieNameRegex.test(n))) {
          throw new Error('Invalid auth bootstrap cookieNames');
        }
      }
    } else {
      throw new Error('Unsupported auth bootstrap extraction mode');
    }
  }
}

export async function bootstrapCredentials(
  scope: Scope,
  config: AuthBootstrapConfig,
  options: {
    signal?: AbortSignal;
    budget?: ProgramBudget;
    environment?: Record<string, string | undefined>;
  } = {},
): Promise<{ credentials: Record<string, string | undefined>; requestsSent: number }> {
  validateAuthBootstrap(config, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  const env: Record<string, string | undefined> = { ...(options.environment ?? process.env) };
  validateHeaderEnvironment(scope, env);
  if (config.accounts.length > scope.limits.maxRequests) {
    throw new SafeError('Auth bootstrap exceeds scope maxRequests');
  }

  let requestsSent = 0;
  for (let i = 0; i < config.accounts.length; i++) {
    const acc = config.accounts[i];
    const ref = `auth-bootstrap:${i + 1}:${acc.targetEnv}`;
    let reserved = false;
    try {
      if (options.budget) {
        await options.budget.beforeRequest(ref, options.signal);
        reserved = true;
      }
      requestsSent++;
      const res = await scopedRequest(scope, acc.url, {
        request: acc.request,
        environment: env,
        signal: options.signal,
        remainingMs: options.budget?.remainingMs(),
      });
      let acquired: string;
      if (acc.extract.from === 'json-pointer') {
        if (![200, 201].includes(res.status)) {
          throw new SafeError(`Auth bootstrap failed with HTTP ${res.status} for ${acc.targetEnv}`);
        }
        let parsed: unknown;
        try { parsed = JSON.parse(res.body.toString('utf8')); }
        catch { throw new SafeError(`Auth bootstrap response for ${acc.targetEnv} was not valid JSON`); }
        acquired = readStringPointer(parsed, acc.extract.pointer);
      } else {
        if (![200, 201, 204, 302, 303].includes(res.status)) {
          throw new SafeError(`Auth bootstrap failed with HTTP ${res.status} for ${acc.targetEnv}`);
        }
        acquired = extractCookieHeader(res.setCookies, acc.extract.cookieNames);
      }
      credentialFor(acc.targetEnv, acquired);
      env[acc.targetEnv] = acquired;
    } finally {
      if (reserved && options.budget) options.budget.complete(ref);
    }
  }
  return { credentials: env, requestsSent };
}

