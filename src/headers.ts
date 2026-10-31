import type { Scope } from './scope.ts';

// Values are read from the operator's environment and never become evidence.
// Origin binding also applies when a capture loads a second allowed origin.
export function identifyingHeaders(scope: Scope, origin: string, env: Record<string, string | undefined> = process.env): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const header of scope.requestHeaders ?? []) {
    if (header.origin !== origin) continue;
    const value = env[header.valueEnv];
    if (!value || value.length > 512 || !/^[\x20-\x7e]+$/.test(value)) throw new Error('Missing or invalid identifying header environment variable');
    headers[header.name] = value;
  }
  return headers;
}

export function validateHeaderEnvironment(scope: Scope, env: Record<string, string | undefined> = process.env): void {
  for (const rule of scope.allowed) identifyingHeaders(scope, rule.origin, env);
}
