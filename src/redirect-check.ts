import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { fields, queryParamNameRegex, strictUrl, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';
import type { Lang } from './i18n.ts';

export type RedirectCheckConfig = {
  schemaVersion: 1;
  class: 'open-redirect';
  policyReference: string;
  url: string;
  parameter: string;
  relativeControlTarget: string;
  externalProbeTarget: string;
  credentialEnv: string | null;
};

const refs = ['BBA_INPUT_REDIRECT_CONTROL', 'BBA_INPUT_REDIRECT_PROBE'] as const;

export function validateRedirectCheck(value: unknown, scope: Scope, checkTime = true): asserts value is RedirectCheckConfig {
  validateScope(scope);
  fields(value, ['schemaVersion', 'class', 'policyReference', 'url', 'parameter', 'relativeControlTarget', 'externalProbeTarget', 'credentialEnv']);
  if (value.schemaVersion !== 1 || value.class !== 'open-redirect'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.url !== 'string'
    || typeof value.parameter !== 'string' || value.parameter.length > 64 || !queryParamNameRegex.test(value.parameter)
    || typeof value.relativeControlTarget !== 'string' || !value.relativeControlTarget.startsWith('/') || value.relativeControlTarget.startsWith('//')
    || value.relativeControlTarget.length > 512 || /[\x00-\x20\\]/.test(value.relativeControlTarget)
    || typeof value.externalProbeTarget !== 'string' || value.externalProbeTarget.length > 1024 || /[\x00-\x20\\]/.test(value.externalProbeTarget)
    || (value.credentialEnv !== null && (typeof value.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(value.credentialEnv)))) {
    throw new Error('Invalid redirect check');
  }
  const baseUrl = strictUrl(value.url);
  let externalUrl: URL;
  try { externalUrl = new URL(value.externalProbeTarget); } catch { throw new Error('Invalid external probe target'); }
  if (!['http:', 'https:'].includes(externalUrl.protocol) || externalUrl.username || externalUrl.password || externalUrl.origin === baseUrl.origin) {
    throw new Error('External probe target must be a distinct valid http/https origin without credentials');
  }
  validatePlan(plan(value as RedirectCheckConfig), scope, checkTime);
  if (scope.limits.maxRequests < 2) throw new Error('Open-redirect proof needs two request reservations');
}

function plan(config: RedirectCheckConfig): Plan {
  return {
    schemaVersion: 1,
    steps: [
      { id: 'relative-control', method: 'GET', url: config.url, credentialEnv: config.credentialEnv, query: [{ name: config.parameter, valueEnv: refs[0] }] },
      { id: 'external-probe', method: 'GET', url: config.url, credentialEnv: config.credentialEnv, query: [{ name: config.parameter, valueEnv: refs[1] }] },
    ],
  };
}

function inputs(config: RedirectCheckConfig, baseEnv: Record<string, string | undefined> = process.env): Record<string, string | undefined> {
  return {
    ...baseEnv,
    [refs[0]]: config.relativeControlTarget,
    [refs[1]]: config.externalProbeTarget,
  };
}

export function evaluateRedirectCheck(session: Session, config: RedirectCheckConfig) {
  validateRedirectCheck(config, session.scope, false);
  if (digest(session.plan) !== digest(plan(config))) throw new Error('Redirect check plan changed');
  const expectedExternalOrigin = new URL(config.externalProbeTarget).origin;
  const control = session.attempts.find(a => a.stepId === 'relative-control' && a.outcome === 'succeeded')?.response;
  const probe = session.attempts.find(a => a.stepId === 'external-probe' && a.outcome === 'succeeded')?.response;
  const baselineOk = !!control && control.status >= 300 && control.status < 400 && control.redirectClass === 'same-origin';

  let status: 'confirmed' | 'not-reproduced' | 'unresolved' = 'unresolved';
  let reason = 'Same-origin redirect baseline or external redirect probe was incomplete.';
  if (baselineOk && probe) {
    if (probe.status >= 300 && probe.status < 400 && probe.redirectClass === 'external' && probe.redirectOrigin === expectedExternalOrigin) {
      status = 'confirmed';
      reason = 'The endpoint issued a 3xx redirect to the external untrusted origin while the relative control redirected within the same origin.';
    } else if (
      [200, 400, 401, 403, 404, 422].includes(probe.status)
      || (probe.status >= 300 && probe.status < 400 && probe.redirectClass === 'same-origin')
    ) {
      status = 'not-reproduced';
      reason = 'The external redirect input was rejected or rewritten to a same-origin destination.';
    }
  }
  return {
    schemaVersion: 1,
    class: config.class,
    status,
    sessionId: session.id,
    scopeDigest: session.scopeDigest,
    configDigest: digest(config),
    evidence: ['relative-control', 'external-probe'].map(id => session.id + ':' + id),
    reason,
    limitations: [
      'Only HTTP 3xx Location header redirection on this parameter was tested; client-side DOM/meta refresh redirects are not covered.',
      'BBA never follows 3xx redirects; only the sanitized target origin and classification are recorded.',
    ],
  };
}

function report(result: ReturnType<typeof evaluateRedirectCheck>, config: RedirectCheckConfig, lang: Lang = 'es'): string {
  if (lang === 'en') {
    return `# BBA — open-redirect: ${result.status}\n\nLocal draft for review; not submitted.\n\n`
      + `## What it is\n\nOpen-redirect comparison on parameter \`${config.parameter}\` of \`${config.url}\` under policy ${config.policyReference}.\n\n`
      + `## How it was found\n\nCompared a relative same-origin redirect control against an external origin probe without following redirects.\n\n`
      + `## Exploitability proof\n\nStatus: **${result.status}**. ${result.reason} Evidence: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
      + `## Remediation\n\nAllow only relative paths (rejecting protocol-relative \`//\`) or an explicit allowlist of trusted origins.\n\n`
      + `## Limitations\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
  }
  return `# BBA — open-redirect: ${result.status}\n\nBorrador para revisión; no enviado.\n\n`
    + `## Qué es\n\nComparación de redirección abierta en el parámetro \`${config.parameter}\` de \`${config.url}\` bajo la regla ${config.policyReference}.\n\n`
    + `## Cómo se encontró\n\nSe comparó un control relativo del mismo origen frente a un destino externo sin seguir ninguna redirección.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
    + `## Cómo corregirlo\n\nPermitir únicamente rutas relativas locales (rechazando \`//\`) o validar contra una lista cerrada de orígenes confiables.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}

function save(folder: string, name: string, session: Session, config: RedirectCheckConfig, lang: Lang = 'es') {
  const result = evaluateRedirectCheck(session, config);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, config, lang), { flag: 'wx', mode: 0o600 });
  return result;
}

export async function redirectCheck(folder: string, scope: Scope, config: RedirectCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateRedirectCheck(config, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(config));
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
    allowRedirectObservation: true,
  });
  return save(folder, 'redirect-check', session, config, options.lang);
}

export async function resumeRedirectCheck(folder: string, scope: Scope, config: RedirectCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateRedirectCheck(config, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope)
    || digest(readJson(join(folder, 'config.json'))) !== digest(config)) throw new Error('Redirect check definition changed');
  if (existsSync(join(folder, 'redirect-resumed.json')) || existsSync(join(folder, 'redirect-resumed.md'))) {
    throw new Error('Resumed redirect check result already exists');
  }
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
    allowRedirectObservation: true,
  });
  return save(folder, 'redirect-resumed', session, config, options.lang);
}
