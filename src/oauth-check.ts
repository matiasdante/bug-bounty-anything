import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { optionalFields, queryParamNameRegex, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';
import type { Lang } from './i18n.ts';

export type OauthCheckConfig = {
  schemaVersion: 1;
  class: 'oauth-flow-conformance';
  policyReference: string;
  authorizeUrl: string;
  clientId: string;
  validRedirectUri: string;
  unapprovedRedirectUri: string;
  state?: string;
  clientIdParam?: string;
  redirectUriParam?: string;
  responseTypeParam?: string;
  stateParam?: string;
  credentialEnv: string | null;
};

const refs = {
  clientId: 'BBA_INPUT_OAUTH_CLIENT_ID',
  validRedirect: 'BBA_INPUT_OAUTH_VALID_REDIRECT',
  unapprovedRedirect: 'BBA_INPUT_OAUTH_UNAPPROVED_REDIRECT',
  responseType: 'BBA_INPUT_OAUTH_RESPONSE_TYPE',
  state: 'BBA_INPUT_OAUTH_STATE',
} as const;

function parseRedirectUri(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 2048 || /[\x00-\x20\\]/.test(raw)) {
    throw new Error('Invalid OAuth redirect URI');
  }
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new Error('Invalid OAuth redirect URI'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
    throw new Error('Invalid OAuth redirect URI');
  }
  return parsed;
}

function queryNamesFor(config: OauthCheckConfig) {
  return {
    clientIdParam: config.clientIdParam ?? 'client_id',
    redirectUriParam: config.redirectUriParam ?? 'redirect_uri',
    responseTypeParam: config.responseTypeParam ?? 'response_type',
    stateParam: config.stateParam ?? 'state',
  };
}

export function validateOauthCheck(value: unknown, scope: Scope, checkTime = true): asserts value is OauthCheckConfig {
  validateScope(scope);
  optionalFields(
    value,
    ['schemaVersion', 'class', 'policyReference', 'authorizeUrl', 'clientId', 'validRedirectUri', 'unapprovedRedirectUri', 'credentialEnv'],
    ['state', 'clientIdParam', 'redirectUriParam', 'responseTypeParam', 'stateParam'],
  );
  if (value.schemaVersion !== 1 || value.class !== 'oauth-flow-conformance'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.authorizeUrl !== 'string'
    || typeof value.clientId !== 'string' || !/^[A-Za-z0-9._~:/@-]{1,128}$/.test(value.clientId)
    || (value.state !== undefined && (typeof value.state !== 'string' || !/^[A-Za-z0-9._~-]{6,128}$/.test(value.state)))
    || (value.credentialEnv !== null && (typeof value.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(value.credentialEnv)))) {
    throw new Error('Invalid OAuth conformance check');
  }
  const validUrl = parseRedirectUri(value.validRedirectUri);
  const unapprovedUrl = parseRedirectUri(value.unapprovedRedirectUri);
  if (validUrl.origin === unapprovedUrl.origin) {
    throw new Error('OAuth valid and unapproved redirect URIs must have distinct origins');
  }
  const names = queryNamesFor(value as OauthCheckConfig);
  const nameList = Object.values(names);
  if (new Set(nameList).size !== nameList.length || nameList.some(n => typeof n !== 'string' || n.length > 64 || !queryParamNameRegex.test(n))) {
    throw new Error('Invalid OAuth query parameter names');
  }
  validatePlan(plan(value as OauthCheckConfig), scope, checkTime);
  if (scope.limits.maxRequests < 2) throw new Error('OAuth conformance proof needs two request reservations');
}

function plan(config: OauthCheckConfig): Plan {
  const names = queryNamesFor(config);
  const buildQuery = (redirectRef: string) => [
    { name: names.clientIdParam, valueEnv: refs.clientId },
    { name: names.redirectUriParam, valueEnv: redirectRef },
    { name: names.responseTypeParam, valueEnv: refs.responseType },
    { name: names.stateParam, valueEnv: refs.state },
  ];
  return {
    schemaVersion: 1,
    steps: [
      { id: 'valid-redirect', method: 'GET', url: config.authorizeUrl, credentialEnv: config.credentialEnv, query: buildQuery(refs.validRedirect) },
      { id: 'unapproved-redirect', method: 'GET', url: config.authorizeUrl, credentialEnv: config.credentialEnv, query: buildQuery(refs.unapprovedRedirect) },
    ],
  };
}

function inputs(config: OauthCheckConfig, baseEnv: Record<string, string | undefined> = process.env): Record<string, string | undefined> {
  return {
    ...baseEnv,
    [refs.clientId]: config.clientId,
    [refs.validRedirect]: config.validRedirectUri,
    [refs.unapprovedRedirect]: config.unapprovedRedirectUri,
    [refs.responseType]: 'code',
    [refs.state]: config.state ?? 'bba-oauth-state',
  };
}

export function evaluateOauthCheck(session: Session, config: OauthCheckConfig) {
  validateOauthCheck(config, session.scope, false);
  if (digest(session.plan) !== digest(plan(config))) throw new Error('OAuth check plan changed');
  const validOrigin = new URL(config.validRedirectUri).origin;
  const unapprovedOrigin = new URL(config.unapprovedRedirectUri).origin;
  const validStep = session.attempts.find(a => a.stepId === 'valid-redirect' && a.outcome === 'succeeded')?.response;
  const probeStep = session.attempts.find(a => a.stepId === 'unapproved-redirect' && a.outcome === 'succeeded')?.response;
  const validBaseline = !!validStep && validStep.status >= 300 && validStep.status < 400 && validStep.redirectOrigin === validOrigin;

  let status: 'confirmed' | 'not-reproduced' | 'unresolved' = 'unresolved';
  let reason = 'Baseline valid OAuth redirect or unapproved redirect probe was incomplete.';
  if (validBaseline && probeStep) {
    if (probeStep.status >= 300 && probeStep.status < 400 && probeStep.redirectOrigin === unapprovedOrigin) {
      status = 'confirmed';
      reason = 'The authorization endpoint redirected to the unapproved redirect_uri origin while the declared valid redirect_uri baseline succeeded.';
    } else if (
      (probeStep.status >= 400 && probeStep.status < 500)
      || probeStep.status === 200
      || (probeStep.status >= 300 && probeStep.status < 400 && probeStep.redirectOrigin === validOrigin)
    ) {
      status = 'not-reproduced';
      reason = 'The authorization endpoint rejected or refused to redirect to the unapproved redirect_uri origin.';
    }
  }
  return {
    schemaVersion: 1,
    class: config.class,
    status,
    sessionId: session.id,
    scopeDigest: session.scopeDigest,
    configDigest: digest(config),
    evidence: ['valid-redirect', 'unapproved-redirect'].map(id => session.id + ':' + id),
    reason,
    limitations: [
      'Only redirect_uri origin enforcement on the declared authorization endpoint and owned client_id was tested.',
      'Redirects were never followed; authorization codes, query strings and fragments in Location headers were never persisted.',
      'PKCE downgrade, token-endpoint replay and cross-account state fixation require additional multi-step flows.',
    ],
  };
}

function report(result: ReturnType<typeof evaluateOauthCheck>, config: OauthCheckConfig, lang: Lang = 'es'): string {
  if (lang === 'en') {
    return `# BBA — oauth-flow-conformance: ${result.status}\n\nLocal draft for review; not submitted.\n\n`
      + `## What it is\n\nOAuth 2.0 \`redirect_uri\` conformance test on \`${config.authorizeUrl}\` under policy ${config.policyReference}.\n\n`
      + `## How it was found\n\nCompared a valid registered redirect URI against an unapproved external redirect URI without following any 3xx redirect.\n\n`
      + `## Exploitability proof\n\nStatus: **${result.status}**. ${result.reason} Evidence: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
      + `## Remediation\n\nEnforce exact byte-for-byte pre-registered \`redirect_uri\` validation before issuing any 3xx authorization response.\n\n`
      + `## Limitations\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
  }
  return `# BBA — oauth-flow-conformance: ${result.status}\n\nBorrador para revisión; no enviado.\n\n`
    + `## Qué es\n\nComprobación de conformidad de \`redirect_uri\` OAuth 2.0 en \`${config.authorizeUrl}\` bajo la regla ${config.policyReference}.\n\n`
    + `## Cómo se encontró\n\nSe comparó el \`redirect_uri\` registrado válido frente a un \`redirect_uri\` externo no aprobado sin seguir redirecciones 3xx.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
    + `## Cómo corregirlo\n\nExigir coincidencia exacta contra la lista blanca pre-registrada de \`redirect_uri\` antes de emitir cualquier respuesta 3xx de autorización.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}

function save(folder: string, name: string, session: Session, config: OauthCheckConfig, lang: Lang = 'es') {
  const result = evaluateOauthCheck(session, config);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, config, lang), { flag: 'wx', mode: 0o600 });
  return result;
}

export async function oauthCheck(folder: string, scope: Scope, config: OauthCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateOauthCheck(config, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(config));
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
    allowRedirectObservation: true,
  });
  return save(folder, 'oauth-check', session, config, options.lang);
}

export async function resumeOauthCheck(folder: string, scope: Scope, config: OauthCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateOauthCheck(config, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope)
    || digest(readJson(join(folder, 'config.json'))) !== digest(config)) throw new Error('OAuth check definition changed');
  if (existsSync(join(folder, 'oauth-resumed.json')) || existsSync(join(folder, 'oauth-resumed.md'))) {
    throw new Error('Resumed OAuth check result already exists');
  }
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
    allowRedirectObservation: true,
  });
  return save(folder, 'oauth-resumed', session, config, options.lang);
}
