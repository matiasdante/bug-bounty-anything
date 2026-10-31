import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { assertAuthorized, fields, optionalFields, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { validateProjections } from './observations.ts';
import type { Fact, Projection } from './observations.ts';
import { validatePolicy } from './semantic.ts';
import type { Policy, SemanticClass } from './semantic.ts';
import { createSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';
import type { Lang } from './i18n.ts';

export type GraphqlCheckConfig = {
  schemaVersion: 1;
  class: 'graphql-authorization';
  semanticClass?: SemanticClass;
  policyReference: string;
  accounts: [string, string];
  identity: { url: string; fact: string; observe: Projection[] };
  endpointUrl: string;
  query: string;
  operationName?: string;
  variables?: Record<string, string | number | boolean | null>;
  protectedPointer: string;
  subjectPointer?: string | null;
  policy: Policy;
};

const bodyRef = 'BBA_BODY_GRAPHQL_OP';
const scalar = (f: Fact | undefined) => !!f?.meaningful && ['string', 'number'].includes(f.kind);
const equal = (a: Fact | undefined, b: Fact | undefined) => !!a?.meaningful && !!b?.meaningful && a.kind === b.kind && a.sha256 === b.sha256;

function validateGraphqlQuery(query: string): void {
  if (typeof query !== 'string' || query.length < 3 || query.length > 8192 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(query)) {
    throw new Error('Invalid GraphQL query document');
  }
  const stripped = query.replace(/#[^\r\n]*/g, '').replace(/"(?:\\.|[^"\\])*"/g, '""').trim();
  if (/^(?:mutation|subscription)\b/i.test(stripped)) {
    throw new Error('GraphQL authorization check accepts read-only query operations only');
  }
  if (!/^(?:query\b|\{)/.test(stripped)) {
    throw new Error('GraphQL document must start with query or selection set');
  }
}

export function validateGraphqlCheck(value: unknown, scope: Scope, checkTime = true): asserts value is GraphqlCheckConfig {
  validateScope(scope);
  optionalFields(
    value,
    ['schemaVersion', 'class', 'policyReference', 'accounts', 'identity', 'endpointUrl', 'query', 'protectedPointer', 'policy'],
    ['semanticClass', 'operationName', 'variables', 'subjectPointer'],
  );
  if (value.schemaVersion !== 1 || value.class !== 'graphql-authorization'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || !Array.isArray(value.accounts) || value.accounts.length !== 2 || new Set(value.accounts).size !== 2
    || value.accounts.some((n: unknown) => typeof n !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(n))
    || typeof value.endpointUrl !== 'string') {
    throw new Error('Invalid GraphQL authorization check');
  }
  validateGraphqlQuery(value.query);
  if (value.operationName !== undefined && (typeof value.operationName !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(value.operationName))) {
    throw new Error('Invalid GraphQL operationName');
  }
  if (value.variables !== undefined) {
    if (!value.variables || typeof value.variables !== 'object' || Array.isArray(value.variables) || Object.keys(value.variables).length > 32) {
      throw new Error('Invalid GraphQL variables');
    }
    for (const [k, v] of Object.entries(value.variables)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k)
        || !(v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
        throw new Error('GraphQL variables support scalar or null values only');
      }
    }
  }
  fields(value.identity, ['url', 'fact', 'observe']);
  validateProjections(value.identity.observe);
  if (!value.identity.observe.some((p: Projection) => p.name === value.identity.fact)) {
    throw new Error('GraphQL identity fact is not projected');
  }
  const semKind: SemanticClass = value.semanticClass ?? (
    (value.policy as Record<string, unknown>)?.boundary === 'owner-only' ? 'bola'
      : (value.policy as Record<string, unknown>)?.boundary === 'tenant-private' ? 'tenant-isolation'
        : 'bfla'
  );
  validatePolicy(value.policy, semKind);
  validateProjections([{ name: 'protected', pointer: value.protectedPointer }]);
  if (value.policy.boundary === 'owner-only' || value.policy.boundary === 'tenant-private') {
    if (typeof value.subjectPointer !== 'string') throw new Error('Owner and tenant GraphQL policies require subjectPointer');
    validateProjections([{ name: 'subject', pointer: value.subjectPointer }]);
  } else if (value.subjectPointer !== undefined && value.subjectPointer !== null) {
    validateProjections([{ name: 'subject', pointer: value.subjectPointer }]);
  }
  const now = checkTime ? Date.now() : Date.parse(scope.authorization.validFrom);
  const idUrl = assertAuthorized(scope, value.identity.url, now);
  const gqlUrl = assertAuthorized(scope, value.endpointUrl, now);
  if (idUrl.origin !== gqlUrl.origin) throw new Error('GraphQL identity and endpoint URLs must share origin');
  validatePlan(plan(value as GraphqlCheckConfig), scope, checkTime);
  if (scope.limits.maxRequests < 5) throw new Error('GraphQL authorization proof needs five request reservations');
}

function plan(config: GraphqlCheckConfig): Plan {
  const opObserve: Projection[] = [{ name: 'protected', pointer: config.protectedPointer }];
  if (config.policy.boundary === 'owner-only' || config.policy.boundary === 'tenant-private') {
    opObserve.push({
      name: config.policy.boundary === 'owner-only' ? config.policy.ownerFact : config.policy.resourceTenantFact,
      pointer: config.subjectPointer!,
    });
  }
  return {
    schemaVersion: 1,
    steps: [
      { id: 'identity-a', method: 'GET', url: config.identity.url, credentialEnv: config.accounts[0], observe: config.identity.observe },
      { id: 'identity-b', method: 'GET', url: config.identity.url, credentialEnv: config.accounts[1], observe: config.identity.observe },
      { id: 'anonymous-op', method: 'POST', url: config.endpointUrl, credentialEnv: null, body: { format: 'json', valueEnv: bodyRef }, observe: [{ name: 'protected', pointer: config.protectedPointer }] },
      { id: 'owner-op', method: 'POST', url: config.endpointUrl, credentialEnv: config.accounts[0], body: { format: 'json', valueEnv: bodyRef }, observe: opObserve },
      { id: 'probe-op', method: 'POST', url: config.endpointUrl, credentialEnv: config.accounts[1], body: { format: 'json', valueEnv: bodyRef }, observe: opObserve },
    ],
  };
}

function inputs(config: GraphqlCheckConfig, baseEnv: Record<string, string | undefined> = process.env): Record<string, string | undefined> {
  const payload: Record<string, unknown> = { query: config.query };
  if (config.operationName !== undefined) payload.operationName = config.operationName;
  if (config.variables !== undefined) payload.variables = config.variables;
  return {
    ...baseEnv,
    [bodyRef]: JSON.stringify(payload),
  };
}

export function evaluateGraphqlCheck(session: Session, config: GraphqlCheckConfig) {
  validateGraphqlCheck(config, session.scope, false);
  if (digest(session.plan) !== digest(plan(config))) throw new Error('GraphQL check plan changed');
  const response = (id: string) => session.attempts.find(a => a.stepId === id && a.outcome === 'succeeded')?.response;
  const fact = (id: string, fieldName: string) => response(id)?.facts?.find(f => f.name === fieldName);

  let status: 'confirmed' | 'not-reproduced' | 'unresolved' = 'unresolved';
  let reason = 'Required GraphQL identity or operation controls are incomplete.';

  const idA = fact('identity-a', config.identity.fact);
  const idB = fact('identity-b', config.identity.fact);
  if (response('identity-a')?.status !== 200 || response('identity-b')?.status !== 200
    || !scalar(idA) || !scalar(idB) || idA!.kind !== idB!.kind || equal(idA, idB)) {
    reason = 'Two distinct server identities were not established.';
  } else {
    const p = config.policy;
    let roleOrTenantOk = true;
    if (p.boundary === 'role-private') {
      if (fact('identity-a', p.roleFact)?.sha256 !== digest(p.baselineRole)
        || fact('identity-b', p.roleFact)?.sha256 !== digest(p.probeRole)
        || fact('identity-a', p.roleFact)?.kind !== 'string'
        || fact('identity-b', p.roleFact)?.kind !== 'string') {
        roleOrTenantOk = false;
        reason = 'Required privileged and restricted server roles were not established.';
      }
    } else if (p.boundary === 'tenant-private') {
      const ta = fact('identity-a', p.tenantFact), tb = fact('identity-b', p.tenantFact);
      if (!scalar(ta) || !scalar(tb) || ta!.kind !== tb!.kind || equal(ta, tb)) {
        roleOrTenantOk = false;
        reason = 'Distinct server tenants were not established.';
      }
    }

    const anonResp = response('anonymous-op');
    const ownerResp = response('owner-op');
    const probeResp = response('probe-op');
    if (roleOrTenantOk && anonResp && ownerResp && probeResp) {
      const anonFact = fact('anonymous-op', 'protected');
      const anonDenied = [401, 403, 404].includes(anonResp.status) || (anonResp.status === 200 && !anonFact?.meaningful);
      const ownerProtected = fact('owner-op', 'protected');
      const probeProtected = fact('probe-op', 'protected');

      if (!anonDenied) {
        reason = 'Anonymous GraphQL denial (HTTP 401/403 or null/missing data field) was not established.';
      } else if (ownerResp.status !== 200 || !ownerProtected?.meaningful) {
        reason = 'Authorized GraphQL baseline did not return a meaningful protected field.';
      } else if (p.boundary === 'owner-only' && !equal(fact('owner-op', p.ownerFact), idA)) {
        reason = 'GraphQL baseline ownership did not match server identity.';
      } else if (p.boundary === 'tenant-private' && !equal(fact('owner-op', p.resourceTenantFact), fact('identity-a', p.tenantFact))) {
        reason = 'GraphQL baseline tenant did not match server tenant.';
      } else if ([401, 403, 404].includes(probeResp.status) || (probeResp.status === 200 && !probeProtected?.meaningful)) {
        status = 'not-reproduced';
        reason = 'The restricted identity was denied or received null/missing data for the protected GraphQL field.';
      } else if (probeResp.status === 200 && equal(ownerProtected, probeProtected)) {
        const subjectOk = p.boundary === 'owner-only'
          ? equal(fact('probe-op', p.ownerFact), idA)
          : p.boundary === 'tenant-private'
            ? equal(fact('probe-op', p.resourceTenantFact), fact('identity-a', p.tenantFact))
            : true;
        if (subjectOk) {
          status = 'confirmed';
          reason = 'The restricted identity resolved the protected GraphQL field matching the authorized baseline while anonymous access was denied.';
        } else {
          reason = 'Probe GraphQL subject ownership or tenant was not established.';
        }
      } else {
        reason = 'GraphQL probe returned non-matching data; partial exposure remains unproven.';
      }
    }
  }

  return {
    schemaVersion: 1,
    class: config.class,
    status,
    sessionId: session.id,
    scopeDigest: session.scopeDigest,
    configDigest: digest(config),
    evidence: ['identity-a', 'identity-b', 'anonymous-op', 'owner-op', 'probe-op'].map(id => session.id + ':' + id),
    reason,
    limitations: [
      'Only this single read-only GraphQL query operation and JSON pointer were tested.',
      'GraphQL HTTP 200 responses with null/missing protected fields are treated as field-level denials.',
      'Batching, alias amplification, mutations and subscriptions were not executed.',
    ],
  };
}

function report(result: ReturnType<typeof evaluateGraphqlCheck>, config: GraphqlCheckConfig, lang: Lang = 'es'): string {
  if (lang === 'en') {
    return `# BBA — graphql-authorization: ${result.status}\n\nLocal draft for review; not submitted.\n\n`
      + `## What it is\n\nOperation-level GraphQL authorization check on \`${config.endpointUrl}\` (\`${config.protectedPointer}\`) under policy ${config.policyReference}.\n\n`
      + `## Exploitability proof\n\nStatus: **${result.status}**. ${result.reason} Evidence: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
      + `## Remediation\n\nEnforce resolver-level ownership, role or tenant checks before returning \`${config.protectedPointer}\`.\n\n`
      + `## Limitations\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
  }
  return `# BBA — graphql-authorization: ${result.status}\n\nBorrador para revisión; no enviado.\n\n`
    + `## Qué es\n\nComprobación de autorización GraphQL por operación en \`${config.endpointUrl}\` (\`${config.protectedPointer}\`) bajo la regla ${config.policyReference}.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
    + `## Cómo corregirlo\n\nAplicar validación de propietario, rol o tenant en el resolver de GraphQL antes de resolver \`${config.protectedPointer}\`.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}

function save(folder: string, name: string, session: Session, config: GraphqlCheckConfig, lang: Lang = 'es') {
  const result = evaluateGraphqlCheck(session, config);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, config, lang), { flag: 'wx', mode: 0o600 });
  return result;
}

export async function graphqlCheck(folder: string, scope: Scope, config: GraphqlCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateGraphqlCheck(config, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(config));
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
  });
  return save(folder, 'graphql-check', session, config, options.lang);
}

export async function resumeGraphqlCheck(folder: string, scope: Scope, config: GraphqlCheckConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; credentials?: Record<string, string | undefined>; lang?: Lang;
} = {}) {
  validateGraphqlCheck(config, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope)
    || digest(readJson(join(folder, 'config.json'))) !== digest(config)) throw new Error('GraphQL check definition changed');
  if (existsSync(join(folder, 'graphql-resumed.json')) || existsSync(join(folder, 'graphql-resumed.md'))) {
    throw new Error('Resumed GraphQL check result already exists');
  }
  const session = await executeSession(join(folder, 'run'), scope, {
    ...options,
    credentials: inputs(config, options.credentials),
  });
  return save(folder, 'graphql-resumed', session, config, options.lang);
}
