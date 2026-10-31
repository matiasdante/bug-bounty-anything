import { createHash, createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonical, digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { credentialFor } from './http.ts';
import { fields, optionalFields, assertRequestAllowed, requestSpec, validatePlan, validateScope } from './scope.ts';
import type { Plan, RequestSpec, Scope } from './scope.ts';
import { validateProjections } from './observations.ts';
import { createSession, inspectSession, readJson, validateSession } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';

export type JwtIntegrityConfig = { schemaVersion: 1; policyReference: string; boundary: 'jwt-signature-integrity';
  url: string; request: RequestSpec; credentialEnv: string; proofPointer: string;
  mutation: { claim: string; mode: 'add-canary' | 'replace'; valueEnv?: string } };
export type JwtIntegrityResult = { schemaVersion: 1; sessionId: string; scopeDigest: string; configDigest: string;
  status: 'confirmed' | 'not-reproduced' | 'unresolved'; reason: string; evidence: string[];
  limitation: string[] };

export function validateJwtIntegrity(value: unknown, scope: Scope, checkTime = true): asserts value is JwtIntegrityConfig {
  validateScope(scope);
  fields(value, ['schemaVersion', 'policyReference', 'boundary', 'url', 'request', 'credentialEnv', 'proofPointer', 'mutation']);
  if (value.schemaVersion !== 1 || value.boundary !== 'jwt-signature-integrity'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.credentialEnv !== 'string' || !/^BBA_TOKEN_[A-Z0-9_]{1,50}$/.test(value.credentialEnv)
    || typeof value.url !== 'string') throw new Error('Invalid JWT integrity contract');
  assertRequestAllowed(scope, value.url, value.request, checkTime ? Date.now() : Date.parse(scope.authorization.validFrom));
  validateProjections([{ name: 'proof', pointer: value.proofPointer }]);
  optionalFields(value.mutation, ['claim', 'mode'], ['valueEnv']);
  if (typeof value.mutation.claim !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value.mutation.claim)
    || !['add-canary', 'replace'].includes(value.mutation.mode)
    || (value.mutation.mode === 'add-canary' && value.mutation.valueEnv !== undefined)
    || (value.mutation.mode === 'replace' && (typeof value.mutation.valueEnv !== 'string'
      || !/^BBA_INPUT_[A-Z0-9_]{1,50}$/.test(value.mutation.valueEnv)))) throw new Error('Invalid JWT mutation');
}

function decodePart(encoded: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]{1,8192}$/.test(encoded)) throw new Error('Invalid compact JWT');
  let parsed: unknown;
  try {
    const raw = Buffer.from(encoded, 'base64url');
    if (raw.toString('base64url') !== encoded || raw.length > 4096) throw new Error();
    parsed = JSON.parse(raw.toString('utf8'));
  } catch { throw new Error('Invalid compact JWT'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid compact JWT');
  return parsed as Record<string, unknown>;
}

export function mutateOwnedJwt(token: string, config: JwtIntegrityConfig, environment: Record<string, string | undefined> = process.env): string {
  credentialFor(config.credentialEnv, token);
  const parts = token.split('.');
  if (parts.length !== 3 || !/^[A-Za-z0-9_-]{4,8192}$/.test(parts[2])) throw new Error('Expected signed compact JWT');
  const header = decodePart(parts[0]), payload = decodePart(parts[1]);
  if (typeof header.alg !== 'string' || !header.alg || header.alg.toLowerCase() === 'none') throw new Error('Expected signed compact JWT');
  if (config.mutation.mode === 'add-canary') {
    if (Object.hasOwn(payload, config.mutation.claim)) throw new Error('Canary claim already exists');
    payload[config.mutation.claim] = createHmac('sha256', token).update(digest(config)).digest('hex').slice(0, 24);
  } else {
    if (!Object.hasOwn(payload, config.mutation.claim)) throw new Error('Claim to replace is absent');
    const replacement = environment[config.mutation.valueEnv!];
    if (replacement === undefined || replacement.length < 1 || Buffer.byteLength(replacement) > 512
      || replacement === payload[config.mutation.claim]) throw new Error('Missing or unchanged controlled claim value');
    payload[config.mutation.claim] = replacement;
  }
  const altered = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const result = `${parts[0]}.${altered}.${parts[2]}`;
  if (result.length > 4096 || result === token) throw new Error('Invalid derived JWT length');
  return result;
}

export function jwtPlan(config: JwtIntegrityConfig): Plan {
  const base = { ...requestSpec(config.request), url: config.url, observe: [{ name: 'proof', pointer: config.proofPointer }] };
  return { schemaVersion: 1, steps: [
    { ...base, id: 'anonymous', credentialEnv: null },
    { ...base, id: 'valid-before', credentialEnv: config.credentialEnv },
    { ...base, id: 'altered-signature', credentialEnv: 'BBA_TOKEN_JWT_DERIVED' },
    { ...base, id: 'valid-after', credentialEnv: config.credentialEnv },
  ] };
}

export function evaluateJwtIntegrity(session: Session, config: JwtIntegrityConfig): JwtIntegrityResult {
  validateSession(session);
  validateJwtIntegrity(config, session.scope, false);
  const expected = jwtPlan(config);
  if (canonical(expected) !== canonical(session.plan)) throw new Error('JWT check plan changed');
  const result: JwtIntegrityResult = { schemaVersion: 1, sessionId: session.id, scopeDigest: session.scopeDigest,
    configDigest: digest(config), status: 'unresolved', reason: 'Required controls are incomplete.',
    evidence: expected.steps.map(s => `${session.id}:${s.id}`),
    limitation: ['This establishes token integrity only for the controlled account and recorded request.',
      'A denial applies only to this mutation; other JWT flaws remain untested.',
      'Response values, original tokens and altered tokens are not retained. Low-entropy fact hashes may be guessed.',
      'The authorization policy and controlled-account ownership are operator assertions.'] };
  const responses = expected.steps.map(s => session.attempts.find(a => a.stepId === s.id && a.outcome === 'succeeded')?.response);
  const [anonymous, before, altered, after] = responses;
  if (!anonymous || !before || !altered || !after) return result;
  if (![401, 403, 404].includes(anonymous.status)) { result.reason = 'Anonymous denial was not established.'; return result; }
  const facts = [before, altered, after].map(r => r.facts?.find(f => f.name === 'proof'));
  if (before.status !== 200 || after.status !== 200 || !facts[0]?.meaningful || !facts[2]?.meaningful
    || facts[0].sha256 !== facts[2].sha256 || facts[0].kind !== facts[2].kind) {
    result.reason = 'Stable protected response under the valid owned token was not established.'; return result;
  }
  if ([401, 403, 404].includes(altered.status)) {
    result.status = 'not-reproduced'; result.reason = 'The changed JWT was denied while the original token remained valid.'; return result;
  }
  if (altered.status !== 200 || !facts[1]?.meaningful || facts[1].kind !== facts[0].kind
    || facts[1].sha256 !== facts[0].sha256) {
    result.reason = 'The altered token did not produce the same protected fact; impact remains unproven.'; return result;
  }
  result.status = 'confirmed'; result.reason = 'A JWT with changed claims and its original signature received the same protected fact as the valid controlled token; anonymous access was denied.';
  return result;
}

export function jwtMarkdown(result: JwtIntegrityResult, config: JwtIntegrityConfig): string {
  return `# BBA — integridad JWT (${result.status})\n\n` +
    `Activo: \`${config.url}\`. Política: ${config.policyReference}. Borrador para revisión; no enviado.\n\n` +
    `## Hipótesis y resultado\n\nUn JWT firmado de una cuenta propia debe rechazarse si cambia su payload sin volver a firmarlo. ${result.reason}\n\n` +
    `## Reproducción acotada\n\n1. Preparar una cuenta propia, un JWT firmado vigente y un request inocuo cuya respuesta tenga el hecho \`${config.proofPointer}\`.\n` +
    `2. Enviar el mismo request anónimo, con el JWT válido, con el JWT alterado sin cambiar la firma y otra vez con el JWT válido.\n` +
    `3. Comparar los estados y el digest de ese hecho. Conservar los checkpoints SQLite y los IDs de evidencia: ${result.evidence.map(id => '\`' + id + '\`').join(', ')}.\n\n` +
    `## Impacto, severidad y corrección\n\n` + (result.status === 'confirmed'
      ? 'La ruta aceptó un JWT con payload modificado y firma inválida para la cuenta controlada. Verificar la firma criptográfica y el algoritmo esperado antes de usar cualquier claim para autenticar o autorizar. No se probó acceso a otras identidades ni conjuntos de datos.\n\n'
      : 'El impacto sobre otras identidades y rutas no está demostrado.\n\n') +
    'La severidad requiere evaluar la sensibilidad del hecho observado, los privilegios de la cuenta de prueba y las reglas del programa; no se infiere del estado HTTP ni de una estimación de registros.\n\n' +
    `## Límites\n\n${result.limitation.map(line => '- ' + line).join('\n')}\n`;
}

function tokenBinding(token: string, salt: string): string {
  return createHash('sha256').update(salt).update('\0').update(token).digest('hex');
}

export async function jwtIntegrityCheck(folder: string, scope: Scope, config: JwtIntegrityConfig, options: {
  signal?: AbortSignal; budget?: ProgramBudget; environment?: Record<string, string | undefined>; resume?: boolean;
} = {}): Promise<JwtIntegrityResult> {
  validateJwtIntegrity(config, scope);
  const env = options.environment ?? process.env, token = env[config.credentialEnv];
  if (!token) throw new Error('Missing controlled JWT environment variable');
  const derived = mutateOwnedJwt(token, config, env);
  const plan = jwtPlan(config); validatePlan(plan, scope);
  const credentials = { ...env, BBA_TOKEN_JWT_DERIVED: derived };
  const manifestPath = join(folder, 'jwt-check.json');
  if (options.resume) {
    const manifest = readJson(manifestPath);
    fields(manifest, ['schemaVersion', 'scopeDigest', 'configDigest', 'salt', 'tokenBinding', 'derivedBinding']);
    if (manifest.schemaVersion !== 1 || manifest.scopeDigest !== digest(scope) || manifest.configDigest !== digest(config)
      || typeof manifest.salt !== 'string' || !/^[a-f0-9]{32}$/.test(manifest.salt)
      || manifest.tokenBinding !== tokenBinding(token, manifest.salt)
      || manifest.derivedBinding !== tokenBinding(derived, manifest.salt)) throw new Error('JWT check inputs changed');
  } else {
    mkdirSync(dirname(folder), { recursive: true });
    mkdirSync(folder);
    const salt = randomBytes(16).toString('hex');
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, scopeDigest: digest(scope), configDigest: digest(config), salt,
      tokenBinding: tokenBinding(token, salt), derivedBinding: tokenBinding(derived, salt) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    createSession(join(folder, 'run'), scope, plan);
  }
  const state = await executeSession(join(folder, 'run'), scope, { credentials, signal: options.signal, budget: options.budget });
  const result = evaluateJwtIntegrity(state, config);
  if (state.status === 'completed') {
    const resultPath = join(folder, 'result.json');
    if (existsSync(resultPath)) {
      const saved = readJson(resultPath);
      fields(saved, ['result', 'sha256']);
      if (saved.sha256 !== digest(result) || canonical(saved.result) !== canonical(result)) throw new Error('JWT result integrity mismatch');
    } else writeFileSync(resultPath, JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    const reportPath = join(folder, 'report.md'), report = jwtMarkdown(result, config);
    if (existsSync(reportPath)) {
      if (readFileSync(reportPath, 'utf8') !== report) throw new Error('JWT report integrity mismatch');
    } else writeFileSync(reportPath, report, { flag: 'wx', mode: 0o600 });
  }
  return result;
}

export function evaluateJwtIntegrityFile(folder: string, configPath: string, output: string): JwtIntegrityResult {
  const session = inspectSession(folder), config = readJson(configPath);
  validateJwtIntegrity(config, session.scope, false);
  const result = evaluateJwtIntegrity(session, config);
  writeFileSync(output, output.endsWith('.md') ? jwtMarkdown(result, config)
    : JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return result;
}
