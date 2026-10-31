import { mkdirSync, openSync, writeSync, fsyncSync, closeSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { digest } from './contracts.ts';
import { credentialFor, scopedRequest } from './http.ts';
import { assertAuthorized, fields, strictUrl, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { validateHeaderEnvironment } from './headers.ts';
import type { ProgramBudget } from './budget.ts';
import { randomUUID } from 'node:crypto';
import { sealArtifact } from './artifacts.ts';

export type HuntConfig = {
  schemaVersion: 1; seed: string; identityUrl: string; identityField: string;
  ownerField: string; privateField: string;
  accounts: [string, string]; boundary: 'owner-only';
};
export function validateHunt(value: unknown, scope: Scope): asserts value is HuntConfig {
  fields(value, ['schemaVersion', 'seed', 'identityUrl', 'identityField', 'ownerField', 'privateField', 'accounts', 'boundary']);
  if (value.schemaVersion !== 1 || value.boundary !== 'owner-only') throw new Error('Unsupported hunt contract');
  for (const field of [value.identityField, value.ownerField, value.privateField]) {
    if (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(field)) throw new Error('Invalid hunt field');
  }
  if (value.ownerField === value.privateField) throw new Error('Private field must differ from owner field');
  if (!Array.isArray(value.accounts) || value.accounts.length !== 2 || new Set(value.accounts).size !== 2
    || value.accounts.some(n => typeof n !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(n))) throw new Error('Two controlled accounts are required');
  const seed = assertAuthorized(scope, value.seed), identity = assertAuthorized(scope, value.identityUrl);
  if (seed.origin !== identity.origin) throw new Error('Hunt identity and seed must share origin');
}
type Trace = { id: number; url: string; account: string | null; status: number; sha256: string; bytes: number; at: string };
export type HuntFinding = { url: string; status: 'confirmed' | 'not-reproduced' | 'unresolved'; reason: string; evidence: number[] };

// Deliberately simple discovery: quoted HTML hrefs, bounded by body size and
// exact scope. No JavaScript or page instructions are executed by this workflow.
export function discoverLinks(body: string, base: string, scope: Scope): string[] {
  const result = new Set<string>();
  for (const match of body.matchAll(/\bhref\s*=\s*["']([^"']{1,2048})["']/gi)) {
    try {
      const url = new URL(match[1], base).href;
      if (strictUrl(url).origin !== new URL(base).origin) continue;
      assertAuthorized(scope, url); result.add(url);
    } catch { /* Discovery is not authorization. Unsupported links stay unvisited. */ }
  }
  return [...result];
}

export async function hunt(folder: string, scope: Scope, config: HuntConfig, options: {
  credentials?: Record<string, string | undefined>; signal?: AbortSignal;
  budget?: ProgramBudget;
} = {}) {
  validateScope(scope); validateHunt(config, scope);
  if (scope.budgetId && !options.budget) throw new Error('Shared program budget runtime is required');
  validateHeaderEnvironment(scope, options.credentials);
  const values = config.accounts.map(n => (options.credentials ?? process.env)[n]);
  if (values.some(v => !v) || values[0] === values[1]) throw new Error('Distinct controlled credentials are required');
  const credentials = values.map((v, i) => credentialFor(config.accounts[i], v!));
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  const journal = openSync(join(folder, 'requests.jsonl'), 'wx', 0o600);
  const append = (event: unknown) => { writeSync(journal, JSON.stringify(event) + '\n'); fsyncSync(journal); };
  const started = Date.now(), deadline = started + scope.limits.maxDurationMs;
  const huntId = randomUUID();
  const traces: Trace[] = [], findings: HuntFinding[] = [];
  let used = 0, lastEnd = 0, stopped: string | null = null;
  const get = async (url: string, account: number | null) => {
    if (options.signal?.aborted) throw new Error('cancelled');
    assertAuthorized(scope, url);
    if (used >= scope.limits.maxRequests) throw new Error('budget-exhausted');
    const wait = Math.max(0, lastEnd + scope.limits.minIntervalMs - Date.now());
    if (Date.now() + wait >= deadline) throw new Error('deadline');
    if (wait) await delay(wait, undefined, { signal: options.signal });
    if (options.signal?.aborted) throw new Error('cancelled');
    if (Date.now() >= deadline) throw new Error('deadline');
    assertAuthorized(scope, url);
    const id = ++used, label = account === null ? null : config.accounts[account];
    append({ event: 'reserved', id, url, account: label, at: new Date().toISOString() });
    const reference = huntId + ':' + id;
    if (options.budget) await options.budget.beforeRequest(reference, options.signal);
    let response: Awaited<ReturnType<typeof scopedRequest>>;
    try { response = await scopedRequest(scope, url, { ...(account === null ? {} : credentials[account]), signal: options.signal, remainingMs: Math.min(deadline - Date.now(), options.budget?.remainingMs() ?? Infinity), environment: options.credentials }); }
    finally { options.budget?.complete(reference); }
    lastEnd = Date.now();
    const trace: Trace = { id, url, account: label, status: response.status, sha256: createHash('sha256').update(response.body).digest('hex'), bytes: response.body.length, at: new Date().toISOString() };
    traces.push(trace); append({ event: 'response', ...trace });
    if ((response.status >= 300 && response.status < 400) || response.status === 429 || response.status >= 500) throw new Error('unsafe-response');
    return { ...response, trace };
  };
  const json = (r: Awaited<ReturnType<typeof get>>) => {
    if (r.status !== 200 || !/^application\/json\b/i.test(r.contentType)) return null;
    try { const v = JSON.parse(r.body.toString('utf8')); return v && typeof v === 'object' && !Array.isArray(v) ? v : null; } catch { return null; }
  };
  const scalar = (v: unknown) => typeof v === 'string' && v.length > 0 || typeof v === 'number' && Number.isFinite(v);
  const surface: { url: string; discoveredBy: number }[] = [];
  append({ event: 'start', version: 1, scopeDigest: digest(scope), configDigest: digest(config), config, scope });
  try {
    const identities = [await get(config.identityUrl, 0), await get(config.identityUrl, 1)];
    const ids = identities.map(r => json(r)?.[config.identityField]);
    if (!ids.every(scalar) || ids[0] === ids[1]) throw new Error('identity-not-established');
    const identityProof = identities.map((r, i) => ({ evidence: r.trace.id, account: config.accounts[i], identityDigest: digest(ids[i]) }));
    append({ event: 'identity-proof', identities: identityProof });
    const queue: { url: string; account: number | null }[] = [
      { url: config.seed, account: 0 }, { url: config.seed, account: 1 },
    ];
    const visited = new Set<string>();
    while (queue.length) {
      const item = queue.shift()!, key = item.account + ':' + item.url;
      if (visited.has(key)) continue; visited.add(key);
      const ownerResponse = await get(item.url, item.account);
      if (/^text\/html\b/i.test(ownerResponse.contentType) && ownerResponse.status === 200) {
        for (const url of discoverLinks(ownerResponse.body.toString('utf8'), item.url, scope)) {
          surface.push({ url, discoveredBy: ownerResponse.trace.id });
          if (url !== config.identityUrl) queue.push({ url, account: item.account });
        }
        continue;
      }
      const data = json(ownerResponse), account = item.account!;
      if (!data || data[config.ownerField] !== ids[account] || !Object.hasOwn(data, config.privateField)
        || !scalar(data[config.privateField])) continue;
      const finding: HuntFinding = { url: item.url, status: 'unresolved', reason: 'Control or probe incomplete.', evidence: [identities[0].trace.id, identities[1].trace.id, ownerResponse.trace.id] };
      findings.push(finding);
      const control = await get(item.url, null); finding.evidence.push(control.trace.id);
      const probe = await get(item.url, 1 - account); finding.evidence.push(probe.trace.id);
      const probeData = json(probe);
      if (![401, 403, 404].includes(control.status)) finding.reason = 'Anonymous boundary not established; public data is not a finding.';
      else if ([403, 404].includes(probe.status)) { finding.status = 'not-reproduced'; finding.reason = 'Other controlled account was denied.'; }
      else if (probeData && probeData[config.ownerField] === ids[account]
        && Object.hasOwn(probeData, config.privateField) && probeData[config.privateField] === data[config.privateField]) {
        finding.status = 'confirmed'; finding.reason = 'Distinct server-identified account received the owner-only private field matching the owner baseline.';
        append({ event: 'boundary-proof', url: item.url, ownerEvidence: ownerResponse.trace.id, probeEvidence: probe.trace.id,
          ownerField: config.ownerField, privateField: config.privateField, ownerDigest: digest(ids[account]), privateValueDigest: digest(data[config.privateField]) });
      } else finding.reason = 'No matching protected field established; session failure and filtered responses remain inconclusive.';
      append({ event: 'finding', ...finding });
      if (finding.status === 'confirmed') break; // Minimal proof: do not keep reading private resources.
    }
  } catch (error) {
    // Persist fixed codes only, never an exception string carrying target data.
    const code = error instanceof Error ? error.message : '';
    stopped = options.signal?.aborted ? 'cancelled' : ['cancelled', 'budget-exhausted', 'deadline', 'unsafe-response', 'identity-not-established'].includes(code) ? code : 'execution-failed';
  } finally {
    try { append({ event: 'finish', stopped, requests: used }); } finally { closeSync(journal); }
  }
  const result = { schemaVersion: 1, id: huntId, scopeDigest: digest(scope), configDigest: digest(config), requests: used, stopped, surface, findings,
    limitations: ['Read-only owner-only BOLA workflow; rule and controlled-account ownership are supplied by the operator.',
      'HTML href discovery only; no JavaScript execution, forms, injection, role inference or general vulnerability coverage.',
      'Redacted field-equality proof, HTTP metadata and digests are retained. Original values and credentials are not retained.',
      'No resume or automatic retries for hunts; requests.jsonl retains durable reservations after a crash. Review before starting a new hunt.'] };
  writeFileSync(join(folder, 'hunt.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2), { flag: 'wx', mode: 0o600 });
  const lines = findings.map((f, i) => `### ${i + 1}. ${f.status}: lectura entre cuentas\n\nRecurso: \`${f.url}\`.\n\n${f.reason}\n\nEvidencia: ${f.evidence.join(', ')} en requests.jsonl.\n`);
  writeFileSync(join(folder, 'report.md'), `# BBA — reporte preparado para revisión\n\nClase: BOLA / CWE-639. Detención: ${stopped ?? 'ninguna'}. Requests: ${used}.\n\n`
    + `## Regla y precondiciones\n\nEl operador declara acceso exclusivo del propietario, dos cuentas de prueba sin permisos compartidos y campos \`${config.ownerField}\` / \`${config.privateField}\` con esa semántica. Debe verificarlo contra las reglas del servicio antes de enviar.\n\n`
    + `## Reproducción\n\n1. Usá dos cuentas de prueba sin permisos compartidos, indicadas por ${config.accounts.join(' y ')}; no publiques sus credenciales.\n2. GET ${config.identityUrl} como cada cuenta: comprobá identidades distintas en ${config.identityField}.\n3. Seguí enlaces desde ${config.seed} para obtener un recurso propio; no enumeres datos de terceros.\n4. GET al recurso como propietario, sin sesión y como la otra cuenta.\n5. Compará ${config.ownerField} y el campo protegido ${config.privateField}; consultá las referencias de evidencia siguientes.\n\n`
    + lines.join('\n') + `\n## Impacto y remediación\n\nSolo los casos confirmed demuestran lectura del campo de prueba entre las cuentas bajo la regla declarada. Aplicar autorización por recurso antes de devolver datos. No se probó escritura ni acceso masivo. No se asigna severidad de producción automáticamente.\n\n## Pendientes antes del envío\n\nRevisar alcance vigente, regla owner-only, duplicados, severidad e instrucciones del programa. Este borrador no fue enviado.\n\n`
    + result.limitations.map(l => '- ' + l).join('\n'), { flag: 'wx', mode: 0o600 });
  sealArtifact(folder, { kind: 'hunt', id: huntId, scopeDigest: digest(scope), configDigest: digest(config) });
  return result;
}
