import { writeFileSync } from 'node:fs';
import { readJson } from './session.ts';
import { digest } from './contracts.ts';
import { fields, optionalFields, strictUrl } from './scope.ts';
import pkg from '../package.json' with { type: 'json' };

type Parameter = { location: string; name: string };
type Endpoint = {
  id: string; method: string; origin: string | null; path: string;
  pathKind: 'literal' | 'inferred-template' | 'declared-template';
  basis: 'observed' | 'declared'; parameters: Parameter[];
  authentication: 'credential-present' | 'not-established' | 'declared-required' | 'declared-optional';
  status: number | null; locator: string; ordinal: number | null;
};
export type Surface = {
  schemaVersion: 1; toolVersion: '0.3.0'; producerVersion?: string; sourceDigest: string;
  format: 'har' | 'openapi' | 'rea'; reaEvidenceId: string | null;
  entries: Endpoint[]; skipped?: number; limitations: string[];
};
const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'];
function record(value: any): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid import object');
  return value;
}
function list(value: any): any[] {
  if (!Array.isArray(value) || value.length > 5000) throw new Error('Invalid import collection');
  return value;
}
function name(value: any): string {
  if (typeof value !== 'string' || value.length > 64 || !/^[A-Za-z_][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_.-]*\]){0,4}$/.test(value)) {
    throw new Error('Unsupported parameter name');
  }
  return value;
}
const surfaceSegmentRegex = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-F]{2})*$/;
const forbiddenSurfaceEscapeRegex = /%(?:0[0-9A-F]|1[0-9A-F]|2E|2F|5C|7F)/i;

function safePath(path: string, declared = false): { path: string; pathKind: Endpoint['pathKind'] } {
  if (path.length > 2048 || !path.startsWith('/') || path.includes('//') || forbiddenSurfaceEscapeRegex.test(path)
    || path.split('/').some(s => s === '.' || s === '..')) throw new Error('Unsupported path representation');
  let inferred = false;
  const result = path.split('/').map((segment, index) => {
    if (index === 0) return '';
    if (declared && /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(segment)) return segment;
    if (/[{}]/.test(segment)) throw new Error('Invalid path template');
    if (!surfaceSegmentRegex.test(segment)) throw new Error('Unsupported path representation');
    if (/^\d+$/.test(segment) || /^[a-f0-9-]{32,}$/i.test(segment) || segment.length > 40) {
      inferred = true;
      return '{opaque}';
    }
    return segment;
  }).join('/');
  return { path: result, pathKind: inferred ? 'inferred-template' : declared && path.includes('{') ? 'declared-template' : 'literal' };
}
function urlParts(value: any) {
  if (typeof value !== 'string' || value.length > 8192 || /[\\\x00-\x20]/.test(value)) throw new Error('Invalid captured URL');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Invalid captured URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Unsupported captured URL');
  // Reject normalization ambiguity before extracting a surface location.
  const rawPath = value.replace(/^https?:\/\/[^/?#]+/i, '').split(/[?#]/)[0] || '/';
  if (rawPath !== url.pathname) throw new Error('Non-canonical captured path');
  return { url, ...safePath(url.pathname) };
}
function endpoint(input: Omit<Endpoint, 'id'>): Endpoint {
  input.parameters = [...new Map(input.parameters.map(p => [p.location + ':' + p.name, p])).values()]
    .sort((a, b) => (a.location + a.name).localeCompare(b.location + b.name));
  return { id: 'sha256:' + digest(input), ...input };
}
function harEntry(entry: any, ordinal: number, locator: string): Endpoint {
  const request = record(record(entry).request), response = record(entry.response);
  if (!methods.includes(request.method)) throw new Error('Unsupported captured method');
  const { url, path, pathKind } = urlParts(request.url);
  if (!Number.isInteger(response.status) || response.status < 0 || response.status > 599) throw new Error('Invalid captured status');
  const parameters: Parameter[] = [];
  for (const key of url.searchParams.keys()) parameters.push({ location: 'query', name: name(key) });
  for (const item of list(request.queryString ?? [])) parameters.push({ location: 'query', name: name(record(item).name) });
  const headers = list(request.headers ?? []);
  const credentials = headers.some(h => ['authorization', 'cookie'].includes(String(record(h).name).toLowerCase()))
    || list(request.cookies ?? []).length > 0;
  return endpoint({ method: request.method, origin: url.origin, path, pathKind, basis: 'observed', parameters,
    authentication: credentials ? 'credential-present' : 'not-established', status: response.status || null, locator, ordinal });
}

function openapi(doc: any): Endpoint[] {
  record(doc);
  const swagger2 = doc.swagger === '2.0';
  if (!swagger2 && (typeof doc.openapi !== 'string' || !/^3\.[01]\.\d+$/.test(doc.openapi))) throw new Error('Only Swagger 2.0 and OpenAPI 3.0/3.1 JSON are supported');
  const swaggerServers = (): { url: string }[] => {
    if (doc.basePath !== undefined && (typeof doc.basePath !== 'string' || !doc.basePath.startsWith('/'))) throw new Error('Invalid Swagger basePath');
    const prefix = (doc.basePath ?? '').replace(/\/$/, '');
    if (prefix) safePath(prefix, true);
    if (doc.host === undefined) return [{ url: prefix || '/' }];
    if (typeof doc.host !== 'string' || !/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(doc.host)) throw new Error('Invalid Swagger host');
    const schemes = doc.schemes === undefined ? [] : list(doc.schemes);
    if (schemes.some(s => s !== 'https' && s !== 'http') || new Set(schemes).size !== schemes.length) throw new Error('Invalid Swagger schemes');
    if (!schemes.length) return [{ url: prefix || '/' }]; // The spec's retrieval scheme is unknown offline.
    return schemes.map(scheme => ({ url: `${scheme}://${doc.host}${prefix || '/'}` }));
  };
  const defaultServers = swagger2 ? swaggerServers() : null;
  const resolve = (item: any): any => {
    let current = record(item); const seen = new Set();
    while (Object.hasOwn(current, '$ref')) {
      const ref = current.$ref;
      if (typeof ref !== 'string' || !ref.startsWith('#/') || seen.has(ref) || seen.size >= 20) throw new Error('Unsupported or cyclic OpenAPI reference');
      // Sibling semantics vary between Reference Objects and Path Items. Do
      // not silently discard potentially meaningful siblings in this subset.
      if (Object.keys(current).length !== 1) throw new Error('Reference siblings are unsupported');
      seen.add(ref);
      let target = doc;
      for (const piece of ref.slice(2).split('/')) {
        const key = piece.replace(/~1/g, '/').replace(/~0/g, '~');
        if (!target || !Object.hasOwn(target, key)) throw new Error('Missing local OpenAPI reference');
        target = target[key];
      }
      current = record(target);
    }
    return current;
  };
  const result: Endpoint[] = [];
  for (const [path, raw] of Object.entries(record(doc.paths))) {
    if (path.startsWith('x-')) continue;
    const item = resolve(raw);
    const pathPointer = '/paths/' + path.replace(/~/g, '~0').replace(/\//g, '~1');
    for (const method of methods) {
      const key = method.toLowerCase(); if (!Object.hasOwn(item, key)) continue;
      const operation = record(item[key]);
      const servers = swagger2 ? defaultServers : operation.servers ?? item.servers ?? doc.servers ?? [{ url: '/' }];
      if (!list(servers).length) throw new Error('Empty OpenAPI server list is unsupported');
      const parameters = new Map<string, Parameter>();
      for (const rawParam of [...list(item.parameters ?? []), ...list(operation.parameters ?? [])]) {
        const p = resolve(rawParam);
        if (!(swagger2 ? ['query', 'path', 'header', 'body', 'formData'] : ['query', 'path', 'header', 'cookie']).includes(p.in)) throw new Error('Invalid parameter location');
        const param = { location: p.in, name: name(p.name) }; parameters.set(param.location + ':' + param.name, param);
      }
      const security = operation.security ?? doc.security;
      if (security !== undefined) list(security).forEach(record);
      const authentication = security === undefined ? 'not-established'
        : security.length === 0 || security.some((s: Record<string, unknown>) => Object.keys(s).length === 0) ? 'declared-optional' : 'declared-required';
      for (const server of servers) {
        const serverUrl = record(server).url;
        if (typeof serverUrl !== 'string') throw new Error('Invalid OpenAPI server');
        let origin: string | null = null, prefix = '';
        if (serverUrl.includes('{')) throw new Error('Server variables require explicit resolution');
        if (serverUrl.startsWith('/') && !serverUrl.startsWith('//')) prefix = serverUrl.replace(/\/$/, '');
        else {
          const parts = urlParts(serverUrl);
          if (parts.url.search || parts.url.hash) throw new Error('Invalid OpenAPI server URL');
          origin = parts.url.origin; prefix = parts.url.pathname.replace(/\/$/, '');
        }
        const projected = safePath(prefix + path, true);
        result.push(endpoint({ method, origin, ...projected, basis: 'declared', parameters: [...parameters.values()],
          authentication, status: null, locator: pathPointer + '/' + key, ordinal: null }));
        if (result.length > 5000) throw new Error('Surface entry limit exceeded');
      }
    }
  }
  return result;
}

export function importSurface(input: unknown, format: Surface['format'], options: { quarantine?: boolean } = {}): Surface {
  const doc = record(input);
  let entries: Endpoint[], reaEvidenceId: string | null = null, skipped = 0;
  const limitations = ['Offline projection only; no URL was fetched and no authorization was granted.',
    'Headers, bodies, query values, examples and descriptions are omitted. Names and literal path segments can still be sensitive; review before sharing.',
    'Numeric, UUID-like and long path segments are replaced by opaque templates. Templates are not handler identity or executable URLs.',
    'Credential presence does not establish a valid session, role, tenant or successful authentication.'];
  if (format === 'har') {
    const log = record(doc.log);
    if (log.version !== '1.2') throw new Error('Only HAR 1.2 is supported');
    entries = [];
    for (const [i, e] of list(log.entries).entries()) {
      try {
        entries.push(harEntry(e, i, '/log/entries/' + i));
      } catch (error) {
        if (!options.quarantine) throw error;
        skipped++;
      }
    }
    if (skipped > 0) limitations.push(`Quarantine mode skipped ${skipped} unrepresentable HAR entries.`);
    limitations.push('Coverage is limited to supplied records, not the complete application or capture lifecycle.');
  } else if (format === 'openapi') {
    entries = openapi(doc);
    limitations.push('Declared operations are not observed execution. Relative servers have unknown origin.',
      'JSON subset only: Swagger 2.0 host/basePath/schemes or OpenAPI 3.x servers, parameters and security declarations. No schema validation, YAML, external refs, server variables, callbacks or body-property inventory.');
  } else if (format === 'rea') {
    if (doc.operation !== 'inspect_web_network_capture' || typeof doc.evidence_id !== 'string'
      || !/^[A-Za-z0-9:_.-]{1,200}$/.test(doc.evidence_id)) throw new Error('Expected complete REA capture Evidence');
    const normalized = record(doc.normalized_result);
    if (normalized.format !== 'har' || !Array.isArray(normalized.records)
      || normalized.records.length !== normalized.total_records) throw new Error('Complete REA HAR records are required');
    reaEvidenceId = doc.evidence_id;
    const ordinals = new Set();
    entries = [];
    for (const [idx, r] of list(normalized.records).entries()) {
      record(r);
      if (!Number.isInteger(r.ordinal) || r.ordinal < 0 || ordinals.has(r.ordinal)) throw new Error('Invalid REA ordinal');
      ordinals.add(r.ordinal);
      try {
        entries.push(harEntry(r.reported, r.ordinal, '/normalized_result/records/' + idx + '/reported'));
      } catch (error) {
        if (!options.quarantine) throw error;
        skipped++;
      }
    }
    if (skipped > 0) limitations.push(`Quarantine mode skipped ${skipped} unrepresentable REA records.`);
    limitations.push('REA Evidence ID is an attributed reference, not independently authenticated by BBA. Imported source limitations and redactions may hide fields; original Evidence must accompany review.');
  } else throw new Error('Unsupported surface format');
  return {
    schemaVersion: 1,
    toolVersion: '0.3.0',
    producerVersion: pkg.version,
    sourceDigest: digest(input),
    format,
    reaEvidenceId,
    entries,
    ...(options.quarantine ? { skipped } : {}),
    limitations,
  };
}

export function projectCapturedHar(records: unknown[]): { surface: Surface; keptIndices: number[]; unrepresentable: number } {
  const keptRecords: unknown[] = [];
  const keptIndices: number[] = [];
  const projectedEntries: Endpoint[] = [];
  let unrepresentable = 0;
  for (let i = 0; i < records.length; i++) {
    try {
      const ordinal = keptRecords.length;
      projectedEntries.push(harEntry(records[i], ordinal, '/log/entries/' + ordinal));
      keptRecords.push(records[i]);
      keptIndices.push(i);
    } catch {
      unrepresentable++;
    }
  }
  const sourceDoc = { log: { version: '1.2', entries: keptRecords } };
  const surface: Surface = {
    schemaVersion: 1,
    toolVersion: '0.3.0',
    producerVersion: pkg.version,
    sourceDigest: digest(sourceDoc),
    format: 'har',
    reaEvidenceId: null,
    entries: projectedEntries,
    limitations: [
      'Offline projection only; no URL was fetched and no authorization was granted.',
      'Headers, bodies, query values, examples and descriptions are omitted. Names and literal path segments can still be sensitive; review before sharing.',
      'Numeric, UUID-like and long path segments are replaced by opaque templates. Templates are not handler identity or executable URLs.',
      'Credential presence does not establish a valid session, role, tenant or successful authentication.',
      'Coverage is limited to supplied records, not the complete application or capture lifecycle.',
    ],
  };
  return { surface, keptIndices, unrepresentable };
}

export function importSurfaceFile(path: string, format: Surface['format'], output: string, options: { quarantine?: boolean } = {}): Surface {
  const surface = importSurface(readJson(path), format, options);
  writeFileSync(output, JSON.stringify({ surface, sha256: digest(surface) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return surface;
}
export function surfaceSummary(surface: Surface) {
  const identities = new Set(surface.entries.map(e => [e.method, e.origin, e.path].join(' ')));
  return { format: surface.format, records: surface.entries.length, endpointCandidates: identities.size,
    observed: surface.entries.filter(e => e.basis === 'observed').length,
    declared: surface.entries.filter(e => e.basis === 'declared').length,
    ...(surface.skipped !== undefined ? { skipped: surface.skipped } : {}),
    reaEvidenceId: surface.reaEvidenceId };
}

export function validateSurfaceBundle(value: unknown): asserts value is { surface: Surface; sha256: string } {
  fields(value, ['surface', 'sha256']);
  const s = value.surface;
  optionalFields(s, ['schemaVersion', 'toolVersion', 'sourceDigest', 'format', 'reaEvidenceId', 'entries', 'limitations'], ['producerVersion', 'skipped']);
  if (s.schemaVersion !== 1 || s.toolVersion !== '0.3.0' || !['har', 'openapi', 'rea'].includes(s.format)
    || (s.producerVersion !== undefined && (typeof s.producerVersion !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s.producerVersion)))
    || (s.skipped !== undefined && (!Number.isSafeInteger(s.skipped) || s.skipped < 0))
    || typeof s.sourceDigest !== 'string' || !/^[a-f0-9]{64}$/.test(s.sourceDigest)
    || (s.reaEvidenceId !== null && (typeof s.reaEvidenceId !== 'string' || !/^[A-Za-z0-9:_.-]{1,200}$/.test(s.reaEvidenceId)))
    || !Array.isArray(s.entries) || s.entries.length > 5000 || !Array.isArray(s.limitations)
    || s.limitations.some((x: unknown) => typeof x !== 'string' || x.length > 2000) || value.sha256 !== digest(s)) throw new Error('Invalid surface bundle');
  for (const e of s.entries) {
    fields(e, ['id', 'method', 'origin', 'path', 'pathKind', 'basis', 'parameters', 'authentication', 'status', 'locator', 'ordinal']);
    if (!methods.includes(e.method) || !['literal', 'inferred-template', 'declared-template'].includes(e.pathKind)
      || !['observed', 'declared'].includes(e.basis) || !['credential-present', 'not-established', 'declared-required', 'declared-optional'].includes(e.authentication)
      || typeof e.path !== 'string' || typeof e.locator !== 'string' || e.locator.length > 2048
      || (e.status !== null && (!Number.isInteger(e.status) || e.status < 0 || e.status > 599))
      || (e.ordinal !== null && (!Number.isSafeInteger(e.ordinal) || e.ordinal < 0))
      || !Array.isArray(e.parameters) || e.parameters.length > 100) throw new Error('Invalid surface entry');
    if (e.origin !== null && (typeof e.origin !== 'string' || strictUrl(e.origin + '/').origin !== e.origin)) throw new Error('Invalid surface origin');
    safePath(e.path, true);
    if (e.pathKind === 'literal' && e.path.includes('{')) throw new Error('Invalid literal surface path');
    for (const p of e.parameters) {
      fields(p, ['location', 'name']); name(p.name);
      if (!['query', 'header', 'path', 'cookie', 'body', 'formData'].includes(p.location)) throw new Error('Invalid parameter location');
    }
    const { id, ...entry } = e;
    if (id !== 'sha256:' + digest(entry)) throw new Error('Surface entry integrity mismatch');
  }
}
