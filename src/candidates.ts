import { closeSync, fstatSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { digest } from './contracts.ts';
import { matchesScopeRule, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import pkg from '../package.json' with { type: 'json' };

export type Candidate = {
  id: string; source: 'zap' | 'nuclei' | 'subfinder'; kind: 'endpoint' | 'host';
  ruleId: string | null; title: string; reportedSeverity: 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  method: string | null; origin: string | null; path: string | null; hasQuery: boolean;
  scopeStatus: 'in-scope' | 'excluded' | 'out-of-scope' | 'unparseable';
  status: 'unvalidated'; locator: string;
};
export type CandidateSet = {
  schemaVersion: 1; toolVersion: '0.7.0'; producerVersion?: string; format: Candidate['source']; sourceDigest: string; scopeDigest: string;
  candidates: Candidate[]; duplicates: number; limitations: string[];
};

const MAX_BYTES = 2 * 1024 * 1024, MAX_RECORDS = 5000;
const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'];
const severities = ['info', 'low', 'medium', 'high', 'critical'];

function readText(path: string): string {
  const fd = openSync(path, 'r');
  try {
    if (fstatSync(fd).size > MAX_BYTES) throw new Error('Input file is too large');
    return readFileSync(fd, 'utf8');
  } finally { closeSync(fd); }
}
// Scanner output is hostile text: keep it short and free of control characters.
const clean = (value: unknown, max: number) =>
  typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').trim().slice(0, max) : '';
const rule = (value: unknown) => typeof value === 'string' || typeof value === 'number'
  ? (/^[A-Za-z0-9_.:-]{1,100}$/.test(String(value)) ? String(value) : null) : null;
const array = (value: unknown): any[] => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_RECORDS) throw new Error('Invalid import collection');
  return value;
};
function lines(content: string): any[] {
  const rows = content.split('\n').map(l => l.trim()).filter(Boolean);
  if (rows.length > MAX_RECORDS) throw new Error('Too many records');
  return rows.map(row => { try { return JSON.parse(row); } catch { throw new Error('Invalid JSON line'); } });
}
function severity(value: unknown): Candidate['reportedSeverity'] {
  if (typeof value === 'string' && severities.includes(value.toLowerCase())) return value.toLowerCase() as Candidate['reportedSeverity'];
  // ZAP riskcode: 0 informational .. 3 high. Anything else, including empty values, is unknown.
  return /^[0-3]$/.test(String(value)) ? (['info', 'low', 'medium', 'high'] as const)[Number(value)] : 'unknown';
}

// Offline comparison with the supplied scope: exact origin and path, exclusions win.
function locate(scope: Scope, value: unknown) {
  let url: URL;
  try {
    if (typeof value !== 'string' || value.length > 8192) throw new Error();
    url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
  } catch { return { origin: null, path: null, hasQuery: false, scopeStatus: 'unparseable' as const }; }
  const match = (r: Scope['allowed'][number]) => matchesScopeRule(r, url);
  const scopeStatus = scope.excluded.some(match) ? 'excluded' as const : scope.allowed.some(match) ? 'in-scope' as const : 'out-of-scope' as const;
  return { origin: url.origin, path: url.pathname.slice(0, 2048), hasQuery: url.search !== '', scopeStatus };
}
function hostStatus(scope: Scope, host: string) {
  // Exclusions are exact paths, so they cannot exclude a host that also has allowed paths.
  const named = (rules: Scope['allowed']) => rules.some(r => new URL(r.origin).hostname === host);
  return named(scope.allowed) ? 'in-scope' as const : named(scope.excluded) ? 'excluded' as const : 'out-of-scope' as const;
}

export function importCandidates(content: string, format: Candidate['source'], scope: unknown): CandidateSet {
  validateScope(scope);
  const found: Omit<Candidate, 'id'>[] = [];
  const endpoint = (source: Candidate['source'], ruleId: unknown, title: unknown, sev: unknown, method: unknown, url: unknown, locator: string) =>
    found.push({ source, kind: 'endpoint', ruleId: rule(ruleId), title: clean(title, 200), reportedSeverity: severity(sev),
      method: typeof method === 'string' && methods.includes(method.toUpperCase()) ? method.toUpperCase() : null,
      ...locate(scope, url), status: 'unvalidated', locator });
  if (format === 'zap') {
    let doc: any;
    try { doc = JSON.parse(content); } catch { throw new Error('Invalid JSON input'); }
    array(doc?.site).forEach((site: any, s: number) => array(site?.alerts).forEach((alert: any, a: number) =>
      array(alert?.instances).forEach((instance: any, i: number) =>
        endpoint('zap', alert?.pluginid ?? alert?.alertRef, alert?.name ?? alert?.alert, alert?.riskcode, instance?.method, instance?.uri,
          `/site/${s}/alerts/${a}/instances/${i}`))));
  } else if (format === 'nuclei') {
    lines(content).forEach((row, i) => endpoint('nuclei', row?.['template-id'], row?.info?.name, row?.info?.severity, null,
      row?.['matched-at'] ?? row?.host, `line ${i + 1}`));
  } else if (format === 'subfinder') {
    lines(content).forEach((row, i) => {
      const host = typeof row?.host === 'string' ? row.host.toLowerCase() : '';
      const valid = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(host);
      found.push({ source: 'subfinder', kind: 'host', ruleId: null, title: valid ? host : '', reportedSeverity: 'unknown', method: null,
        origin: null, path: null, hasQuery: false, scopeStatus: valid ? hostStatus(scope, host) : 'unparseable', status: 'unvalidated', locator: `line ${i + 1}` });
    });
  } else throw new Error('Unsupported candidate format');
  const unique = new Map<string, Candidate>();
  for (const item of found) {
    const { locator: _locator, ...identity } = item; // Position in the file is not identity.
    const id = 'sha256:' + digest(identity);
    if (!unique.has(id)) unique.set(id, { id, ...item });
  }
  return { schemaVersion: 1, toolVersion: '0.7.0', producerVersion: pkg.version, format, sourceDigest: digest(content), scopeDigest: digest(scope),
    candidates: [...unique.values()], duplicates: found.length - unique.size, limitations: [
      'Imported claims only: no scanner was run and no URL was contacted. Every candidate is unvalidated; none is a confirmed finding.',
      'Descriptions, evidence, requests, responses and extracted values were dropped. Titles and paths can still be sensitive; review before sharing.',
      'Scope status compares origin and exact path with the supplied scope.json. It is not the owner\'s authorization, and an in-scope candidate was not tested by BBA.',
      'Severity is the scanner\'s label, not an assessment by BBA. Subdomain candidates are never resolved or contacted.',
      'Formats follow each tool\'s documented JSON output; they were not checked against a live scanner run.',
    ] };
}

export function importCandidatesFile(path: string, format: Candidate['source'], scope: unknown, output: string): CandidateSet {
  const set = importCandidates(readText(path), format, scope);
  writeFileSync(output, JSON.stringify({ candidates: set, sha256: digest(set) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return set;
}
export function candidateSummary(set: CandidateSet) {
  const count = (key: Candidate['scopeStatus']) => set.candidates.filter(c => c.scopeStatus === key).length;
  return { format: set.format, candidates: set.candidates.length, duplicates: set.duplicates, inScope: count('in-scope'),
    excluded: count('excluded'), outOfScope: count('out-of-scope'), unparseable: count('unparseable'), validated: 0 };
}
