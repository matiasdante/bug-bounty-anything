import { createServer } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { digest } from './contracts.ts';
import { checkClasses } from './checks.ts';
import { runLabCase } from './cases.ts';
import { executeSession } from './execution.ts';
import { startRoleLab } from './role-lab.ts';
import { validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, exportSession } from './session.ts';

type Group = 'detection' | 'inconclusive' | 'scope' | 'secrets' | 'recovery';
type Outcome = { actual: string; requests: number };
type Case = { id: string; group: Group; expected: string; run: () => Promise<Outcome> };
export type CaseResult = { id: string; group: Group; expected: string; actual: string; passed: boolean; requests: number; ms: number };
export type Report = {
  schemaVersion: 1; toolVersion: '0.9.0'; frozenDigest: string; node: string; cases: CaseResult[];
  metrics: {
    cases: number; passed: number; requests: number; ms: number;
    detections: number; omissions: number; falsePositives: number; unresolvedAsExpected: number;
    scopeViolations: number; secretOccurrences: number; repeatedRequests: number;
  };
  limitations: string[];
};

// ---- helpers: a counting HTTP server and loopback scopes -------------------------------------
async function counting(handler: (req: IncomingMessage, hit: number) => [number, Record<string, string>, string]) {
  const hits: string[] = []; let connections = 0;
  const server = createServer((req, res) => {
    hits.push(req.url ?? '');
    const [status, headers, body] = handler(req, hits.length);
    res.writeHead(status, headers); res.end(body);
  });
  server.on('connection', () => { connections++; });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  return { origin: `http://127.0.0.1:${port}`, port, hits, connections: () => connections,
    close: () => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }) };
}
const window = (from = -1000, to = 600000) => ({ reference: 'BBA frozen evaluation', validFrom: new Date(Date.now() + from).toISOString(), validUntil: new Date(Date.now() + to).toISOString() });
const limits = (maxRequests: number) => ({ maxRequests, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 });
const plan = (origin: string, paths: string[], env: (string | null)[] = []): Plan => ({ schemaVersion: 1,
  steps: paths.map((p, i) => ({ id: 's' + (i + 1), method: 'GET', url: origin + p, credentialEnv: env[i] ?? null })) });
const ok = (body = 'ok'): [number, Record<string, string>, string] => [200, { 'Content-Type': 'text/plain' }, body];
async function temp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'bba-eval-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
const rejected = (scope: Scope, p: Plan) => { try { validateScope(scope); validatePlan(p, scope); return false; } catch { return true; } };
async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await files(path)); else out.push(path);
  }
  return out;
}

// ---- the frozen set ---------------------------------------------------------------------------
const cases: Case[] = [
  ...checkClasses.flatMap((kind): Case[] => [
    { id: `detection/${kind}-vulnerable`, group: 'detection', expected: 'needs-validation', run: async () => {
      const e = await runLabCase(kind, 'vulnerable'); return { actual: e.findings[0].status, requests: 3 }; } },
    { id: `detection/${kind}-fixed`, group: 'detection', expected: kind === 'property-exposure' ? 'unresolved' : 'not-reproduced', run: async () => {
      const e = await runLabCase(kind, 'fixed'); return { actual: e.findings[0].status, requests: 3 }; } },
    { id: `inconclusive/${kind}-budget-exhausted`, group: 'inconclusive', expected: 'unresolved', run: async () => {
      const e = await runLabCase(kind, 'vulnerable', 2); return { actual: e.findings[0].status, requests: 2 }; } },
  ]),
  { id: 'scope/other-origin-rejected', group: 'scope', expected: 'rejected, 0 requests', run: async () => {
    const s = await counting(() => ok()); const o = await counting(() => ok());
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/a'] }], excluded: [], limits: limits(5) };
      const blocked = rejected(scope, plan(o.origin, ['/a']));
      return { actual: `${blocked ? 'rejected' : 'accepted'}, ${s.hits.length + o.hits.length} requests`, requests: s.hits.length + o.hits.length };
    } finally { await s.close(); await o.close(); } } },
  { id: 'scope/excluded-path-wins', group: 'scope', expected: 'rejected, 0 requests', run: async () => {
    const s = await counting(() => ok());
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/a', '/b'] }],
        excluded: [{ origin: s.origin, paths: ['/b'] }], limits: limits(5) };
      const blocked = rejected(scope, plan(s.origin, ['/a', '/b']));
      return { actual: `${blocked ? 'rejected' : 'accepted'}, ${s.hits.length} requests`, requests: s.hits.length };
    } finally { await s.close(); } } },
  { id: 'scope/expired-authorization-rejected', group: 'scope', expected: 'rejected, 0 requests', run: async () => {
    const s = await counting(() => ok());
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(-4000, -2000), allowed: [{ origin: s.origin, paths: ['/a'] }], excluded: [], limits: limits(5) };
      const blocked = rejected(scope, plan(s.origin, ['/a']));
      return { actual: `${blocked ? 'rejected' : 'accepted'}, ${s.hits.length} requests`, requests: s.hits.length };
    } finally { await s.close(); } } },
  { id: 'scope/private-address-in-public-mode', group: 'scope', expected: 'stopped:address-blocked, 0 connections', run: async () => {
    const s = await counting(() => ok());
    try {
      const origin = s.origin.replace('http://', 'https://');
      const scope: Scope = { schemaVersion: 1, mode: 'public-https', authorization: window(), allowed: [{ origin, paths: ['/a'] }], excluded: [], limits: limits(5) };
      return await temp(async dir => {
        const p = plan(origin, ['/a']); createSession(join(dir, 'run'), scope, p);
        const state = await executeSession(join(dir, 'run'), scope);
        return { actual: `${state.status}:${state.stopReason}, ${s.connections()} connections`, requests: s.connections() };
      });
    } finally { await s.close(); } } },
  { id: 'scope/redirect-not-followed', group: 'scope', expected: 'stopped:redirect, 1 requests', run: async () => {
    const s = await counting(req => req.url === '/a' ? [302, { Location: '/b' }, ''] : ok());
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/a', '/b'] }], excluded: [], limits: limits(5) };
      return await temp(async dir => {
        createSession(join(dir, 'run'), scope, plan(s.origin, ['/a', '/b']));
        const state = await executeSession(join(dir, 'run'), scope);
        return { actual: `${state.status}:${state.stopReason}, ${s.hits.length} requests`, requests: s.hits.length };
      });
    } finally { await s.close(); } } },
  { id: 'scope/budget-respected', group: 'scope', expected: 'stopped:budget-exhausted, 1 requests', run: async () => {
    const s = await counting(() => ok());
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/a', '/b', '/c'] }], excluded: [], limits: limits(1) };
      return await temp(async dir => {
        createSession(join(dir, 'run'), scope, plan(s.origin, ['/a', '/b', '/c']));
        const state = await executeSession(join(dir, 'run'), scope);
        return { actual: `${state.status}:${state.stopReason}, ${s.hits.length} requests`, requests: s.hits.length };
      });
    } finally { await s.close(); } } },
  { id: 'secrets/bearer-not-persisted', group: 'secrets', expected: '0 occurrences', run: async () => {
    const lab = await startRoleLab('vulnerable');
    try {
      return await temp(async dir => {
        const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: lab.origin, paths: ['/admin/users'] }], excluded: [], limits: limits(3) };
        const p = plan(lab.origin, ['/admin/users', '/admin/users', '/admin/users'], [null, 'BBA_TOKEN_ADMIN', 'BBA_TOKEN_USER']);
        createSession(join(dir, 'run'), scope, p);
        await executeSession(join(dir, 'run'), scope, { credentials: { BBA_TOKEN_ADMIN: lab.credentials.admin, BBA_TOKEN_USER: lab.credentials.user } });
        exportSession(join(dir, 'run'), join(dir, 'export.json'), 'json'); exportSession(join(dir, 'run'), join(dir, 'report.md'), 'markdown');
        const found = await occurrences(dir, [lab.credentials.admin, lab.credentials.user]);
        return { actual: `${found} occurrences`, requests: 3 };
      });
    } finally { await lab.close(); } } },
  { id: 'secrets/cookie-not-persisted', group: 'secrets', expected: '0 occurrences', run: async () => {
    const cookie = 'sid=' + randomBytes(16).toString('hex');
    const s = await counting(req => req.headers.cookie === cookie ? ok('session') : [401, {}, '']);
    try {
      return await temp(async dir => {
        const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/me'] }], excluded: [], limits: limits(2) };
        createSession(join(dir, 'run'), scope, plan(s.origin, ['/me'], ['BBA_COOKIE_ME']));
        const state = await executeSession(join(dir, 'run'), scope, { credentials: { BBA_COOKIE_ME: cookie } });
        exportSession(join(dir, 'run'), join(dir, 'export.json'), 'json');
        const found = await occurrences(dir, [cookie.slice(4)]);
        return { actual: `${found} occurrences${state.status === 'completed' ? '' : ' (run did not complete)'}`, requests: s.hits.length };
      });
    } finally { await s.close(); } } },
  { id: 'recovery/resume-repeats-nothing', group: 'recovery', expected: 'paused then resumed, 0 repeated', run: async () => {
    const controller = new AbortController();
    const s = await counting((req, hit) => { if (hit === 2) controller.abort(); return ok(req.url); });
    try {
      const scope: Scope = { schemaVersion: 1, mode: 'loopback-lab', authorization: window(), allowed: [{ origin: s.origin, paths: ['/1', '/2', '/3'] }], excluded: [], limits: limits(5) };
      return await temp(async dir => {
        createSession(join(dir, 'run'), scope, plan(s.origin, ['/1', '/2', '/3']));
        const first = await executeSession(join(dir, 'run'), scope, { signal: controller.signal });
        const second = await executeSession(join(dir, 'run'), scope);
        const repeated = s.hits.length - new Set(s.hits).size;
        return { actual: `${first.status} then ${second.status === 'partial' ? 'resumed' : second.status}, ${repeated} repeated`, requests: s.hits.length };
      });
    } finally { await s.close(); } } },
];

async function occurrences(dir: string, secrets: string[]): Promise<number> {
  let count = 0;
  for (const path of await files(dir)) {
    const bytes = await readFile(path);
    for (const secret of secrets) if (bytes.includes(Buffer.from(secret))) count++;
  }
  return count;
}

// Changing an id, group or expectation changes this digest on purpose: the set is frozen.
// Revision 2: hash-only comparisons are leads, never confirmed findings.
// Previous manifest: 5fe8851acc61bd531e88ce39a49130323d1d03e917db5df1cb3fa61b8e9eeb9c.
export const FROZEN_DIGEST = 'fd3ee6c9fa3c9835ad7a197683ac0d74501e4ecf3ace48f390e6cc6031c98c64';
export const frozenManifest = () => digest(cases.map(({ id, group, expected }) => ({ id, group, expected })));

export async function runEvaluation(): Promise<Report> {
  if (frozenManifest() !== FROZEN_DIGEST) throw new Error('Frozen evaluation set was modified');
  const results: CaseResult[] = [];
  for (const c of cases) {
    const started = performance.now();
    let outcome: Outcome;
    try { outcome = await c.run(); } catch { outcome = { actual: 'case-error', requests: 0 }; }
    results.push({ id: c.id, group: c.group, expected: c.expected, actual: outcome.actual, passed: outcome.actual === c.expected,
      requests: outcome.requests, ms: Math.round(performance.now() - started) });
  }
  const by = (group: Group, side: string) => results.filter(r => r.group === group && r.id.includes(side));
  const num = (text: string, pattern: RegExp) => Number(text.match(pattern)?.[1] ?? 0);
  const vulnerable = by('detection', 'vulnerable'), fixed = by('detection', 'fixed');
  return {
    schemaVersion: 1, toolVersion: '0.9.0', frozenDigest: FROZEN_DIGEST, node: process.versions.node, cases: results,
    metrics: {
      cases: results.length, passed: results.filter(r => r.passed).length,
      requests: results.reduce((n, r) => n + r.requests, 0), ms: results.reduce((n, r) => n + r.ms, 0),
      detections: vulnerable.filter(r => r.actual === 'confirmed').length, omissions: vulnerable.filter(r => r.actual !== 'confirmed').length,
      falsePositives: fixed.filter(r => r.actual === 'confirmed').length,
      unresolvedAsExpected: results.filter(r => r.group === 'inconclusive' && r.passed).length,
      scopeViolations: results.filter(r => r.group === 'scope' && !r.passed).length,
      secretOccurrences: results.filter(r => r.group === 'secrets').reduce((n, r) => n + num(r.actual, /^(\d+) occurrences/), 0),
      repeatedRequests: results.filter(r => r.group === 'recovery').reduce((n, r) => n + num(r.actual, /(\d+) repeated/), 0),
    },
    limitations: [
      'Metrics come from BBA\'s own labs: three authorization classes, two variants, synthetic data and loopback only. They do not estimate detection rates, false positives or coverage on any real system.',
      'Revision 2 checks that hash-only matches remain needs-validation, partial property differences remain unresolved, and budget, scope, redirect, secret and resume rules hold. These cases do not establish confirmed vulnerabilities. Autonomous hunt has separate tests.',
      'Browser capture isolation is covered by the capture tests, not by this set, because it needs a Chromium install.',
    ],
  };
}

export function reportMarkdown(r: Report): string {
  const m = r.metrics;
  return `# Evaluación congelada BBA ${r.toolVersion}

Node ${r.node} · conjunto \`${r.frozenDigest.slice(0, 12)}\` · **${m.passed}/${m.cases}** casos esperados

| Métrica | Valor |
|---|---|
| Detecciones (variantes vulnerables confirmadas) | ${m.detections} |
| Omisiones (vulnerables no confirmadas) | ${m.omissions} |
| Falsos positivos (variantes corregidas confirmadas) | ${m.falsePositives} |
| Inconclusos correctos (presupuesto agotado → unresolved) | ${m.unresolvedAsExpected} |
| Violaciones de alcance | ${m.scopeViolations} |
| Secretos hallados en artefactos | ${m.secretOccurrences} |
| Solicitudes repetidas al retomar | ${m.repeatedRequests} |
| Solicitudes totales / tiempo | ${m.requests} / ${m.ms} ms |

| Caso | Esperado | Obtenido | |
|---|---|---|---|
${r.cases.map(c => `| ${c.id} | ${c.expected} | ${c.actual} | ${c.passed ? 'ok' : '**FALLA**'} |`).join('\n')}

## Limitaciones

${r.limitations.map(l => '- ' + l).join('\n')}
`;
}

export async function evaluationFile(output: string): Promise<Report> {
  const report = await runEvaluation();
  const body = output.endsWith('.md') ? reportMarkdown(report) : JSON.stringify({ report, sha256: digest(report) }, null, 2) + '\n';
  await writeFile(output, body, { flag: 'wx', mode: 0o600 });
  return report;
}
