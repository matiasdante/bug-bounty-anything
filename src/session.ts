import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, statSync, writeFileSync, unlinkSync, openSync, readSync, closeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { canonical, digest } from './contracts.ts';
import { fields, optionalFields, isoDate, validateScope, validatePlan } from './scope.ts';
import type { Scope, Plan, Step } from './scope.ts';
import { validateFacts } from './observations.ts';
import type { Fact } from './observations.ts';
import pkg from '../package.json' with { type: 'json' };

export type Attempt = {
  stepId: string; startedAt: string; endedAt: string | null;
  outcome: 'reserved' | 'succeeded' | 'cancelled' | 'interrupted' | 'error';
  reason: string | null;
  response: { status: number; bytes: number; sha256: string; facts?: Fact[] } | null;
};
export type Session = {
  schemaVersion: 2; toolVersion: '0.2.0'; id: string; createdAt: string;
  scope: Scope; scopeDigest: string; plan: Plan;
  status: 'ready' | 'running' | 'paused' | 'stopped' | 'completed' | 'partial';
  attempts: Attempt[];
  stopReason: string | null;
  inputDigest?: string;
  budgetBinding?: string;
  producerVersion?: string;
};
const reasons = ['cancelled', 'interrupted', 'deadline', 'budget-exhausted', 'authorization-expired',
  'address-blocked', 'invalid-credential', 'missing-credential', 'network-error', 'response-too-large',
  'incomplete-response', 'redirect', 'rate-limited', 'server-error', 'invalid-identifying-header', 'invalid-request-input', 'proof-complete'];

export function validateSession(value: unknown): asserts value is Session {
  optionalFields(value, ['schemaVersion', 'toolVersion', 'id', 'createdAt', 'scope', 'scopeDigest', 'plan', 'status', 'attempts', 'stopReason'], ['inputDigest', 'budgetBinding', 'producerVersion']);
  if (value.schemaVersion !== 2 || value.toolVersion !== '0.2.0' || !/^[a-f0-9-]{36}$/.test(value.id)) throw new Error('Unsupported session contract');
  isoDate(value.createdAt); validateScope(value.scope); validatePlan(value.plan, value.scope, false);
  if (value.scopeDigest !== digest(value.scope)) throw new Error('Scope integrity mismatch');
  if (value.inputDigest !== undefined && (typeof value.inputDigest !== 'string' || !/^[a-f0-9]{64}$/.test(value.inputDigest))) throw new Error('Invalid input digest');
  if (value.producerVersion !== undefined && (typeof value.producerVersion !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value.producerVersion))) throw new Error('Invalid producer version');
  if (value.budgetBinding !== undefined && (typeof value.budgetBinding !== 'string' || !/^[a-f0-9]{64}$/.test(value.budgetBinding))) throw new Error('Invalid budget binding');
  if (value.attempts?.length && value.scope.budgetId && !value.budgetBinding) throw new Error('Missing shared budget binding');
  if (value.attempts?.length && value.plan.steps.some((s: Step) => s.query || s.body) && !value.inputDigest) throw new Error('Missing input binding');
  if (!['ready', 'running', 'paused', 'stopped', 'completed', 'partial'].includes(value.status)) throw new Error('Invalid session status');
  if (value.stopReason !== null && !reasons.includes(value.stopReason)) throw new Error('Invalid stop reason');
  if (!Array.isArray(value.attempts) || value.attempts.length > value.plan.steps.length
    || value.attempts.length > value.scope.limits.maxRequests) throw new Error('Invalid attempt count');
  for (const [index, attempt] of value.attempts.entries()) {
    fields(attempt, ['stepId', 'startedAt', 'endedAt', 'outcome', 'reason', 'response']);
    if (attempt.stepId !== value.plan.steps[index].id) throw new Error('Attempts do not match plan order');
    isoDate(attempt.startedAt);
    if (attempt.startedAt < value.createdAt || (index && attempt.startedAt < value.attempts[index - 1].startedAt)) throw new Error('Invalid attempt chronology');
    if (!['reserved', 'succeeded', 'cancelled', 'interrupted', 'error'].includes(attempt.outcome)) throw new Error('Invalid outcome');
    if (attempt.outcome === 'reserved') {
      if (index !== value.attempts.length - 1 || attempt.endedAt !== null || attempt.reason !== null || attempt.response !== null || value.status !== 'running') throw new Error('Invalid reservation');
    } else {
      isoDate(attempt.endedAt);
      if (attempt.endedAt < attempt.startedAt) throw new Error('Invalid completion time');
      if (attempt.outcome === 'succeeded' ? attempt.reason !== null : !reasons.includes(attempt.reason)) throw new Error('Invalid outcome reason');
    }
    if (attempt.response !== null) {
      optionalFields(attempt.response, ['status', 'bytes', 'sha256'], ['facts']);
      const r = attempt.response;
      if (!Number.isInteger(r.status) || r.status < 100 || r.status > 599
        || !Number.isInteger(r.bytes) || r.bytes < 0 || r.bytes > value.scope.limits.maxResponseBytes
        || typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)) throw new Error('Invalid response evidence');
      const projections = value.plan.steps[index].observe;
      if (projections) validateFacts(r.facts, projections);
      else if (r.facts !== undefined) throw new Error('Unrequested response facts');
    } else if (attempt.outcome === 'succeeded') throw new Error('Missing response evidence');
  }
  if (value.status === 'completed' && (value.attempts.length !== value.plan.steps.length
    || value.attempts.some(a => a.outcome !== 'succeeded'))) throw new Error('Incomplete success state');
  if (value.status === 'partial' && (value.attempts.length !== value.plan.steps.length
    || value.attempts.some(a => a.outcome === 'reserved') || value.attempts.every(a => a.outcome === 'succeeded'))) throw new Error('Invalid partial state');
}

function transition(previous: Session, next: Session): void {
  if (previous.inputDigest !== undefined ? next.inputDigest !== previous.inputDigest : previous.attempts.length && next.inputDigest !== undefined) throw new Error('Immutable request inputs changed');
  if (previous.budgetBinding !== undefined ? next.budgetBinding !== previous.budgetBinding : previous.attempts.length && next.budgetBinding !== undefined) throw new Error('Immutable budget binding changed');
  for (const key of ['id', 'createdAt', 'scope', 'scopeDigest', 'plan', 'producerVersion'] as const) {
    if (canonical(previous[key]) !== canonical(next[key])) throw new Error('Immutable session contract changed');
  }
  const delta = next.attempts.length - previous.attempts.length;
  if (delta < 0 || delta > 1) throw new Error('Invalid reservation transition');
  for (let i = 0; i < previous.attempts.length; i++) {
    const old = previous.attempts[i], current = next.attempts[i];
    if (old.outcome !== 'reserved') {
      if (canonical(old) !== canonical(current)) throw new Error('Completed evidence changed');
    } else if (delta || current.stepId !== old.stepId || current.startedAt !== old.startedAt || current.outcome === 'reserved') {
      throw new Error('Invalid reservation completion');
    }
  }
  if (delta && next.attempts.at(-1)?.outcome !== 'reserved') throw new Error('Missing durable reservation');
  if (['stopped', 'completed', 'partial'].includes(previous.status)) throw new Error('Session already terminal');
}

export function readJson(path: string): unknown {
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(1024 * 1024 + 1);
    let size = 0;
    while (size < buffer.length) {
      const read = readSync(fd, buffer, size, buffer.length - size, null);
      if (!read) break; size += read;
    }
    if (size > 1024 * 1024) throw new Error('JSON input exceeds 1 MiB');
    return JSON.parse(buffer.subarray(0, size).toString('utf8'));
  } finally { closeSync(fd); }
}

function connect(folder: string, readOnly = false): DatabaseSync {
  try { statSync(join(folder, '.initializing')); throw new Error('Session initialization is incomplete'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const path = join(folder, 'session.sqlite');
  if (!statSync(path).isFile() || statSync(path).size > 128 * 1024 * 1024) throw new Error('Invalid session database size');
  const db = new DatabaseSync(path, { readOnly, timeout: 0 });
  db.exec('PRAGMA trusted_schema=OFF;');
  return db;
}

function latest(db: DatabaseSync): { state: Session; hash: string; sequence: number } {
  const count = db.prepare('SELECT COUNT(*) AS n, MAX(length(body)) AS size FROM checkpoints').get();
  if (!count || Number(count.n) < 1 || Number(count.n) > 512 || Number(count.size) > 1024 * 1024) throw new Error('Invalid checkpoint limits');
  let previous: Session | undefined, previousHash = '', sequence = 0;
  for (const row of db.prepare('SELECT sequence, body, previous_hash, hash FROM checkpoints ORDER BY sequence').iterate()) {
    if (row.sequence !== sequence + 1 || row.previous_hash !== previousHash) throw new Error('Broken checkpoint chain');
    const state: unknown = JSON.parse(String(row.body));
    validateSession(state);
    const hash = digest({ sequence: row.sequence, previousHash, state });
    if (row.hash !== hash) throw new Error('Checkpoint integrity mismatch');
    if (previous) transition(previous, state);
    previous = state; previousHash = hash; sequence++;
  }
  return { state: previous!, hash: previousHash, sequence };
}

export function createSession(folder: string, scope: Scope, plan: Plan): void {
  validateScope(scope); validatePlan(plan, scope);
  const target = resolve(folder);
  mkdirSync(dirname(target), { recursive: true });
  mkdirSync(target); // Exclusive ownership; no overwriting another investigation.
  const marker = join(target, '.initializing');
  writeFileSync(marker, 'initializing\n', { flag: 'wx' });
  const db = new DatabaseSync(join(target, 'session.sqlite'));
  try {
    db.exec('PRAGMA synchronous=FULL; CREATE TABLE checkpoints (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL) STRICT;');
    const state: Session = {
      schemaVersion: 2, toolVersion: '0.2.0', producerVersion: pkg.version, id: randomUUID(), createdAt: new Date().toISOString(),
      scope: structuredClone(scope), scopeDigest: digest(scope), plan: structuredClone(plan), status: 'ready', attempts: [], stopReason: null,
    };
    validateSession(state);
    db.prepare('INSERT INTO checkpoints VALUES (?, ?, ?, ?)').run(1, canonical(state), '', digest({ sequence: 1, previousHash: '', state }));
    const lock = new DatabaseSync(join(target, 'execution-lock.sqlite'));
    try { lock.exec('CREATE TABLE owner (id INTEGER PRIMARY KEY) STRICT;'); } finally { lock.close(); }
  } finally { db.close(); }
  unlinkSync(marker);
}

export function inspectSession(folder: string): Session {
  const db = connect(resolve(folder), true);
  try { return latest(db).state; } finally { db.close(); }
}

export async function withSession<T>(folder: string, action: (state: Session, checkpoint: (state: Session) => void) => Promise<T>): Promise<T> {
  const target = resolve(folder);
  statSync(join(target, 'execution-lock.sqlite'));
  // A separate SQLite write transaction is the OS-owned execution lock.
  // The evidence DB commits independently; process death releases only the lock.
  const lock = new DatabaseSync(join(target, 'execution-lock.sqlite'), { timeout: 0 });
  let db: DatabaseSync | undefined;
  try {
    try { lock.exec('BEGIN IMMEDIATE;'); } catch { throw new Error('Execution already active'); }
    db = connect(target);
    db.exec('PRAGMA synchronous=FULL;');
    let current = latest(db);
    const checkpoint = (state: Session) => {
      validateSession(state); transition(current.state, state);
      if (current.sequence >= 512) throw new Error('Checkpoint limit reached');
      const sequence = current.sequence + 1;
      const hash = digest({ sequence, previousHash: current.hash, state });
      db!.prepare('INSERT INTO checkpoints VALUES (?, ?, ?, ?)').run(sequence, canonical(state), current.hash, hash);
      current = { state: structuredClone(state), hash, sequence };
    };
    return await action(structuredClone(current.state), checkpoint);
  } finally { db?.close(); lock.close(); }
}

export function sessionSummary(state: Session) {
  return {
    id: state.id, status: state.status, reservedRequests: state.attempts.length,
    requestBudget: state.scope.limits.maxRequests, pendingSteps: state.plan.steps.length - state.attempts.length,
    succeeded: state.attempts.filter(a => a.outcome === 'succeeded').length,
    unresolved: state.attempts.filter(a => a.outcome !== 'succeeded').length, stopReason: state.stopReason,
  };
}

export function exportSession(folder: string, output: string, format: 'json' | 'markdown'): void {
  const state = inspectSession(folder);
  const content = format === 'json' ? JSON.stringify({ session: state, sha256: digest(state) }, null, 2) + '\n'
    : `# BBA — ejecución ${state.id}\n\nEstado: **${state.status}**. No se infieren vulnerabilidades a partir de estos estados HTTP.\n\n`
      + `Presupuesto consumido: ${state.attempts.length}/${state.scope.limits.maxRequests}. Pendientes: ${state.plan.steps.length - state.attempts.length}.\n\n`
      + 'Los intentos interrumpidos o cancelados consumen presupuesto y no se repiten al retomar. Cuerpos y credenciales no se conservan.\n\n'
      + '| Paso | Resultado | HTTP | Motivo |\n|---|---|---|---|\n'
      + state.attempts.map(a => `| ${a.stepId} | ${a.outcome} | ${a.response?.status ?? '-'} | ${a.reason ?? '-'} |`).join('\n')
      + '\n\nLa evidencia conserva tamaño y hash de los bytes recibidos, sin guardar su contenido. Un hash no autentica al autor.\n';
  writeFileSync(resolve(output), content, { flag: 'wx', mode: 0o600 });
}
