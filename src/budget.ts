import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, realpathSync, lstatSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonical, digest } from './contracts.ts';
import { validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { RequestFailure } from './http.ts';

type Reservation = { reference: string; reservedAt: number; endedAt: number | null; pair?: boolean };
type Event = { type: 'start'; authorizationDigest: string; limitsDigest: string; at: number }
  | { type: 'reserve'; reference: string; at: number; pair?: true }
  | { type: 'finish'; reference: string; at: number };

function canFinishReservation(reservations: Reservation[], index: number): boolean {
  const selected = reservations[index];
  if (!selected || selected.endedAt !== null) return false;
  const openAfter = reservations.slice(index + 1).filter(r => r.endedAt === null);
  if (openAfter.length === 0) return true;
  return selected.pair === true
    && openAfter.length === 1
    && reservations[index + 1] === openAfter[0]
    && openAfter[0].pair === true;
}

function read(db: DatabaseSync) {
  const size = db.prepare('SELECT count(*) AS n, max(length(body)) AS size FROM events').get()!;
  if (Number(size.n) < 1 || Number(size.n) > 201 || Number(size.size) > 1024) throw new Error('Invalid shared budget event limits');
  const rows = db.prepare('SELECT sequence, body, previous_hash, hash FROM events ORDER BY sequence').all();
  if (!rows.length || rows.length > 201) throw new Error('Invalid shared budget event count');
  let sequence = 0, hash = '', start: Extract<Event, { type: 'start' }> | undefined;
  const reservations: Reservation[] = [];
  for (const row of rows) {
    const event = JSON.parse(String(row.body)) as Event;
    if (row.sequence !== ++sequence || row.previous_hash !== hash || row.hash !== digest({ sequence, previousHash: hash, event })
      || !Number.isSafeInteger(event.at) || event.at < 0) throw new Error('Invalid shared budget chain');
    if (event.type === 'start') {
      if (sequence !== 1 || Object.keys(event).sort().join() !== 'at,authorizationDigest,limitsDigest,type'
        || !/^[a-f0-9]{64}$/.test(event.authorizationDigest) || !/^[a-f0-9]{64}$/.test(event.limitsDigest)) throw new Error('Invalid shared budget start');
      start = event;
    } else {
      const keys = Object.keys(event).sort().join();
      const validKeys = keys === 'at,reference,type' || (event.type === 'reserve' && keys === 'at,pair,reference,type' && event.pair === true);
      if (!start || !validKeys || typeof event.reference !== 'string'
        || !/^[A-Za-z0-9:._-]{1,200}$/.test(event.reference) || event.at < start.at) throw new Error('Invalid shared budget event');
      const last = reservations.at(-1);
      if (event.type === 'reserve') {
        if (reservations.some(r => r.reference === event.reference) || last && event.at < (last.endedAt ?? last.reservedAt)) throw new Error('Invalid shared budget reservation');
        reservations.push({ reference: event.reference, reservedAt: event.at, endedAt: null, ...(event.pair ? { pair: true } : {}) });
      } else if (event.type === 'finish') {
        const index = reservations.findIndex(r => r.reference === event.reference);
        const selected = reservations[index];
        if (!selected || event.at < selected.reservedAt || !canFinishReservation(reservations, index)) throw new Error('Invalid shared budget completion');
        selected.endedAt = event.at;
      }
      else throw new Error('Invalid shared budget completion');
    }
    hash = String(row.hash);
  }
  if (!start) throw new Error('Missing shared budget start');
  return { sequence, hash, start, reservations };
}

export type ProgramBudget = { bindingDigest: string; beforeRequest: (reference: string, signal?: AbortSignal) => Promise<void>;
  beforeConcurrentPair: (references: [string, string], signal?: AbortSignal) => Promise<void>;
  complete: (reference: string) => void; remainingMs: () => number };
export async function withProgramBudget<T>(folder: string, scope: Scope, action: (budget: ProgramBudget) => Promise<T>): Promise<T> {
  validateScope(scope);
  mkdirSync(folder, { recursive: true });
  for (const name of ['lock.sqlite', 'budget.sqlite']) {
    try { const stat = lstatSync(join(folder, name)); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) throw new Error('Invalid shared budget file'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  const lock = new DatabaseSync(join(folder, 'lock.sqlite'), { timeout: 0 });
  let db: DatabaseSync | undefined;
  try {
    try { lock.exec('CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY); BEGIN IMMEDIATE;'); }
    catch { throw new Error('Shared program budget is already active'); }
    db = new DatabaseSync(join(folder, 'budget.sqlite'), { timeout: 0 });
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL) STRICT;');
    if (Number(db.prepare('SELECT count(*) AS n FROM events').get()!.n) === 0) {
      const event: Event = { type: 'start', at: Date.now(), authorizationDigest: digest(scope.authorization), limitsDigest: digest(scope.limits) };
      db.prepare('INSERT INTO events VALUES (?, ?, ?, ?)').run(1, canonical(event), '', digest({ sequence: 1, previousHash: '', event }));
    }
    let state = read(db);
    if (state.start.authorizationDigest !== digest(scope.authorization) || state.start.limitsDigest !== digest(scope.limits)) throw new Error('Shared budget authorization or limits changed');
    if (state.reservations.length > scope.limits.maxRequests) throw new Error('Shared budget exceeds configured limit');
    const append = (event: Event) => {
      const sequence = state.sequence + 1, hash = digest({ sequence, previousHash: state.hash, event });
      db!.prepare('INSERT INTO events VALUES (?, ?, ?, ?)').run(sequence, canonical(event), state.hash, hash);
      state = read(db!);
    };
    const deadline = Math.min(state.start.at + scope.limits.maxDurationMs, Date.parse(scope.authorization.validUntil));
    const check = (signal?: AbortSignal) => {
      if (signal?.aborted) throw new RequestFailure('cancelled');
      if (Date.now() < Date.parse(scope.authorization.validFrom) || Date.now() >= Date.parse(scope.authorization.validUntil)) throw new RequestFailure('authorization-expired');
      if (Date.now() >= deadline) throw new RequestFailure('deadline');
      if (state.reservations.length >= scope.limits.maxRequests) throw new RequestFailure('budget-exhausted');
    };
    return await action({
      bindingDigest: digest({ path: process.platform === 'win32' ? realpathSync(folder).toLowerCase() : realpathSync(folder), authorization: state.start.authorizationDigest }),
      remainingMs: () => deadline - Date.now(),
      beforeRequest: async (reference, signal) => {
        if (!/^[A-Za-z0-9:._-]{1,200}$/.test(reference) || state.reservations.some(r => r.reference === reference)) throw new Error('Shared budget reservation cannot be replayed');
        check(signal);
        // After process loss, conservatively wait through any uncompleted reservation timeout.
        const lastEnd = state.reservations.reduce((max, r) => Math.max(max, r.endedAt ?? r.reservedAt + scope.limits.timeoutMs), 0);
        const wait = Math.max(0, lastEnd + scope.limits.minIntervalMs - Date.now());
        if (Date.now() + wait >= deadline) throw new RequestFailure('deadline');
        if (wait) try { await delay(wait, undefined, { signal }); } catch { throw new RequestFailure('cancelled'); }
        check(signal); append({ type: 'reserve', reference, at: Date.now() });
      },
      beforeConcurrentPair: async (references, signal) => {
        if (scope.limits.minIntervalMs !== 0 || references.length !== 2 || references[0] === references[1]
          || references.some(reference => !/^[A-Za-z0-9:._-]{1,200}$/.test(reference)
            || state.reservations.some(r => r.reference === reference))) throw new Error('Invalid concurrent pair');
        check(signal);
        if (state.reservations.length + 2 > scope.limits.maxRequests) throw new RequestFailure('budget-exhausted');
        const lastEnd = state.reservations.reduce((max, r) => Math.max(max, r.endedAt ?? r.reservedAt + scope.limits.timeoutMs), 0);
        const wait = Math.max(0, lastEnd - Date.now());
        if (Date.now() + wait >= deadline) throw new RequestFailure('deadline');
        if (wait) try { await delay(wait, undefined, { signal }); } catch { throw new RequestFailure('cancelled'); }
        check(signal);
        for (const reference of references) append({ type: 'reserve', reference, at: Date.now(), pair: true });
      },
      complete: reference => {
        const index = state.reservations.findIndex(r => r.reference === reference);
        if (!canFinishReservation(state.reservations, index))
          throw new Error('Invalid shared budget completion');
        append({ type: 'finish', reference, at: Date.now() });
      },
    });
  } finally { db?.close(); lock.close(); }
}

export function usingScopeBudget<T>(scope: Scope, scopePath: string, action: (budget: ProgramBudget | undefined) => Promise<T>, confine: (path: string) => string = p => p): Promise<T> {
  validateScope(scope);
  if (!scope.budgetId) return action(undefined);
  const folder = confine(join(dirname(resolve(scopePath)), '.bba-budgets', scope.budgetId));
  confine(join(folder, 'lock.sqlite')); confine(join(folder, 'budget.sqlite'));
  return withProgramBudget(folder, scope, action);
}

export function inspectBudget(folder: string) {
  const stat = lstatSync(join(folder, 'budget.sqlite'));
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) throw new Error('Invalid shared budget file');
  const db = new DatabaseSync(join(folder, 'budget.sqlite'), { readOnly: true });
  try {
    db.exec('PRAGMA trusted_schema=OFF;'); const state = read(db);
    return { schemaVersion: 1, startedAt: new Date(state.start.at).toISOString(), authorizationDigest: state.start.authorizationDigest,
      limitsDigest: state.start.limitsDigest, reservedRequests: state.reservations.length, uncertainRequests: state.reservations.filter(r => r.endedAt === null).length,
      revisionDigest: state.hash, reservations: state.reservations.map(({ reference, reservedAt, endedAt }) => ({ reference, reservedAt, endedAt })) };
  } finally { db.close(); }
}
