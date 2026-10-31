import { integer, optionalFields, requestSpec } from './scope.ts';
import { writeFileSync } from 'node:fs';
import { digest } from './contracts.ts';
import { inspectSession, validateSession } from './session.ts';
import type { Session } from './session.ts';

type Query = { kind: 'summary' | 'attempts' | 'fields'; offset: number; limit: number; stepId?: string; expectedDigest?: string };
export function evidenceView(session: Session, value: unknown) {
  validateSession(session); optionalFields(value, ['kind', 'offset', 'limit'], ['stepId', 'expectedDigest']);
  if (!['summary', 'attempts', 'fields'].includes(value.kind)) throw new Error('Invalid evidence view');
  integer(value.offset, 0, 2000); integer(value.limit, 1, 50);
  const query = value as Query;
  if (query.stepId !== undefined && !session.plan.steps.some(s => s.id === query.stepId)) throw new Error('Unknown evidence step');
  const revisionDigest = digest(session);
  if (query.expectedDigest !== undefined && query.expectedDigest !== revisionDigest) throw new Error('Evidence revision changed; request a fresh summary');
  const parentEvidenceId = session.id;
  if (query.kind === 'summary') return { parentEvidenceId, revisionDigest, producerVersion: session.producerVersion ?? null, status: session.status, scopeDigest: session.scopeDigest,
    steps: session.plan.steps.length, attempts: session.attempts.length, fields: session.attempts.reduce((n, a) => n + (a.response?.facts?.length ?? 0), 0),
    retained: 'metadata-and-projected-digests', limitations: ['Raw request inputs, credentials and response bodies are not retained.', 'Evidence IDs identify records; digests do not authenticate an operator.'] };
  const attempts = session.attempts.filter(a => query.stepId === undefined || a.stepId === query.stepId);
  const records = query.kind === 'attempts' ? attempts.map(a => ({ evidenceId: session.id + ':' + a.stepId, ...a }))
    : attempts.flatMap(a => (a.response?.facts ?? []).map(f => ({ evidenceId: session.id + ':' + a.stepId + ':' + f.name, parentEvidenceId: session.id + ':' + a.stepId,
      pointer: session.plan.steps.find(s => s.id === a.stepId)!.observe!.find(p => p.name === f.name)!.pointer, ...f })));
  const items = records.slice(query.offset, query.offset + query.limit);
  return { parentEvidenceId, revisionDigest, kind: query.kind, total: records.length, offset: query.offset, items,
    nextOffset: query.offset + items.length < records.length ? query.offset + items.length : null };
}

export function compareSessions(before: Session, after: Session) {
  validateSession(before); validateSession(after);
  const previous = new Map(before.plan.steps.map(s => [s.id, s]));
  const next = new Map(after.plan.steps.map(s => [s.id, s]));
  const steps = [...new Set([...previous.keys(), ...next.keys()])].map(id => {
    const a = previous.get(id), b = next.get(id);
    const oldResponse = before.attempts.find(x => x.stepId === id)?.response ?? null;
    const newResponse = after.attempts.find(x => x.stepId === id)?.response ?? null;
    const sameRequestDefinition = !!a && !!b && a.url === b.url && a.credentialEnv === b.credentialEnv && digest(requestSpec(a)) === digest(requestSpec(b));
    const inputsComparable = sameRequestDefinition && !a!.query && !a!.body;
    return { stepId: id, change: !a ? 'added' : !b ? 'removed' : sameRequestDefinition ? 'same-definition' : 'changed-definition', inputsComparable,
      beforeEvidenceId: a ? before.id + ':' + id : null, afterEvidenceId: b ? after.id + ':' + id : null,
      statusBefore: oldResponse?.status ?? null, statusAfter: newResponse?.status ?? null,
      bodyDigestEqual: oldResponse && newResponse ? oldResponse.sha256 === newResponse.sha256 : null,
      fields: (b?.observe ?? a?.observe ?? []).map(p => {
        const old = oldResponse?.facts?.find(f => f.name === p.name), current = newResponse?.facts?.find(f => f.name === p.name);
        const sameSelector = !!a?.observe?.some(x => x.name === p.name && x.pointer === p.pointer) && !!b?.observe?.some(x => x.name === p.name && x.pointer === p.pointer);
        return { name: p.name, sameSelector, digestEqual: sameSelector && old?.present && current?.present ? old.kind === current.kind && old.sha256 === current.sha256 : null };
      }) };
  });
  return { schemaVersion: 1, before: { evidenceId: before.id, revisionDigest: digest(before) }, after: { evidenceId: after.id, revisionDigest: digest(after) }, steps,
    limitations: ['Differences are observations, not vulnerability classifications.', 'Credential values, current server state and request input values are not available for comparison; session-salted input bindings are not cross-run identities.'] };
}

export const evidenceViewFile = (folder: string, query: unknown) => evidenceView(inspectSession(folder), query);
export const compareRunFiles = (before: string, after: string) => compareSessions(inspectSession(before), inspectSession(after));
export function exportComparison(before: string, after: string, out: string) {
  const comparison = compareRunFiles(before, after);
  writeFileSync(out, JSON.stringify({ comparison, sha256: digest(comparison) }, null, 2), { flag: 'wx', mode: 0o600 });
  return comparison;
}
