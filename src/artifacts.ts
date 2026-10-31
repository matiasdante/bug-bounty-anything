import { existsSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { digest } from './contracts.ts';
import { fields, integer, optionalFields } from './scope.ts';
import { inspectSession, readJson } from './session.ts';
import { evidenceView } from './evidence.ts';
import pkg from '../package.json' with { type: 'json' };

const files = { hunt: 'hunt.json', 'browser-check': 'browser-check.json', scenario: 'scenario.json', 'race-check': 'race-check.json', 'csrf-check': 'csrf-check.json' } as const;
type Kind = keyof typeof files;
type Manifest = { schemaVersion: 1; producerVersion?: string; kind: Kind; id: string; scopeDigest: string; configDigest: string; journalDigest: string; resultDigest: string };
function bytes(folder: string, name: string): Buffer {
  const path = join(folder, name), stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024) throw new Error('Invalid retained artifact file');
  return readFileSync(path);
}
const hash = (value: Buffer) => createHash('sha256').update(value).digest('hex');
export function sealArtifact(folder: string, input: Pick<Manifest, 'kind' | 'id' | 'scopeDigest' | 'configDigest'>): void {
  const manifest: Manifest = { schemaVersion: 1, producerVersion: pkg.version, ...input, journalDigest: hash(bytes(folder, 'requests.jsonl')), resultDigest: hash(bytes(folder, files[input.kind])) };
  writeFileSync(join(folder, 'artifact.json'), JSON.stringify({ manifest, sha256: digest(manifest) }, null, 2), { flag: 'wx', mode: 0o600 });
}

export function artifactView(folder: string, input: unknown): any {
  if (!existsSync(join(folder, 'artifact.json')) && existsSync(join(folder, 'session.sqlite'))) {
    const mapped = input && typeof input === 'object' && !Array.isArray(input) && (input as any).kind === 'events'
      ? { ...(input as Record<string, unknown>), kind: 'attempts' }
      : input;
    return evidenceView(inspectSession(folder), mapped);
  }
  optionalFields(input, ['kind', 'offset', 'limit'], ['eventType', 'expectedDigest']);
  if (!['summary', 'events', 'fields'].includes(input.kind)) throw new Error('Invalid artifact view');
  integer(input.offset, 0, 10000); integer(input.limit, 1, 50);
  if (input.eventType !== undefined && (typeof input.eventType !== 'string' || !/^[a-z][a-z-]{0,39}$/.test(input.eventType))) throw new Error('Invalid event filter');
  bytes(folder, 'artifact.json');
  const envelope = readJson(join(folder, 'artifact.json')); fields(envelope, ['manifest', 'sha256']);
  const m = envelope.manifest; optionalFields(m, ['schemaVersion', 'kind', 'id', 'scopeDigest', 'configDigest', 'journalDigest', 'resultDigest'], ['producerVersion']);
  if (m.schemaVersion !== 1 || (m.producerVersion !== undefined && (typeof m.producerVersion !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(m.producerVersion))) || !Object.hasOwn(files, m.kind) || !/^[a-f0-9-]{36}$/.test(m.id)
    || [m.scopeDigest, m.configDigest, m.journalDigest, m.resultDigest].some(x => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x))
    || envelope.sha256 !== digest(m)) throw new Error('Invalid artifact manifest');
  if (input.expectedDigest !== undefined && input.expectedDigest !== envelope.sha256) throw new Error('Artifact revision changed');
  const manifest = m as Manifest, journal = bytes(folder, 'requests.jsonl');
  if (hash(journal) !== manifest.journalDigest || hash(bytes(folder, files[manifest.kind])) !== manifest.resultDigest) throw new Error('Artifact file integrity mismatch');
  const result = JSON.parse(bytes(folder, files[manifest.kind]).toString('utf8'));
  fields(result, ['result', 'sha256']);
  if (result.result?.id !== manifest.id || result.sha256 !== digest(result.result)) throw new Error('Artifact result integrity mismatch');
  const lines = journal.toString('utf8').trimEnd().split('\n');
  if (lines.length > 500 || lines.some(s => s.length > 1024 * 1024)) throw new Error('Artifact event limits exceeded');
  const events = lines.map((line, i) => {
    const event = JSON.parse(line);
    if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.event !== 'string' || !/^[a-z][a-z-]{0,39}$/.test(event.event)) throw new Error('Invalid retained event');
    return { evidenceId: manifest.id + ':event-' + (i + 1), ordinal: i + 1, event };
  });
  const start = events[0]?.event;
  if (start?.event !== 'start') throw new Error('Missing artifact start');
  const scope = manifest.kind === 'hunt' ? start.scope : JSON.parse(bytes(folder, 'scope.json').toString('utf8'));
  const config = manifest.kind === 'hunt' ? start.config : JSON.parse(bytes(folder, 'config.json').toString('utf8'));
  if (digest(scope) !== manifest.scopeDigest || digest(config) !== manifest.configDigest) throw new Error('Artifact source integrity mismatch');
  if (input.kind === 'summary') return { parentEvidenceId: manifest.id, revisionDigest: envelope.sha256, artifactKind: manifest.kind,
    producerVersion: manifest.producerVersion, events: events.length, resultFile: files[manifest.kind], journalFile: 'requests.jsonl',
    limitations: ['Sealed file integrity is verified; this does not authenticate an operator or independently confirm findings.', 'Raw credentials and request/response values are not retained by the producers.'] };
  const selected = events.filter(e => input.eventType === undefined || e.event.event === input.eventType);
  const records = input.kind === 'events' ? selected.map(e => {
    const { scope, config, ...event } = e.event;
    return { ...e, event, ...(scope || config ? { sourceObjectsOmitted: true } : {}) };
  }) : selected.flatMap(e => {
    if (e.event.facts === undefined) return [];
    if (!Array.isArray(e.event.facts) || e.event.facts.length > 20) throw new Error('Invalid retained fields');
    return e.event.facts.map((f: any, index: number) => ({ evidenceId: e.evidenceId + ':field-' + (index + 1), parentEvidenceId: e.evidenceId, fact: f }));
  });
  const items = records.slice(input.offset, input.offset + input.limit);
  return { parentEvidenceId: manifest.id, revisionDigest: envelope.sha256, kind: input.kind, total: records.length, items,
    nextOffset: input.offset + items.length < records.length ? input.offset + items.length : null };
}
