import { createHash } from 'node:crypto';

export type Actor = 'anonymous' | 'account-a' | 'account-b';
export type Variant = 'vulnerable' | 'fixed';
export type Status = 'confirmed' | 'not-reproduced' | 'unresolved';
export type Document = { id: string; owner: Actor; marker: string };
export type Observation = {
  timestamp: string;
  actor: Actor;
  path: string;
  status: number;
  document: Document | null;
};
export type Evidence = Observation & { id: string };
export type Finding = {
  id: string;
  actor: Actor;
  owner: Actor;
  documentId: string;
  status: Status;
  evidenceIds: string[];
  observation: string;
  limitation: string;
};
export type Investigation = {
  schemaVersion: 1;
  id: string;
  createdAt: string;
  toolVersion: '0.1.0';
  environment: {
    kind: 'owned-loopback-lab';
    variant: Variant;
    origin: string;
    authorization: 'BBA-created disposable lab with synthetic data';
    paths: string[];
    requestBudget: 5;
  };
  evidence: Evidence[];
  findings: Finding[];
};
export type Bundle = { investigation: Investigation; sha256: string };

// Canonicalize parsed JSON, independent of object-key insertion order.
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, item]) => JSON.stringify(key) + ':' + canonical(item)).join(',') + '}';
  }
  const result = JSON.stringify(value);
  if (result === undefined) throw new Error('Value is not JSON');
  return result;
}

export function digest(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

export function evidence(observation: Observation): Evidence {
  return { ...observation, id: 'sha256:' + digest(observation) };
}

function object(value: unknown, fields: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) {
    throw new Error('Invalid contract fields');
  }
}
function text(value: unknown, max = 1500): asserts value is string {
  if (typeof value !== 'string' || !value.length || value.length > max
    || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) throw new Error('Invalid text');
}
function actor(value: unknown): asserts value is Actor {
  if (!['anonymous', 'account-a', 'account-b'].includes(value as string)) throw new Error('Invalid actor');
}
function timestamp(value: unknown): void {
  text(value, 30);
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value))) throw new Error('Invalid timestamp');
}

export function validateDocument(value: unknown): asserts value is Document {
  object(value, ['id', 'owner', 'marker']);
  text(value.id, 36);
  if (!/^[a-f0-9-]{36}$/.test(value.id)) throw new Error('Invalid document ID');
  actor(value.owner);
  if (value.owner === 'anonymous') throw new Error('Anonymous owner');
  text(value.marker, 100);
  if (!/^synthetic-[a-f0-9]{32}$/.test(value.marker)) throw new Error('Unexpected document content');
}

export function validateBundle(value: unknown): asserts value is Bundle {
  object(value, ['investigation', 'sha256']);
  const inv = value.investigation;
  object(inv, ['schemaVersion', 'id', 'createdAt', 'toolVersion', 'environment', 'evidence', 'findings']);
  if (inv.schemaVersion !== 1 || inv.toolVersion !== '0.1.0') throw new Error('Unsupported schema/tool version');
  text(inv.id, 36);
  if (!/^[a-f0-9-]{36}$/.test(inv.id)) throw new Error('Invalid investigation ID');
  timestamp(inv.createdAt);
  const env = inv.environment;
  object(env, ['kind', 'variant', 'origin', 'authorization', 'paths', 'requestBudget']);
  if (env.kind !== 'owned-loopback-lab' || !['vulnerable', 'fixed'].includes(env.variant as string)
    || env.authorization !== 'BBA-created disposable lab with synthetic data' || env.requestBudget !== 5) {
    throw new Error('Invalid lab scope');
  }
  text(env.origin, 100);
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(env.origin)
    || Number(new URL(env.origin).port) > 65535) throw new Error('Invalid lab origin');
  if (!Array.isArray(env.paths) || env.paths.length !== 2 || new Set(env.paths).size !== 2
    || env.paths.some(p => typeof p !== 'string' || !/^\/documents\/[a-f0-9-]{36}$/.test(p))) {
    throw new Error('Invalid lab paths');
  }
  if (!Array.isArray(inv.evidence) || inv.evidence.length !== 5) throw new Error('Incomplete lab evidence');
  const ids = new Set<string>();
  for (const item of inv.evidence) {
    object(item, ['id', 'timestamp', 'actor', 'path', 'status', 'document']);
    const { id, ...observation } = item;
    timestamp(item.timestamp); actor(item.actor);
    if (!env.paths.includes(item.path)) throw new Error('Evidence outside scope');
    if (!Number.isInteger(item.status) || Number(item.status) < 100 || Number(item.status) > 599) {
      throw new Error('Invalid response status');
    }
    if (item.document !== null) {
      validateDocument(item.document);
      if (item.status !== 200 || item.path !== '/documents/' + item.document.id) throw new Error('Mismatched document');
    }
    if (id !== 'sha256:' + digest(observation) || ids.has(id as string)) throw new Error('Invalid or duplicate evidence ID');
    ids.add(id as string);
  }
  if (!Array.isArray(inv.findings) || inv.findings.length !== 2) throw new Error('Invalid findings');
  for (const item of inv.findings) {
    object(item, ['id', 'actor', 'owner', 'documentId', 'status', 'evidenceIds', 'observation', 'limitation']);
    text(item.id, 50); actor(item.actor); actor(item.owner); text(item.documentId, 36);
    if (item.actor === item.owner || item.actor === 'anonymous' || item.owner === 'anonymous') throw new Error('Invalid boundary');
    if (!env.paths.includes('/documents/' + item.documentId)) throw new Error('Finding outside scope');
    if (!['confirmed', 'not-reproduced', 'unresolved'].includes(item.status as string)) throw new Error('Invalid finding status');
    if (!Array.isArray(item.evidenceIds) || item.evidenceIds.length !== 4
      || item.evidenceIds.some(id => !ids.has(id))) throw new Error('Invalid finding evidence');
    text(item.observation); text(item.limitation);
  }
  if (value.sha256 !== digest(inv)) throw new Error('Bundle integrity mismatch');
}
