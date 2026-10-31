import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync,
  renameSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { canonical, digest } from './contracts.ts';
import { assertAuthorized, fields, isoDate, strictUrl, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { readJson, inspectSession } from './session.ts';
import { validateSurfaceBundle } from './surface.ts';
import { readPageSurface } from './capture.ts';
import { compileInvestigation, resumeInvestigation } from './planner.ts';
import { inspectBudget } from './budget.ts';
import { usingScopeBudget } from './budget.ts';
import { captureSurface } from './capture.ts';
import { investigateSurface } from './planner.ts';

type Kind = 'scope' | 'policy' | 'surface' | 'page' | 'profile' | 'run' | 'report';
const kinds: Kind[] = ['scope', 'policy', 'surface', 'page', 'profile', 'run', 'report'];
type Manifest = { schemaVersion: 1; id: string; target: string; createdAt: string };
type Event = { sequence: number; at: string; kind: Kind; artifact: string; artifactDigest: string;
  summary: Record<string, string | number | boolean>; previousHash: string; hash: string };
type Review = { schemaVersion: 1; sourceUrl: string; reviewedAt: string; scopeDigest: string;
  authorizationReference: string; sourceKind: 'official-program-policy' | 'owner-written-authorization';
  operatorDecision: 'authorized' | 'uncertain' };
type ReviewWithSource = Omit<Review, 'schemaVersion'> & { schemaVersion: 2; sourceFile: 'policy-source.txt'; sourceSha256: string };

function policySource(folder: string): string {
  const path = join(folder, 'policy-source.txt'), stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 1024 * 1024)
    throw new Error('Invalid policy source snapshot');
  const bytes = readFileSync(path);
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (value.includes('\0')) throw new Error('Invalid policy source text');
  return createHash('sha256').update(bytes).digest('hex');
}

function envelope(path: string, name: string): any {
  if (lstatSync(path).isSymbolicLink()) throw new Error('Invalid campaign ' + name);
  const saved = readJson(path); fields(saved, [name, 'sha256']);
  if (saved.sha256 !== digest(saved[name])) throw new Error('Campaign ' + name + ' integrity mismatch');
  return saved[name];
}
function manifest(folder: string): Manifest {
  const value = envelope(join(folder, 'manifest.json'), 'manifest');
  fields(value, ['schemaVersion', 'id', 'target', 'createdAt']);
  if (value.schemaVersion !== 1 || typeof value.id !== 'string' || !/^[a-f0-9-]{36}$/.test(value.id)) throw new Error('Invalid campaign manifest');
  strictUrl(value.target); isoDate(value.createdAt);
  return value as Manifest;
}
function events(folder: string): Event[] {
  const value = envelope(join(folder, 'events.json'), 'events');
  if (!Array.isArray(value) || value.length > 100) throw new Error('Invalid campaign events');
  let previousHash = '';
  for (let i = 0; i < value.length; i++) {
    const event = value[i];
    fields(event, ['sequence', 'at', 'kind', 'artifact', 'artifactDigest', 'summary', 'previousHash', 'hash']);
    isoDate(event.at);
    if (event.sequence !== i + 1 || !kinds.includes(event.kind) || typeof event.artifact !== 'string'
      || !/^[a-f0-9]{64}$/.test(event.artifactDigest) || event.previousHash !== previousHash
      || event.hash !== digest({ sequence: event.sequence, at: event.at, kind: event.kind,
        artifact: event.artifact, artifactDigest: event.artifactDigest, summary: event.summary, previousHash }))
      throw new Error('Campaign event integrity mismatch');
    previousHash = event.hash;
  }
  return value as Event[];
}
function writeEnvelope(path: string, key: string, value: unknown, replace = false): void {
  const body = JSON.stringify({ [key]: value, sha256: digest(value) }, null, 2) + '\n';
  if (!replace) { writeFileSync(path, body, { flag: 'wx', mode: 0o600 }); return; }
  const temp = path + '.' + randomUUID() + '.tmp';
  try {
    const fd = openSync(temp, 'wx', 0o600);
    try { writeSync(fd, body); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path);
  } finally { if (existsSync(temp)) unlinkSync(temp); }
}
function latest(records: Event[], kind: Kind): Event | undefined { return records.findLast(event => event.kind === kind); }
function artifact(path: string, kind: Kind, target: string, records: Event[]): { artifactDigest: string; summary: Event['summary'] } {
  const scopeEvent = latest(records, 'scope');
  let scope: Scope | null = null;
  if (scopeEvent) {
    const value = readJson(scopeEvent.artifact); validateScope(value);
    if (digest(value) !== scopeEvent.artifactDigest) throw new Error('Linked scope changed');
    scope = value;
  }
  if (kind === 'scope') {
    const value = readJson(path); validateScope(value); assertAuthorized(value, target, Date.parse(value.authorization.validFrom));
    if (!value.budgetId) throw new Error('Campaign scope requires a shared budget ID');
    return { artifactDigest: digest(value), summary: { budgetId: value.budgetId, mode: value.mode } };
  }
  if (kind === 'policy') {
    if (!scope) throw new Error('Attach scope before policy review');
    const value = readJson(path);
    const version = (value as { schemaVersion?: unknown } | null)?.schemaVersion;
    fields(value, ['schemaVersion', 'sourceUrl', 'reviewedAt', 'scopeDigest', 'authorizationReference', 'sourceKind', 'operatorDecision',
      ...(version === 2 ? ['sourceFile', 'sourceSha256'] : [])]);
    const review = value as Review | ReviewWithSource;
    const source = new URL(review.sourceUrl);
    if (![1, 2].includes(review.schemaVersion) || source.protocol !== 'https:' || source.username || source.password || source.hash
      || review.scopeDigest !== scopeEvent!.artifactDigest || review.authorizationReference !== scope.authorization.reference
      || !['official-program-policy', 'owner-written-authorization'].includes(review.sourceKind)
      || !['authorized', 'uncertain'].includes(review.operatorDecision)) throw new Error('Invalid campaign policy review');
    isoDate(review.reviewedAt);
    if (review.schemaVersion === 2 && (review.sourceFile !== 'policy-source.txt'
      || !/^[a-f0-9]{64}$/.test(review.sourceSha256)
      || policySource(dirname(path)) !== review.sourceSha256)) throw new Error('Policy source changed');
    return { artifactDigest: digest(review), summary: { decision: review.operatorDecision, sourceKind: review.sourceKind,
      ...(review.schemaVersion === 2 ? { sourceBound: true } : {}) } };
  }
  if (kind === 'surface') {
    const value = readJson(path); validateSurfaceBundle(value);
    const origin = new URL(target).origin;
    if (!value.surface.entries.some(entry => entry.origin === origin)) throw new Error('Surface does not include target origin');
    return { artifactDigest: digest(value), summary: { entries: value.surface.entries.length, format: value.surface.format } };
  }
  if (kind === 'page') {
    const value = readPageSurface(path);
    if (!value.pages.some(page => new URL(page.url).origin === new URL(target).origin)) throw new Error('Page capture does not include target origin');
    if (!scope || value.scopeDigest !== scopeEvent!.artifactDigest) throw new Error('Page capture scope differs');
    return { artifactDigest: digest(value), summary: { pages: value.pages.length } };
  }
  if (kind === 'profile') {
    const surfaceEvent = latest(records, 'surface');
    if (!scope || !surfaceEvent) throw new Error('Attach scope and surface before profile');
    const profile = readJson(path), surface = readJson(surfaceEvent.artifact);
    if (digest(surface) !== surfaceEvent.artifactDigest) throw new Error('Linked surface changed');
    const compiled = compileInvestigation(scope, surface, profile);
    return { artifactDigest: digest(profile), summary: { planned: compiled.checks.checks.length,
      unresolved: compiled.coverage.filter(item => item.disposition === 'unresolved').length,
      surfaceDigest: surfaceEvent.artifactDigest } };
  }
  if (kind === 'run') {
    if (!scope) throw new Error('Attach scope before run');
    const profileEvent = latest(records, 'profile'), surfaceEvent = latest(records, 'surface');
    if (!profileEvent || !surfaceEvent || profileEvent.sequence < surfaceEvent.sequence)
      throw new Error('Attach a current profile before its run');
    const state = inspectSession(path);
    if (digest(state.scope) !== scopeEvent!.artifactDigest) throw new Error('Run scope differs from campaign');
    const compiled = compileInvestigation(scope, readJson(surfaceEvent.artifact), readJson(profileEvent.artifact));
    if (!compiled.plan || digest(state.plan) !== digest(compiled.plan)) throw new Error('Run plan differs from campaign profile');
    if (state.status !== 'completed' && !(state.status === 'stopped' && state.stopReason === 'proof-complete'))
      throw new Error('Link only terminal runs; inspect paused runs separately');
    return { artifactDigest: digest(state), summary: { status: state.status, attempts: state.attempts.length } };
  }
  const runEvent = latest(records, 'run');
  if (!runEvent || runEvent.sequence < (latest(records, 'profile')?.sequence ?? 0)
    || dirname(runEvent.artifact) !== dirname(path)) throw new Error('Attach the current run before its report');
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw new Error('Invalid campaign report');
  const body = readFileSync(path);
  return { artifactDigest: createHash('sha256').update(body).digest('hex'), summary: { bytes: body.length } };
}

export function openCampaign(folder: string, target: string) {
  strictUrl(target);
  const out = resolve(folder); mkdirSync(dirname(out), { recursive: true }); mkdirSync(out);
  const value: Manifest = { schemaVersion: 1, id: randomUUID(), target, createdAt: new Date().toISOString() };
  writeEnvelope(join(out, 'manifest.json'), 'manifest', value);
  writeEnvelope(join(out, 'events.json'), 'events', []);
  return { campaign: out, target, requestsSent: 0, next: 'Attach a shared-budget scope and record the official policy review.' };
}
export function preparePolicyReview(folder: string, sourceUrl: string, sourceKind: Review['sourceKind'],
  operatorDecision: Review['operatorDecision']) {
  const base = realpathSync(folder), records = events(base), scopeEvent = latest(records, 'scope');
  manifest(base);
  if (!scopeEvent || latest(records, 'policy')) throw new Error('Attach scope before preparing one policy review');
  const source = new URL(sourceUrl);
  if (source.protocol !== 'https:' || source.username || source.password || source.hash
    || !['official-program-policy', 'owner-written-authorization'].includes(sourceKind)
    || !['authorized', 'uncertain'].includes(operatorDecision)) throw new Error('Invalid policy review inputs');
  const scope = readJson(scopeEvent.artifact) as Scope; validateScope(scope);
  const review: ReviewWithSource = { schemaVersion: 2, sourceUrl, reviewedAt: new Date().toISOString(),
    scopeDigest: scopeEvent.artifactDigest, authorizationReference: scope.authorization.reference,
    sourceKind, operatorDecision, sourceFile: 'policy-source.txt', sourceSha256: policySource(base) };
  const out = join(base, 'policy.json');
  writeFileSync(out, JSON.stringify(review, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { policy: out, sourceSha256: review.sourceSha256, operatorDecision,
    permissionVerifiedByTool: false, next: 'Review the saved source and link policy.json to the campaign.' };
}
export function linkCampaign(folder: string, kind: string, input: string) {
  if (!kinds.includes(kind as Kind)) throw new Error('Unsupported campaign artifact kind');
  const base = realpathSync(folder), path = realpathSync(input), lockPath = join(base, '.campaign.lock');
  const rel = relative(base, path);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw new Error('Campaign artifact must be inside its folder');
  const fd = openSync(lockPath, 'wx', 0o600);
  try {
    const state = manifest(base), records = events(base), selected = kind as Kind;
    if (['scope', 'policy'].includes(kind) && latest(records, selected)) throw new Error('Campaign artifact is immutable');
    const validated = artifact(path, selected, state.target, records);
    if (records.some(e => e.kind === selected && e.artifact === path && e.artifactDigest === validated.artifactDigest))
      throw new Error('Campaign artifact already linked');
    if (records.length >= 100) throw new Error('Campaign event limit reached');
    const previousHash = records.at(-1)?.hash ?? '', sequence = records.length + 1, at = new Date().toISOString();
    const head = { sequence, at, kind: selected, artifact: path, ...validated, previousHash };
    const event: Event = { ...head, hash: digest(head) };
    writeEnvelope(join(base, 'events.json'), 'events', [...records, event], true);
    return { campaign: base, sequence, kind: selected, artifactDigest: validated.artifactDigest, revision: event.hash };
  } finally { closeSync(fd); unlinkSync(lockPath); }
}
export function campaignStatus(folder: string) {
  const base = realpathSync(folder), state = manifest(base), records = events(base);
  // Validate every retained source on read; changed artifacts cannot silently keep their old conclusions.
  for (const record of records) {
    const real = realpathSync(record.artifact), rel = relative(base, real);
    if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw new Error('Campaign artifact escaped its folder');
    const previous = records.slice(0, record.sequence - 1);
    if (scopeExpired(previous) && (record.kind === 'profile' || record.kind === 'run')) {
      const value = record.kind === 'profile' ? readJson(real) : inspectSession(real);
      if (digest(value) !== record.artifactDigest) throw new Error('Linked campaign artifact changed');
      continue;
    }
    const current = artifact(real, record.kind, state.target, previous);
    if (current.artifactDigest !== record.artifactDigest || canonical(current.summary) !== canonical(record.summary))
      throw new Error('Linked campaign artifact changed');
  }
  const scopeEvent = latest(records, 'scope'), policyEvent = latest(records, 'policy');
  const surfaceEvent = latest(records, 'surface'), pageEvent = latest(records, 'page');
  const profileEvent = latest(records, 'profile'), runEvent = latest(records, 'run'), reportEvent = latest(records, 'report');
  const scope = scopeEvent ? readJson(scopeEvent.artifact) as Scope : null;
  let budget: ReturnType<typeof inspectBudget> | null = null;
  if (scope?.budgetId) {
    const budgetFolder = join(dirname(scopeEvent!.artifact), '.bba-budgets', scope.budgetId);
    if (existsSync(budgetFolder)) budget = inspectBudget(budgetFolder);
  }
  let next: string, blockers: string[] = [];
  if (!scope) next = 'Create and attach a canonical scope with a shared budget ID.';
  else if (!policyEvent) next = 'Review official policy or owner authorization and attach a policy review record.';
  else if (policyEvent.summary.decision !== 'authorized') { next = 'Resolve program authorization before active requests.'; blockers.push('policy-uncertain'); }
  else if (!surfaceEvent && !pageEvent) next = 'Inspect the exact authorized page or import a saved API surface.';
  else if (!surfaceEvent) next = 'Import or attach an API surface; DOM paths alone are not executable hypotheses.';
  else if (!profileEvent || profileEvent.sequence < surfaceEvent.sequence) next = 'Bind controlled identities and business rules to the latest imported surface.';
  else if (profileEvent.summary.planned === 0) next = 'Revise the profile or surface; no testable semantic checks were compiled.';
  else if (!runEvent || runEvent.sequence < profileEvent.sequence) next = 'Plan and execute the bounded semantic investigation with the canonical scope.';
  else if (!reportEvent || reportEvent.sequence < runEvent.sequence) next = 'Generate and review a report from the verified run.';
  else next = 'Review the draft, scope, impact and disclosure program before submission.';
  if (budget?.uncertainRequests) blockers.push('uncertain-request-reservations');
  if (scope && Date.parse(scope.authorization.validUntil) <= Date.now()) blockers.push('authorization-window-expired');
  const captureAttempt = join(base, 'actions', 'capture');
  const investigationAttempt = profileEvent ? join(base, 'actions', `investigation-${profileEvent.sequence}`) : null;
  if ((existsSync(captureAttempt) && !pageEvent)
    || (investigationAttempt && existsSync(investigationAttempt) && (!runEvent || runEvent.sequence < profileEvent!.sequence))) {
    blockers.push('interrupted-action');
    next = 'Inspect the saved action output and budget before any further requests; do not repeat an uncertain action.';
  }
  return { schemaVersion: 1, campaign: base, target: state.target, revision: records.at(-1)?.hash ?? digest(state),
    linked: records.map(event => ({ sequence: event.sequence, kind: event.kind, artifact: event.artifact, summary: event.summary })),
    budget: budget ? { reservedRequests: budget.reservedRequests, uncertainRequests: budget.uncertainRequests } : null,
    blockers, next, policySourceBound: policyEvent?.summary.sourceBound === true,
    claims: { ownerPermissionVerifiedByTool: false, vulnerabilityConfirmedByCampaign: false } };
}

function activeInputs(folder: string, allowInterrupted = false): { base: string; records: Event[]; scope: Scope; scopePath: string; target: string } {
  const status = campaignStatus(folder);
  const blockers = status.blockers.filter(item => item !== 'interrupted-action' || !allowInterrupted);
  if (blockers.length) throw new Error('Campaign blocked: ' + blockers.join(', '));
  const base = status.campaign, records = events(base), scopeEvent = latest(records, 'scope');
  const policyEvent = latest(records, 'policy');
  if (!scopeEvent || !policyEvent || policyEvent.summary.decision !== 'authorized')
    throw new Error('Attach an authorized policy review and canonical scope before active requests');
  const scope = readJson(scopeEvent.artifact) as Scope;
  assertAuthorized(scope, status.target);
  return { base, records, scope, scopePath: scopeEvent.artifact, target: status.target };
}

export async function campaignCapture(folder: string, signal?: AbortSignal) {
  const { base, records, scope, scopePath, target } = activeInputs(folder);
  if (latest(records, 'page')) throw new Error('Campaign page capture already linked; inspect its saved facts');
  const plan = { schemaVersion: 1 as const, steps: [{ id: 'seed', method: 'GET' as const, url: target, credentialEnv: null }] };
  const action = join(base, 'actions', 'capture');
  mkdirSync(dirname(action), { recursive: true }); mkdirSync(action);
  writeFileSync(join(action, 'started.json'), JSON.stringify({ at: new Date().toISOString(), campaignRevision: records.at(-1)?.hash ?? null,
    target, action: 'capture' }, null, 2), { flag: 'wx', mode: 0o600 });
  const output = join(action, 'output');
  const result = await usingScopeBudget(scope, scopePath, budget => captureSurface(output, scope, plan, { budget, signal }));
  linkCampaign(base, 'page', output);
  const surfacePath = join(output, 'surface.json');
  try { linkCampaign(base, 'surface', surfacePath); } catch (error) {
    if (result.surface.entries.length) throw error;
  }
  return { campaign: base, output, requests: result.capture.counts.sent, stopped: result.capture.stopReason,
    pageFacts: result.pages.pages.length, surfaceEntries: result.surface.entries.length, next: campaignStatus(base).next };
}

export async function campaignExecute(folder: string, signal?: AbortSignal) {
  const { base, records, scope, scopePath } = activeInputs(folder);
  const surfaceEvent = latest(records, 'surface'), profileEvent = latest(records, 'profile'), runEvent = latest(records, 'run');
  if (!surfaceEvent || !profileEvent || profileEvent.sequence < surfaceEvent.sequence || profileEvent.summary.planned === 0)
    throw new Error('Attach a current profile with executable checks before investigation');
  if (runEvent && runEvent.sequence > profileEvent.sequence) throw new Error('Campaign investigation already linked for this profile');
  const action = join(base, 'actions', `investigation-${profileEvent.sequence}`);
  mkdirSync(dirname(action), { recursive: true }); mkdirSync(action);
  writeFileSync(join(action, 'started.json'), JSON.stringify({ at: new Date().toISOString(), campaignRevision: records.at(-1)?.hash ?? null,
    action: 'investigation', profileDigest: profileEvent.artifactDigest, surfaceDigest: surfaceEvent.artifactDigest }, null, 2),
    { flag: 'wx', mode: 0o600 });
  const output = join(action, 'output');
  const result = await usingScopeBudget(scope, scopePath, budget => investigateSurface(output, scope,
    readJson(surfaceEvent.artifact), readJson(profileEvent.artifact), { budget, signal }));
  const run = inspectSession(join(output, 'run'));
  if (run.status === 'completed' || (run.status === 'stopped' && run.stopReason === 'proof-complete')) {
    linkCampaign(base, 'run', join(output, 'run'));
    linkCampaign(base, 'report', join(output, 'report.md'));
  }
  return { campaign: base, output, ...result, runStatus: run.status, next: campaignStatus(base).next };
}

export async function campaignResume(folder: string, signal?: AbortSignal) {
  const { base, records, scope, scopePath } = activeInputs(folder, true);
  const surfaceEvent = latest(records, 'surface'), profileEvent = latest(records, 'profile'), runEvent = latest(records, 'run');
  if (!surfaceEvent || !profileEvent || profileEvent.sequence < surfaceEvent.sequence
    || (runEvent && runEvent.sequence > profileEvent.sequence)) throw new Error('No current interrupted investigation');
  const action = join(base, 'actions', `investigation-${profileEvent.sequence}`), output = join(action, 'output');
  if (!existsSync(join(action, 'started.json')) || !existsSync(join(output, 'run')))
    throw new Error('No checkpointed campaign run to resume');
  const before = inspectSession(join(output, 'run'));
  const compiled = compileInvestigation(scope, readJson(surfaceEvent.artifact), readJson(profileEvent.artifact));
  if (digest(before.scope) !== digest(scope) || !compiled.plan || digest(before.plan) !== digest(compiled.plan))
    throw new Error('Interrupted run differs from current campaign definition');
  const originalReport = join(output, 'report.md'), resumedReport = join(output, 'report-resumed.md');
  if (before.status === 'completed' || (before.status === 'stopped' && before.stopReason === 'proof-complete')) {
    if (!existsSync(originalReport) && !existsSync(resumedReport)) throw new Error('Terminal run needs a saved report');
    linkCampaign(base, 'run', join(output, 'run'));
    linkCampaign(base, 'report', existsSync(resumedReport) ? resumedReport : originalReport);
    return { campaign: base, output, requests: before.attempts.length, newRequests: 0,
      stopped: before.stopReason, runStatus: before.status, next: campaignStatus(base).next };
  }
  if (before.status !== 'paused') throw new Error('Only a paused checkpoint can resume');
  if (existsSync(resumedReport)) throw new Error('Resumed report already exists; inspect it before continuing');
  const result = await usingScopeBudget(scope, scopePath, budget => resumeInvestigation(output, scope, resumedReport, { budget, signal }));
  const after = inspectSession(join(output, 'run'));
  if (after.status === 'completed' || (after.status === 'stopped' && after.stopReason === 'proof-complete')) {
    linkCampaign(base, 'run', join(output, 'run'));
    linkCampaign(base, 'report', resumedReport);
  }
  return { campaign: base, output, ...result, runStatus: after.status, next: campaignStatus(base).next };
}

function scopeExpired(records: Event[]): boolean {
  const event = latest(records, 'scope');
  if (!event) return false;
  const value = readJson(event.artifact); validateScope(value);
  return Date.parse(value.authorization.validUntil) <= Date.now();
}
