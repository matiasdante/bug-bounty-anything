import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { checkClasses, validateChecks } from './checks.ts';
import type { Checks } from './checks.ts';
import { assertAuthorized, fields, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope, Step } from './scope.ts';
import { readJson } from './session.ts';
import type { Session } from './session.ts';
import type { CandidateSet } from './candidates.ts';

export type CandidatePlanSummary = {
  schemaVersion: 1;
  scopeDigest: string;
  candidatesDigest: string;
  plannedChecks: number;
  plannedRequests: number;
  skipped: { id: string; reason: string }[];
  limitations: string[];
};

export function planCandidates(
  scope: Scope,
  candidatesEnvelope: unknown,
  options: {
    accounts?: [string, string];
    checkClass?: typeof checkClasses[number];
  } = {},
): { summary: CandidatePlanSummary; plan: Plan | null; checks: Checks } {
  validateScope(scope);
  fields(candidatesEnvelope, ['candidates', 'sha256']);
  const set = candidatesEnvelope.candidates as CandidateSet;
  if (!set || typeof set !== 'object' || candidatesEnvelope.sha256 !== digest(set)) {
    throw new Error('Candidate bundle integrity mismatch');
  }
  if (set.scopeDigest !== digest(scope)) {
    throw new Error('Candidate bundle scope digest does not match scope.json');
  }
  const accounts: [string, string] = options.accounts ?? ['BBA_TOKEN_A', 'BBA_TOKEN_B'];
  if (!Array.isArray(accounts) || accounts.length !== 2 || accounts[0] === accounts[1]
    || accounts.some(a => typeof a !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(a))) {
    throw new Error('Invalid candidate planner accounts');
  }
  const checkClass = options.checkClass ?? 'bola';
  if (!checkClasses.includes(checkClass)) throw new Error('Invalid candidate check class');

  const steps: Step[] = [];
  const checks: Checks = { schemaVersion: 1, checks: [] };
  const skipped: { id: string; reason: string }[] = [];
  const seenUrls = new Set<string>();
  const maxSteps = Math.min(scope.limits.maxRequests, 99);

  for (const c of set.candidates) {
    if (c.scopeStatus !== 'in-scope') {
      skipped.push({ id: c.id, reason: `Candidate scopeStatus is ${c.scopeStatus}.` });
      continue;
    }
    if (c.kind !== 'endpoint' || !c.origin || !c.path) {
      skipped.push({ id: c.id, reason: 'Host-only candidates are never resolved or probed automatically.' });
      continue;
    }
    const method = c.method ?? 'GET';
    if (method !== 'GET') {
      skipped.push({ id: c.id, reason: `Candidate method ${method} requires explicit disposable-resource write configuration.` });
      continue;
    }
    if (c.hasQuery) {
      skipped.push({ id: c.id, reason: 'Candidate had query parameters requiring explicit BBA_INPUT_* bindings.' });
      continue;
    }
    const url = c.origin + c.path;
    if (seenUrls.has(url)) {
      skipped.push({ id: c.id, reason: 'Duplicate target URL already planned.' });
      continue;
    }
    try {
      assertAuthorized(scope, url, Date.parse(scope.authorization.validFrom));
    } catch {
      skipped.push({ id: c.id, reason: 'URL failed strict canonical scope verification.' });
      continue;
    }
    if (steps.length + 3 > maxSteps || checks.checks.length >= 50) {
      skipped.push({ id: c.id, reason: 'Insufficient scope maxRequests budget for another three-step comparison.' });
      continue;
    }
    seenUrls.add(url);
    const shortId = 'cand-' + digest({ url, checkClass }).slice(0, 16);
    const triple: Step[] = [
      { id: `${shortId}-control`, method: 'GET', url, credentialEnv: null },
      { id: `${shortId}-baseline`, method: 'GET', url, credentialEnv: accounts[0] },
      { id: `${shortId}-probe`, method: 'GET', url, credentialEnv: accounts[1] },
    ];
    steps.push(...triple);
    checks.checks.push({
      id: shortId,
      class: checkClass,
      control: triple[0].id,
      baseline: triple[1].id,
      probe: triple[2].id,
    });
  }

  let plan: Plan | null = null;
  if (steps.length > 0) {
    plan = { schemaVersion: 1, steps };
    validatePlan(plan, scope, false);
    validateChecks(checks, { plan } as Session);
  }

  const summary: CandidatePlanSummary = {
    schemaVersion: 1,
    scopeDigest: digest(scope),
    candidatesDigest: candidatesEnvelope.sha256,
    plannedChecks: checks.checks.length,
    plannedRequests: steps.length,
    skipped,
    limitations: [
      'Scanner candidates are unvalidated leads; compiled checks test bounded three-step GET authorization differentials only.',
      'Hash-level matches from evaluate-run produce needs-validation leads until verified with semantic identity/field projections.',
    ],
  };
  return { summary, plan, checks };
}

export function planCandidatesFile(
  scopePath: string,
  candidatesPath: string,
  outDir: string,
  options: { accounts?: [string, string]; checkClass?: typeof checkClasses[number] } = {},
): CandidatePlanSummary {
  const scope = readJson(scopePath);
  validateScope(scope);
  const envelope = readJson(candidatesPath);
  const { summary, plan, checks } = planCandidates(scope, envelope, options);
  mkdirSync(dirname(outDir), { recursive: true });
  mkdirSync(outDir);
  if (plan) {
    writeFileSync(join(outDir, 'plan.json'), JSON.stringify(plan, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  writeFileSync(join(outDir, 'checks.draft.json'), JSON.stringify(checks, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(outDir, 'candidate-plan.json'), JSON.stringify({ summary, sha256: digest(summary) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return summary;
}

