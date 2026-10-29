import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Variant } from './contracts.ts';
import { evaluateChecks } from './checks.ts';
import type { Check, Evaluation } from './checks.ts';
import { executeSession } from './execution.ts';
import { startLab } from './lab.ts';
import { startRoleLab } from './role-lab.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, inspectSession } from './session.ts';

export type LabClass = Check['class'];

async function prepare(kind: LabClass, variant: Variant) {
  if (kind === 'bola') {
    const lab = await startLab(variant);
    return { lab, path: '/documents/' + lab.documents[1].id, baselineEnv: 'BBA_TOKEN_B', probeEnv: 'BBA_TOKEN_A',
      tokens: { BBA_TOKEN_A: lab.credentials['account-a'], BBA_TOKEN_B: lab.credentials['account-b'] } };
  }
  const lab = await startRoleLab(variant);
  return { lab, path: kind === 'bfla' ? '/admin/users' : '/profiles/' + lab.profileId, baselineEnv: 'BBA_TOKEN_ADMIN', probeEnv: 'BBA_TOKEN_USER',
    tokens: { BBA_TOKEN_ADMIN: lab.credentials.admin, BBA_TOKEN_USER: lab.credentials.user } };
}

// One control/baseline/probe triple per class against the owned labs. A case spends
// at most three requests (fewer when the budget is lowered) and never leaves 127.0.0.1.
export async function runLabCase(kind: LabClass, variant: Variant, maxRequests = 3): Promise<Evaluation> {
  const { lab, path, baselineEnv, probeEnv, tokens } = await prepare(kind, variant);
  const dir = await mkdtemp(join(tmpdir(), 'bba-case-'));
  try {
    const url = lab.origin + path;
    const scope: Scope = {
      schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'BBA-owned evaluation lab', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin: lab.origin, paths: [path] }], excluded: [],
      limits: { maxRequests, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 },
    };
    const plan: Plan = { schemaVersion: 1, steps: [
      { id: 'control', method: 'GET', url, credentialEnv: null },
      { id: 'baseline', method: 'GET', url, credentialEnv: baselineEnv },
      { id: 'probe', method: 'GET', url, credentialEnv: probeEnv },
    ] };
    const folder = join(dir, 'run');
    createSession(folder, scope, plan);
    await executeSession(folder, scope, { credentials: tokens });
    return evaluateChecks(inspectSession(folder), { schemaVersion: 1, checks: [{ id: kind, class: kind, control: 'control', baseline: 'baseline', probe: 'probe' }] });
  } finally { await lab.close(); await rm(dir, { recursive: true, force: true }); }
}
