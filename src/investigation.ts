import { randomUUID } from 'node:crypto';
import { canonical, evidence } from './contracts.ts';
import type { Actor, Evidence, Finding, Investigation, Variant } from './contracts.ts';
import { startLab } from './lab.ts';
import { labTransport } from './transport.ts';

export function evaluate(evidence: Evidence[]): Finding[] {
  const own = (actor: Actor) => evidence.find(e => e.actor === actor && e.document?.owner === actor && e.status === 200);
  const a = own('account-a');
  const b = own('account-b');
  const anonymous = evidence.find(e => e.actor === 'anonymous');
  const baselinesValid = a && b && a.document!.id !== b.document!.id
    && anonymous?.status === 401 && anonymous.path === b.path;
  return (['account-a', 'account-b'] as const).map(actor => {
    const target = actor === 'account-a' ? b : a;
    const owner = actor === 'account-a' ? 'account-b' : 'account-a';
    // Acquisition is ordered: anonymous, own A, own B, A->B, B->A.
    const probe = evidence[actor === 'account-a' ? 3 : 4];
    let status: Finding['status'] = 'unresolved';
    let observation = 'Baseline or probe did not establish the expected authenticated boundary.';
    if (baselinesValid && target && probe && probe.actor === actor && probe.path === target.path) {
      if (probe.status === 200 && canonical(probe.document) === canonical(target.document)) {
        status = 'confirmed';
        observation = 'The other authenticated account received the complete private synthetic document matching its owner baseline.';
      } else if ((probe.status === 403 || probe.status === 404) && probe.document === null) {
        status = 'not-reproduced';
        observation = 'The cross-account read was denied while both owner baselines succeeded.';
      } else {
        observation = 'The cross-account response did not prove either private-data access or an authorization denial.';
      }
    }
    return {
      id: actor === 'account-a' ? 'bola-a-to-b' : 'bola-b-to-a', actor, owner,
      documentId: probe?.path.slice('/documents/'.length) ?? '', status,
      evidenceIds: [evidence[0], evidence[1], evidence[2], probe].filter(Boolean).map(e => e.id),
      observation,
      limitation: 'Only this read, two synthetic accounts and the recorded conditions were tested. No write, enumeration, production impact or broader coverage is established.',
    };
  });
}

export async function investigateLab(variant: Variant): Promise<Investigation> {
  const lab = await startLab(variant);
  try {
    const paths = lab.documents.map(d => '/documents/' + d.id);
    const get = labTransport(lab.origin, paths);
    const observations = [
      await get(paths[1], 'anonymous'),
      await get(paths[0], 'account-a', lab.credentials['account-a']),
      await get(paths[1], 'account-b', lab.credentials['account-b']),
      await get(paths[1], 'account-a', lab.credentials['account-a']),
      await get(paths[0], 'account-b', lab.credentials['account-b']),
    ].map(evidence);
    return {
      schemaVersion: 1, id: randomUUID(), createdAt: new Date().toISOString(), toolVersion: '0.1.0',
      environment: {
        kind: 'owned-loopback-lab', variant, origin: lab.origin,
        authorization: 'BBA-created disposable lab with synthetic data', paths, requestBudget: 5,
      },
      evidence: observations, findings: evaluate(observations),
    };
  } finally { await lab.close(); }
}
