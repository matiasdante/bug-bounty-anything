import { writeFileSync } from 'node:fs';
import { digest } from './contracts.ts';
import { fields } from './scope.ts';
import { inspectSession, readJson } from './session.ts';
import type { Session } from './session.ts';

export const checkClasses = ['bola', 'bfla', 'property-exposure'] as const;
type CheckClass = typeof checkClasses[number];
export type Check = { id: string; class: CheckClass; control: string; baseline: string; probe: string };
export type Checks = { schemaVersion: 1; checks: Check[] };
type Ref = { stepId: string; status: number | null; sha256: string | null };
export type Finding = {
  checkId: string; class: CheckClass; status: 'confirmed' | 'not-reproduced' | 'unresolved';
  observation: string; steps: { control: Ref; baseline: Ref; probe: Ref }; limitation: string;
};
export type Evaluation = {
  schemaVersion: 1; toolVersion: '0.6.0'; sessionId: string; scopeDigest: string; checksDigest: string;
  sessionStatus: Session['status']; findings: Finding[];
};

const limitations: Record<CheckClass, string> = {
  bola: 'Only this read between the two supplied identities was compared by response hash. Ownership of the baseline is asserted by the operator, not verified. No write, enumeration or broader coverage is established.',
  bfla: 'Only this GET was compared between the two supplied identities. Their roles are asserted by the operator, not verified. Other functions, methods and roles are untested.',
  'property-exposure': 'Only whole-response equality with the privileged baseline was tested. A different response does not prove that no privileged property is exposed.',
};

// The structure is what makes a check meaningful: the control must be anonymous,
// the baseline and probe must be different authenticated identities, and all three
// must read the same URL.
export function validateChecks(value: unknown, session: Session): asserts value is Checks {
  fields(value, ['schemaVersion', 'checks']);
  if (value.schemaVersion !== 1 || !Array.isArray(value.checks) || !value.checks.length || value.checks.length > 50) throw new Error('Invalid checks');
  const steps = new Map(session.plan.steps.map(s => [s.id, s]));
  const ids = new Set();
  for (const check of value.checks) {
    fields(check, ['id', 'class', 'control', 'baseline', 'probe']);
    if (typeof check.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(check.id) || ids.has(check.id)) throw new Error('Invalid check ID');
    ids.add(check.id);
    if (!checkClasses.includes(check.class)) throw new Error('Unsupported check class');
    const [control, baseline, probe] = [check.control, check.baseline, check.probe].map(id => steps.get(id));
    if (!control || !baseline || !probe || new Set([check.control, check.baseline, check.probe]).size !== 3) throw new Error('Check steps must be three distinct plan steps');
    if (control.credentialEnv !== null || !baseline.credentialEnv || !probe.credentialEnv
      || baseline.credentialEnv === probe.credentialEnv) throw new Error('Check identities do not form a control and two distinct credentials');
    if (control.url !== baseline.url || baseline.url !== probe.url) throw new Error('Check steps must read the same URL');
  }
}

export function evaluateChecks(session: Session, value: unknown): Evaluation {
  validateChecks(value, session);
  const ref = (stepId: string): Ref => {
    const attempt = session.attempts.find(a => a.stepId === stepId && a.outcome === 'succeeded');
    return { stepId, status: attempt?.response?.status ?? null, sha256: attempt?.response?.sha256 ?? null };
  };
  const findings = value.checks.map((check): Finding => {
    const control = ref(check.control), baseline = ref(check.baseline), probe = ref(check.probe);
    let status: Finding['status'] = 'unresolved', observation: string;
    if (control.status === null || baseline.status === null || probe.status === null) {
      observation = 'A required step has no completed response.';
    } else if (control.status !== 401 && control.status !== 403) {
      observation = 'The anonymous control was not denied, so no authentication boundary was established.';
    } else if (baseline.status !== 200) {
      observation = 'The authorized baseline did not succeed.';
    } else if (probe.status === 200 && probe.sha256 === baseline.sha256) {
      status = 'confirmed';
      observation = 'The probe identity received a response identical to the privileged baseline.';
    } else if (probe.status === 401 || probe.status === 403 || probe.status === 404) {
      status = 'not-reproduced';
      observation = 'The probe identity was denied while the baseline succeeded.';
    } else if (probe.status === 200 && check.class === 'property-exposure') {
      status = 'not-reproduced';
      observation = 'The probe identity received a different response than the privileged baseline; partial exposure is not excluded.';
    } else {
      observation = 'The probe response proved neither identical access nor a denial.';
    }
    return { checkId: check.id, class: check.class, status, observation, steps: { control, baseline, probe }, limitation: limitations[check.class] };
  });
  return { schemaVersion: 1, toolVersion: '0.6.0', sessionId: session.id, scopeDigest: session.scopeDigest,
    checksDigest: digest(value), sessionStatus: session.status, findings };
}

export function evaluationMarkdown(e: Evaluation): string {
  const rows = e.findings.map(f => `| ${f.checkId} | ${f.class} | **${f.status}** | ${f.steps.control.status ?? '-'} / ${f.steps.baseline.status ?? '-'} / ${f.steps.probe.status ?? '-'} | ${f.observation} |`);
  return `# Evaluación de hipótesis

Sesión \`${e.sessionId}\` (${e.sessionStatus}) · scope \`${e.scopeDigest.slice(0, 12)}\` · checks \`${e.checksDigest.slice(0, 12)}\`

| Check | Clase | Estado | Control / baseline / sonda (HTTP) | Observación |
|---|---|---|---|---|
${rows.join('\n')}

## Limitaciones

${[...new Set(e.findings.map(f => f.limitation))].map(l => '- ' + l).join('\n')}
- \`confirmed\` es una comparación de hashes de respuestas HTTP; no mide impacto ni severidad. \`not-reproduced\` no significa seguro y \`unresolved\` no es un resultado negativo.
`;
}

export function evaluateRunFile(folder: string, checksPath: string, output: string): Evaluation {
  const evaluation = evaluateChecks(inspectSession(folder), readJson(checksPath));
  const body = output.endsWith('.md') ? evaluationMarkdown(evaluation)
    : JSON.stringify({ evaluation, sha256: digest(evaluation) }, null, 2) + '\n';
  writeFileSync(output, body, { flag: 'wx', mode: 0o600 });
  return evaluation;
}
