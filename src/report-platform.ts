import { existsSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { digest } from './contracts.ts';
import { fields } from './scope.ts';
import type { Step } from './scope.ts';
import { inspectSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { Lang } from './i18n.ts';

export type SubmissionPlatform = 'hackerone' | 'bugcrowd' | 'ghsa';

export type CvssBaseline = {
  v31Vector: string;
  v31Score: number;
  v40Vector: string;
  v40Score: number;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
};

type Cvss31Metrics = {
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'N' | 'L' | 'H';
  I: 'N' | 'L' | 'H';
  A: 'N' | 'L' | 'H';
};

function roundUp1(val: number): number {
  const intInput = Math.round(val * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function calculateCvss31(m: Cvss31Metrics): { vector: string; score: number; severity: CvssBaseline['severity'] } {
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const ac = { L: 0.77, H: 0.44 }[m.AC];
  const pr = m.S === 'U'
    ? { N: 0.85, L: 0.62, H: 0.27 }[m.PR]
    : { N: 0.85, L: 0.68, H: 0.5 }[m.PR];
  const ui = { N: 0.85, R: 0.62 }[m.UI];
  const c = { N: 0, L: 0.22, H: 0.56 }[m.C];
  const i = { N: 0, L: 0.22, H: 0.56 }[m.I];
  const a = { N: 0, L: 0.22, H: 0.56 }[m.A];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = m.S === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;
  const score = impact <= 0
    ? 0
    : m.S === 'U'
      ? roundUp1(Math.min(impact + exploitability, 10))
      : roundUp1(Math.min(1.08 * (impact + exploitability), 10));
  const severity: CvssBaseline['severity'] = score >= 9.0 ? 'Critical' : score >= 7.0 ? 'High' : score >= 4.0 ? 'Medium' : 'Low';
  const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
  return { vector, score, severity };
}

function deriveCvssBaseline(vulnClass: string, isWrite = false): CvssBaseline {
  let m: Cvss31Metrics;
  let v40Vector: string;
  let v40Score: number;

  if (isWrite || vulnClass === 'mass-assignment') {
    m = { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'N', I: 'H', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N';
    v40Score = 7.1;
  } else if (vulnClass === 'bola' || vulnClass === 'bfla' || vulnClass === 'tenant-isolation' || vulnClass === 'graphql-authorization') {
    m = { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N';
    v40Score = 7.1;
  } else if (vulnClass === 'property-exposure' || vulnClass === 'cross-identity-cache') {
    m = { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N';
    v40Score = 5.3;
  } else if (vulnClass === 'jwt-signature-integrity') {
    m = { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N';
    v40Score = 7.3;
  } else if (vulnClass === 'single-use-race') {
    m = { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N';
    v40Score = 2.3;
  } else if (vulnClass === 'xss' || vulnClass === 'open-redirect' || vulnClass === 'oauth-flow-conformance') {
    m = { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N';
    v40Score = 5.1;
  } else if (vulnClass === 'cors') {
    m = { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'N', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N';
    v40Score = 6.9;
  } else {
    // cross-origin-form, template-arithmetic, outbound-fetch
    m = { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' };
    v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N';
    v40Score = 5.3;
  }
  const v31 = calculateCvss31(m);
  return {
    v31Vector: v31.vector,
    v31Score: v31.score,
    v40Vector,
    v40Score,
    severity: v31.severity,
  };
}

function renderRedactedCurl(step: Step): string {
  const parts = [`curl -i -sS -X ${step.method}`];
  if (step.credentialEnv) {
    if (step.credentialEnv.startsWith('BBA_COOKIE_')) {
      parts.push(`-H "Cookie: \$${step.credentialEnv}"`);
    } else {
      parts.push(`-H "Authorization: Bearer \$${step.credentialEnv}"`);
    }
  }
  let url = step.url;
  if (step.query?.length) {
    const qs = step.query.map(q => `${encodeURIComponent(q.name)}=\$${q.valueEnv}`).join('&');
    url += (url.includes('?') ? '&' : '?') + qs;
  }
  if (step.body) {
    const ct = step.body.format === 'json' ? 'application/json' : step.body.format === 'form' ? 'application/x-www-form-urlencoded' : 'text/plain';
    parts.push(`-H "Content-Type: ${ct}"`);
    parts.push(`--data-raw "\$${step.body.valueEnv}"`);
  }
  parts.push(`"${url}"`);
  return `# Step: ${step.id}\n` + parts.join(' \\\n  ');
}

const candidateResultFiles = [
  'semantic.json',
  'result.json',
  'graphql-check.json',
  'oauth-check.json',
  'redirect-check.json',
  'race-check.json',
  'csrf-check.json',
  'template-check.json',
  'ssrf-callback.json',
  'cache-check.json',
  'browser-check.json',
  'hunt.json',
];

function loadVerifiedArtifact(artifactPath: string): { result: Record<string, any>; session: Session | null } {
  let jsonFile = artifactPath;
  let session: Session | null = null;
  if (statSync(artifactPath).isDirectory()) {
    const found = candidateResultFiles.find(name => existsSync(join(artifactPath, name)));
    if (!found) throw new Error('No verified BBA result JSON found in directory');
    jsonFile = join(artifactPath, found);
    if (existsSync(join(artifactPath, 'run', 'session.sqlite'))) {
      session = inspectSession(join(artifactPath, 'run'));
    } else if (existsSync(join(artifactPath, 'session.sqlite'))) {
      session = inspectSession(artifactPath);
    }
  }
  const envelope = readJson(jsonFile);
  fields(envelope, ['result', 'sha256']);
  if (envelope.sha256 !== digest(envelope.result)) {
    throw new Error('Result integrity mismatch');
  }
  return { result: envelope.result as Record<string, any>, session };
}

export function exportSubmission(
  artifactPath: string,
  platform: SubmissionPlatform,
  outputPath: string,
  options: { runPath?: string; lang?: Lang } = {},
): { platform: SubmissionPlatform; status: string; vulnClass: string; cvss: CvssBaseline | null } {
  const lang = options.lang ?? 'es';
  const loaded = loadVerifiedArtifact(artifactPath);
  const session = options.runPath ? inspectSession(options.runPath) : loaded.session;
  const r = loaded.result;

  let status = 'unresolved';
  let vulnClass = 'unknown';
  let targetUrl = '(declarado en artefacto)';
  let reason = '';
  let evidenceIds: string[] = [];
  let limitations: string[] = Array.isArray(r.limitations) ? r.limitations : Array.isArray(r.limitation) ? r.limitation : [];
  let isWrite = false;

  if (Array.isArray(r.findings)) {
    const primary = r.findings.find((f: any) => f.status === 'confirmed') ?? r.findings[0];
    if (!primary) throw new Error('Artifact contains zero findings');
    status = String(primary.status);
    vulnClass = String(primary.class ?? 'bola');
    targetUrl = String(primary.url ?? targetUrl);
    reason = String(primary.reason ?? '');
    evidenceIds = Array.isArray(primary.evidence) ? primary.evidence : [];
    if (session && primary.probe) {
      const pStep = session.plan.steps.find(s => s.id === primary.probe);
      if (pStep && pStep.method !== 'GET') isWrite = true;
    } else if (reason.includes('mutated')) {
      isWrite = true;
    }
  } else {
    status = String(r.status ?? 'unresolved');
    vulnClass = String(r.class ?? (r.configDigest && r.sessionId ? 'jwt-signature-integrity' : 'unknown'));
    reason = String(r.reason ?? `Outcome status: ${status}.`);
    evidenceIds = Array.isArray(r.evidence) ? r.evidence : [];
    if (session?.plan.steps.length) {
      targetUrl = session.plan.steps.at(-1)!.url;
    }
  }

  const cvss = status === 'confirmed' ? deriveCvssBaseline(vulnClass, isWrite) : null;
  const curlBlock = session
    ? session.plan.steps.map(renderRedactedCurl).join('\n\n')
    : `# Redacted reproduction uses environment placeholders ($BBA_TOKEN_*, $BBA_COOKIE_*, $BBA_INPUT_*, $BBA_BODY_*).\n# Inspect config.json and requests.jsonl in the sealed artifact directory.`;

  const cvssSectionEs = cvss
    ? `- **Severidad base orientativa**: ${cvss.severity}\n- **CVSS v3.1**: \`${cvss.v31Vector}\` (${cvss.v31Score})\n- **CVSS v4.0**: \`${cvss.v40Vector}\` (${cvss.v40Score})\n- *Nota*: Vector calculado de forma conservadora a partir de la clase probada (\`${vulnClass}\`); ajustá según sensibilidad real del activo y reglas del programa.`
    : `- **CVSS**: No asignado (el estado verificado es \`${status}\`, no \`confirmed\`). BBA no asigna severidad sin prueba positiva con controles negativos.`;
  const cvssSectionEn = cvss
    ? `- **Conservative Baseline Severity**: ${cvss.severity}\n- **CVSS v3.1**: \`${cvss.v31Vector}\` (${cvss.v31Score})\n- **CVSS v4.0**: \`${cvss.v40Vector}\` (${cvss.v40Score})\n- *Note*: Vector derived conservatively from proven class (\`${vulnClass}\`); adjust for real data sensitivity and program policy.`
    : `- **CVSS**: Unassigned (verified status is \`${status}\`, not \`confirmed\`). BBA never assigns severity without positive proof and negative controls.`;

  let md: string;
  if (platform === 'hackerone') {
    md = lang === 'en'
      ? `# [BBA Draft — HackerOne] ${vulnClass} (${status})\n\n## Summary\n\nTarget: \`${targetUrl}\`\nVerified outcome: **${status}**. ${reason}\n\n## Severity & CVSS Baseline\n\n${cvssSectionEn}\n\n## Steps To Reproduce (Redacted)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n## Supporting Material / Evidence IDs\n\n${evidenceIds.map(id => `- \`${id}\``).join('\n') || '- Retained in BBA artifact'}\n\n## Impact & Limitations\n\n${limitations.map(l => `- ${l}`).join('\n')}\n`
      : `# [Borrador BBA — HackerOne] ${vulnClass} (${status})\n\n## Summary / Resumen\n\nActivo: \`${targetUrl}\`\nResultado verificado: **${status}**. ${reason}\n\n## Severidad y línea base CVSS\n\n${cvssSectionEs}\n\n## Steps To Reproduce (Redactado sin secretos)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n## Evidencia retenida\n\n${evidenceIds.map(id => `- \`${id}\``).join('\n') || '- Retenida en artefacto BBA'}\n\n## Impacto y límites\n\n${limitations.map(l => `- ${l}`).join('\n')}\n`;
  } else if (platform === 'bugcrowd') {
    md = lang === 'en'
      ? `# [BBA Draft — Bugcrowd] ${vulnClass} (${status})\n\n## VRT & CVSS Baseline\n\n${cvssSectionEn}\n\n## Description\n\nTarget: \`${targetUrl}\`\n${reason}\n\n## Proof of Concept (Redacted)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n## Evidence & Limitations\n\n${evidenceIds.map(id => `- \`${id}\``).join('\n')}\n${limitations.map(l => `- ${l}`).join('\n')}\n`
      : `# [Borrador BBA — Bugcrowd] ${vulnClass} (${status})\n\n## Línea base VRT y CVSS\n\n${cvssSectionEs}\n\n## Descripción\n\nActivo: \`${targetUrl}\`\n${reason}\n\n## Prueba de concepto (Redactada)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n## Evidencia y límites\n\n${evidenceIds.map(id => `- \`${id}\``).join('\n')}\n${limitations.map(l => `- ${l}`).join('\n')}\n`;
  } else if (platform === 'ghsa') {
    md = lang === 'en'
      ? `# [BBA Draft — GitHub Security Advisory] ${vulnClass} (${status})\n\n### Summary\n\nTarget: \`${targetUrl}\` — **${status}**. ${reason}\n\n### Severity\n\n${cvssSectionEn}\n\n### PoC (Redacted)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n### Impact & Limitations\n\n${limitations.map(l => `- ${l}`).join('\n')}\n`
      : `# [Borrador BBA — GitHub Security Advisory] ${vulnClass} (${status})\n\n### Resumen\n\nActivo: \`${targetUrl}\` — **${status}**. ${reason}\n\n### Severidad\n\n${cvssSectionEs}\n\n### PoC (Redactada)\n\n\`\`\`bash\n${curlBlock}\n\`\`\`\n\n### Impacto y límites\n\n${limitations.map(l => `- ${l}`).join('\n')}\n`;
  } else {
    throw new Error('Unsupported submission platform');
  }

  writeFileSync(outputPath, md, { flag: 'wx', mode: 0o600 });
  return { platform, status, vulnClass, cvss };
}

