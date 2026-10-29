import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { startLab } from './lab.ts';
import { createSession, exportSession, sessionSummary } from './session.ts';
import { executeSession } from './execution.ts';
import type { Scope, Plan } from './scope.ts';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--out' || !args[1] || args[1].startsWith('--')) {
  console.error('Uso: npm run demo:core -- --out <new-directory>'); process.exitCode = 2;
} else {
  const lab = await startLab('fixed');
  try {
    const output = resolve(args[1]);
    const paths = lab.documents.map(d => '/documents/' + d.id);
    const scope: Scope = {
      schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'BBA-owned demo lab', validFrom: new Date().toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin: lab.origin, paths }], excluded: [],
      limits: { maxRequests: 5, minIntervalMs: 20, timeoutMs: 2000, maxResponseBytes: 4096, maxDurationMs: 60000 },
    };
    const plan: Plan = { schemaVersion: 1, steps: [
      { id: 'anonymous-control', method: 'GET', url: lab.origin + paths[1], credentialEnv: null },
      { id: 'owner-a', method: 'GET', url: lab.origin + paths[0], credentialEnv: 'BBA_TOKEN_A' },
      { id: 'owner-b', method: 'GET', url: lab.origin + paths[1], credentialEnv: 'BBA_TOKEN_B' },
      { id: 'cross-a-to-b', method: 'GET', url: lab.origin + paths[1], credentialEnv: 'BBA_TOKEN_A' },
      { id: 'cross-b-to-a', method: 'GET', url: lab.origin + paths[0], credentialEnv: 'BBA_TOKEN_B' },
    ] };
    createSession(output, scope, plan);
    writeFileSync(join(output, 'scope.json'), JSON.stringify(scope, null, 2) + '\n', { flag: 'wx' });
    writeFileSync(join(output, 'plan.json'), JSON.stringify(plan, null, 2) + '\n', { flag: 'wx' });
    const state = await executeSession(output, scope, {
      credentials: { BBA_TOKEN_A: lab.credentials['account-a'], BBA_TOKEN_B: lab.credentials['account-b'] },
    });
    exportSession(output, join(output, 'export.json'), 'json');
    exportSession(output, join(output, 'report.md'), 'markdown');
    console.log(JSON.stringify({ ...sessionSummary(state), output }, null, 2));
    if (state.status !== 'completed') process.exitCode = 1;
  } catch {
    console.error('No se pudo completar la demo. Revisá la carpeta de salida y el acceso a loopback.'); process.exitCode = 1;
  } finally { await lab.close(); }
}
