import { investigateLab } from './investigation.ts';
import { summary } from './report.ts';
import { exportReport, loadInvestigation, requireNewDirectory, saveInvestigation } from './storage.ts';
import { validateScope, validatePlan } from './scope.ts';
import { readJson, createSession, inspectSession, exportSession, sessionSummary } from './session.ts';
import { executeSession } from './execution.ts';
import { importSurfaceFile, surfaceSummary } from './surface.ts';

const help = `BBA 0.3.0 — investigaciones, capturas y superficie

  npm run bba -- lab --variant vulnerable|fixed --out <new-directory>
  npm run bba -- inspect <directory>
  npm run bba -- report <directory> --out <new-file.md>
  npm run bba -- scope-check --scope <scope.json> --plan <plan.json>
  npm run bba -- run --scope <scope.json> --plan <plan.json> --out <new-directory>
  npm run bba -- resume <directory> --scope <same-scope.json>
  npm run bba -- inspect-run <directory>
  npm run bba -- export-run <directory> --out <new-file.json>
  npm run bba -- report-run <directory> --out <new-file.md>
  npm run bba -- import-surface --format har|openapi|rea --input <file.json> --out <new-file.json>

lab crea su propio servidor. run/resume ejecutan GET con un alcance explícito.
Los otros comandos son offline. Ctrl+C pausa una ejecución con checkpoints.
Exit codes: 0 completo, 1 error/detenido, 2 uso inválido, 3 parcial, 130 cancelado.
`;

function options(args: string[], names: string[]): Map<string, string> {
  const parsed = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i]; const value = args[i + 1];
    if (!names.includes(key) || parsed.has(key) || !value || value.startsWith('--')) throw new Error('Invalid arguments');
    parsed.set(key, value);
  }
  if (names.some(name => !parsed.has(name))) throw new Error('Missing arguments');
  return parsed;
}

async function main(args: string[]): Promise<void> {
  const [command, ...rest] = args;
  if (!command || (command === '--help' && !rest.length)) { console.log(help); return; }
  let action: () => Promise<void>;
  try {
    if (command === 'import-surface') {
      const flags = options(rest, ['--format', '--input', '--out']);
      const format = flags.get('--format');
      if (format !== 'har' && format !== 'openapi' && format !== 'rea') throw new Error('Invalid format');
      action = async () => { console.log(JSON.stringify(surfaceSummary(importSurfaceFile(flags.get('--input')!, format, flags.get('--out')!)), null, 2)); };
    } else if (command === 'lab') {
      const flags = options(rest, ['--variant', '--out']);
      const variant = flags.get('--variant');
      if (variant !== 'vulnerable' && variant !== 'fixed') throw new Error('Unknown variant');
      action = async () => {
        const out = await requireNewDirectory(flags.get('--out')!);
        const investigation = await investigateLab(variant);
        await saveInvestigation(out, investigation);
        console.log(JSON.stringify({ ...summary(investigation), output: out }, null, 2));
      };
    } else if (command === 'scope-check' || command === 'run') {
      const flags = options(rest, command === 'run' ? ['--scope', '--plan', '--out'] : ['--scope', '--plan']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const plan = readJson(flags.get('--plan')!); validatePlan(plan, scope);
        if (command === 'scope-check') { console.log('Formato, vigencia y coincidencia con scope válidos; no se verificó el permiso del propietario ni se enviaron solicitudes.'); return; }
        createSession(flags.get('--out')!, scope, plan);
        await runCancellable(flags.get('--out')!, scope);
      };
    } else if (command === 'resume' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--scope']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        await runCancellable(rest[0], scope);
      };
    } else if (command === 'inspect-run' && rest.length === 1 && !rest[0].startsWith('--')) {
      action = async () => { console.log(JSON.stringify(sessionSummary(inspectSession(rest[0])), null, 2)); };
    } else if (['export-run', 'report-run'].includes(command) && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--out']);
      action = async () => { exportSession(rest[0], flags.get('--out')!, command === 'report-run' ? 'markdown' : 'json'); console.log('Evidencia verificada y exportada.'); };
    } else if (command === 'inspect' && rest.length === 1 && !rest[0].startsWith('--')) {
      action = async () => { console.log(JSON.stringify(summary(await loadInvestigation(rest[0])), null, 2)); };
    } else if (command === 'report' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--out']);
      action = async () => { await exportReport(rest[0], flags.get('--out')!); console.log('Reporte verificado y exportado.'); };
    } else throw new Error('Unknown command');
  } catch {
    console.error(help); process.exitCode = 2; return;
  }
  try { await action(); } catch (error) {
    // Do not echo request bodies, credential values or hostile imported content.
    const known = error instanceof Error ? error.message : 'Unknown error';
    const safe = /^[A-Za-z0-9 .;:'()/-]{1,160}$/.test(known) ? known : 'Operation failed; check arguments and local artifact integrity';
    console.error(`BBA: ${safe}`); process.exitCode = 1;
  }
}

async function runCancellable(folder: string, scope: import('./scope.ts').Scope): Promise<void> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const state = await executeSession(folder, scope, { signal: controller.signal });
    console.log(JSON.stringify(sessionSummary(state), null, 2));
    process.exitCode = state.status === 'paused' ? 130 : state.status === 'partial' ? 3 : state.status === 'stopped' ? 1 : 0;
  } finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}

await main(process.argv.slice(2));
