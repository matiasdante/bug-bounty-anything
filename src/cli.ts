import { investigateLab } from './investigation.ts';
import { summary } from './report.ts';
import { exportReport, loadInvestigation, requireNewDirectory, saveInvestigation } from './storage.ts';
import { assertAuthorized, validateScope, validatePlan } from './scope.ts';
import { readJson, createSession, inspectSession, exportSession, sessionSummary } from './session.ts';
import { executeSession } from './execution.ts';
import { importSurfaceFile, surfaceSummary } from './surface.ts';
import { captureSurface, readPageSurface } from './capture.ts';
import { evaluateRunFile } from './checks.ts';
import { candidateSummary, importCandidatesFile } from './candidates.ts';
import { doctor } from './doctor.ts';
import { evaluationFile } from './evaluation.ts';
import { serveMcp } from './mcp.ts';
import { resolve } from 'node:path';
import { hunt, validateHunt } from './hunt.ts';
import { prepareInvestigation, startCase } from './prepare.ts';
import { installSkill } from './install.ts';
import { capabilities } from './capabilities.ts';
import { evaluateSemanticFile } from './semantic.ts';
import { evidenceViewFile, exportComparison } from './evidence.ts';
import { prepareCompiled, investigateSurface, resumeInvestigation } from './planner.ts';
import { browserCheck, validateBrowserCheck } from './browser-checks.ts';
import { usingScopeBudget, inspectBudget } from './budget.ts';
import type { ProgramBudget } from './budget.ts';
import { captureScenario, validateScenario } from './browser-scenario.ts';
import { artifactView } from './artifacts.ts';
import { evaluateJwtIntegrityFile, jwtIntegrityCheck, validateJwtIntegrity } from './jwt-integrity.ts';
import { assembleStudyBundle, compileStudy, executeStudy, prepareStudy, validateStudyBundle } from './study.ts';
import { join } from 'node:path';
import { setupCodexMcp } from './mcp-setup.ts';
import { openCampaign, linkCampaign, campaignStatus, campaignCapture, campaignExecute, campaignResume, preparePolicyReview } from './campaign.ts';
import { templateCheck, resumeTemplateCheck, validateTemplateCheck } from './template-check.ts';
import { ssrfCallbackCheck, resumeSsrfCallbackCheck, validateSsrfCallback } from './ssrf-callback.ts';
import { cacheCheck, resumeCacheCheck, validateCacheCheck } from './cache-check.ts';
import { raceCheck, validateRaceCheck } from './race-check.ts';
import { csrfCheck, validateCsrfCheck } from './csrf-check.ts';
import { safeErrorMessage } from './contracts.ts';

import pkg from '../package.json' with { type: 'json' };

const help = `BBA ${pkg.version} — investigaciones, capturas y superficie

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
  npm run bba -- evaluate-run <directory> --checks <checks.json> --out <new-file.json|.md>
  npm run bba -- import-candidates --format zap|nuclei|subfinder --input <file> --scope <scope.json> --out <new-file.json>
  npm run bba -- doctor
  npm run bba -- start-case --target <canonical-service-url> --out <new-directory>
  npm run bba -- campaign-open --target <canonical-service-url> --out <new-directory>
  npm run bba -- campaign-link --campaign <directory> --kind scope|policy|surface|page|profile|run|report --artifact <path>
  npm run bba -- campaign-status <directory>
  npm run bba -- campaign-policy-review --campaign <directory> --source-url <https-url> --source-kind official-program-policy|owner-written-authorization --decision authorized|uncertain
  npm run bba -- campaign-capture <directory>
  npm run bba -- campaign-execute <directory>
  npm run bba -- campaign-resume <directory>
  npm run bba -- capabilities
  npm run bba -- inspect-budget <budget-directory>
  npm run bba -- plan-investigation --scope <scope.json> --surface <surface.json> --profile <profile.json> --out <new-directory>
  npm run bba -- investigate --scope <scope.json> --surface <surface.json> --profile <profile.json> --out <new-directory>
  npm run bba -- resume-investigation <case-directory> --scope <canonical-scope.json> --out <new-report.json|.md>
  npm run bba -- evaluate-semantic <run-directory> --checks <checks.json> --out <new-file.json|.md>
  npm run bba -- evidence-view <run-directory> --query <view.json>
  npm run bba -- artifact-view <hunt-or-browser-directory> --query <view.json>
  npm run bba -- compare-runs --before <run-directory> --after <run-directory> --out <new-file.json>
  npm run bba -- browser-check --scope <scope.json> --config <browser-check.json> --out <new-directory>
  npm run bba -- browser-scenario --scope <scope.json> --config <scenario.json> --out <new-directory>
  npm run bba -- jwt-check --scope <scope.json> --config <jwt-check.json> --out <new-directory>
  npm run bba -- resume-jwt <directory> --scope <scope.json> --config <jwt-check.json>
  npm run bba -- evaluate-jwt <run-directory> --config <jwt-check.json> --out <new-file.json>
  npm run bba -- template-check --scope <scope.json> --config <template-check.json> --out <new-directory>
  npm run bba -- resume-template-check <directory> --scope <same-scope.json> --config <same-template-check.json>
  npm run bba -- ssrf-callback-check --scope <scope.json> --config <ssrf-callback.json> --out <new-directory>
  npm run bba -- resume-ssrf-callback <directory> --scope <same-scope.json> --config <same-ssrf-callback.json>
  npm run bba -- cache-check --scope <scope.json> --config <cache-check.json> --out <new-directory>
  npm run bba -- resume-cache-check <directory> --scope <same-scope.json> --config <same-cache-check.json>
  npm run bba -- race-check --scope <scope.json> --config <race-check.json> --out <new-directory>
  npm run bba -- csrf-check --scope <scope.json> --config <csrf-check.json> --out <new-directory>
  npm run bba -- study-plan --input <study-bundle.json> --out <new-directory>
  npm run bba -- study-bundle --case <published-case.json> --policy <policy.json> --surface <surface.json> --historical <historical.json> --profile <profile.json> --out <new-file.json>
  npm run bba -- study-run --input <study-bundle.json> --out <new-directory>
  npm run bba -- resume-study <directory> --input <same-study-bundle.json>
  npm run bba -- install-skill --out <new-skill-directory>
  npm run bba -- update-skill --out <existing-skill-directory>
  npm run bba -- prepare --scope <scope.json> --target <authorized-url> --out <new-directory>
  npm run bba -- hunt --scope <scope.json> --config <hunt.json> --out <new-directory>
  npm run bba -- eval --out <new-file.json|.md>
  npm run bba -- mcp --root <workspace-directory> [--allow-network]
  npm run bba -- setup-mcp --root <workspace-directory> [--apply] [--allow-network] [--replace]
  npm run bba -- capture --scope <scope.json> --plan <plan.json> --out <new-directory>
  npm run bba -- inspect-web-page --scope <scope.json> --url <authorized-url> --out <new-directory>
  npm run bba -- page-view <capture-directory>

ACTIVOS: run/resume, capture, campaign-capture/campaign-execute/campaign-resume, hunt, investigate/resume-investigation, browser-check, browser-scenario, jwt-check/resume-jwt, template-check/resume-template-check, ssrf-callback-check/resume-ssrf-callback, cache-check/resume-cache-check, race-check, csrf-check y study-run/resume-study.
run/resume ejecutan solo métodos e inputs autorizados explícitamente por scope.
browser-scenario puede enviar formularios y seguir redirects declarados; los demás
flujos de navegador solo envían GET. lab/eval crean sus propios laboratorios locales.
Planificación, importación, evaluación de evidencia, inspección y exportación son offline.
doctor prueba Node/SQLite/loopback/Chromium localmente; install/update-skill escriben
únicamente la instalación elegida. run/investigate reanudan checkpoints; los flujos
de navegador y hunt conservan journals pero no reanudan su sesión.
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

function commandHelp(command: string): string | null {
  const prefix = `  npm run bba -- ${command}`;
  const matches = help.split('\n').filter(line => line === prefix || line.startsWith(prefix + ' '));
  if (!matches.length) return null;
  return `BBA ${pkg.version} — ayuda de ${command}\n\n${matches.join('\n')}\n`;
}

async function main(args: string[]): Promise<void> {
  const [command, ...rest] = args;
  if (!command || ((command === '--help' || command === '-h') && !rest.length)) { console.log(help); return; }
  if ((command === '--help' || command === '-h') && rest.length === 1) {
    const specific = commandHelp(rest[0]);
    if (specific) { console.log(specific); return; }
  }
  if (rest.length === 1 && (rest[0] === '--help' || rest[0] === '-h')) {
    const specific = commandHelp(command);
    if (specific) { console.log(specific); return; }
  }
  let action: () => Promise<void>;
  try {
    if (command === 'study-bundle') {
      const flags = options(rest, ['--case', '--policy', '--surface', '--historical', '--profile', '--out']);
      action = async () => { const bundle = assembleStudyBundle({ caseFile: flags.get('--case')!, policy: flags.get('--policy')!,
        surface: flags.get('--surface')!, historical: flags.get('--historical')!, profile: flags.get('--profile')! }, flags.get('--out')!);
      console.log(JSON.stringify({ case: bundle.case.id, surfaceEntries: bundle.surface.surface.entries.length, output: flags.get('--out') }, null, 2)); };
    } else if (command === 'study-plan' || command === 'study-run') {
      const flags = options(rest, ['--input', '--out']);
      action = async () => {
        const bundle = readJson(flags.get('--input')!);
        validateStudyBundle(bundle);
        const compiled = compileStudy(bundle);
        if (command === 'study-plan') {
          prepareStudy(flags.get('--out')!, bundle);
          console.log(JSON.stringify({ status: compiled.status, reason: compiled.reason, candidates: compiled.candidates.length, output: flags.get('--out') }, null, 2));
        } else {
          const run = (budget?: ProgramBudget) => withCancellation(signal => executeStudy(flags.get('--out')!, bundle, { budget, signal }));
          const result = compiled.scope ? await usingScopeBudget(compiled.scope, flags.get('--input')!, run) : await run(undefined);
          console.log(JSON.stringify({ status: result.result?.status ?? result.analysis.status, report: result.report,
            candidates: result.analysis.candidates.length }, null, 2));
          process.exitCode = result.result && !result.report ? inspectSession(join(flags.get('--out')!, 'jwt', 'run')).status === 'paused' ? 130 : 1
            : result.analysis.status === 'unresolved' ? 3 : 0;
        }
      };
    } else if (command === 'resume-study' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--input']);
      action = async () => {
        const bundle = readJson(flags.get('--input')!); validateStudyBundle(bundle);
        const compiled = compileStudy(bundle);
        const run = (budget?: ProgramBudget) => withCancellation(signal => executeStudy(rest[0], bundle, { budget, signal, resume: true }));
        const result = compiled.scope ? await usingScopeBudget(compiled.scope, flags.get('--input')!, run) : await run(undefined);
        console.log(JSON.stringify({ status: result.result?.status ?? result.analysis.status, report: result.report }, null, 2));
        process.exitCode = result.result && !result.report ? inspectSession(join(rest[0], 'jwt', 'run')).status === 'paused' ? 130 : 1
          : result.analysis.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'campaign-open') {
      const flags = options(rest, ['--target', '--out']);
      action = async () => { console.log(JSON.stringify(openCampaign(flags.get('--out')!, flags.get('--target')!), null, 2)); };
    } else if (command === 'campaign-link') {
      const flags = options(rest, ['--campaign', '--kind', '--artifact']);
      action = async () => { console.log(JSON.stringify(linkCampaign(flags.get('--campaign')!, flags.get('--kind')!, flags.get('--artifact')!), null, 2)); };
    } else if (command === 'campaign-status' && rest.length === 1) {
      action = async () => { console.log(JSON.stringify(campaignStatus(rest[0]), null, 2)); };
    } else if (command === 'campaign-policy-review') {
      const flags = options(rest, ['--campaign', '--source-url', '--source-kind', '--decision']);
      action = async () => { console.log(JSON.stringify(preparePolicyReview(flags.get('--campaign')!, flags.get('--source-url')!,
        flags.get('--source-kind')! as 'official-program-policy' | 'owner-written-authorization',
        flags.get('--decision')! as 'authorized' | 'uncertain'), null, 2)); };
    } else if (command === 'campaign-capture' && rest.length === 1) {
      action = async () => { console.log(JSON.stringify(await withCancellation(signal => campaignCapture(rest[0], signal)), null, 2)); };
    } else if (command === 'campaign-execute' && rest.length === 1) {
      action = async () => { console.log(JSON.stringify(await withCancellation(signal => campaignExecute(rest[0], signal)), null, 2)); };
    } else if (command === 'campaign-resume' && rest.length === 1) {
      action = async () => { console.log(JSON.stringify(await withCancellation(signal => campaignResume(rest[0], signal)), null, 2)); };
    } else if (command === 'start-case') {
      const flags = options(rest, ['--target', '--out']);
      action = async () => { console.log(JSON.stringify(startCase(flags.get('--out')!, flags.get('--target')!), null, 2)); };
    } else if (command === 'capabilities' && !rest.length) {
      action = async () => { console.log(JSON.stringify(capabilities(), null, 2)); };
    } else if (command === 'plan-investigation' || command === 'investigate') {
      const flags = options(rest, ['--scope', '--surface', '--profile', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const surface = readJson(flags.get('--surface')!), profile = readJson(flags.get('--profile')!);
        if (command === 'plan-investigation') {
          const result = prepareCompiled(flags.get('--out')!, scope, surface, profile);
          console.log(JSON.stringify({ planned: result.checks.checks.length, requests: result.plan?.steps.length ?? 0, coverage: result.coverage }, null, 2));
        } else {
          const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => investigateSurface(flags.get('--out')!, scope, surface, profile, { signal, budget })));
          console.log(JSON.stringify(result, null, 2));
          process.exitCode = result.stopped === 'cancelled' ? 130 : result.stopped === 'no-testable-hypotheses' ? 3 : result.stopped && result.stopped !== 'proof-complete' ? 1 : 0;
        }
      };
    } else if (command === 'resume-investigation' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--scope', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resumeInvestigation(rest[0], scope, flags.get('--out')!, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.stopped === 'cancelled' ? 130 : result.stopped && result.stopped !== 'proof-complete' ? 1 : 0;
      };
    } else if (command === 'jwt-check' || command === 'resume-jwt') {
      const resume = command === 'resume-jwt';
      if (resume && (!rest[0] || rest[0].startsWith('--'))) throw new Error('Missing JWT check directory');
      const flags = options(resume ? rest.slice(1) : rest, resume ? ['--scope', '--config'] : ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateJwtIntegrity(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => jwtIntegrityCheck(resume ? rest[0] : flags.get('--out')!, scope, config, { signal, budget, resume })));
        console.log(JSON.stringify(result, null, 2));
        process.exitCode = result.reason === 'Required controls are incomplete.' ? 3 : 0;
      };
    } else if (command === 'csrf-check') {
      const flags = options(rest, ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateCsrfCheck(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal =>
          csrfCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'race-check') {
      const flags = options(rest, ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateRaceCheck(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal =>
          raceCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'cache-check' || command === 'resume-cache-check') {
      const resume = command === 'resume-cache-check';
      if (resume && (!rest[0] || rest[0].startsWith('--'))) throw new Error('Missing cache check directory');
      const flags = options(resume ? rest.slice(1) : rest, resume ? ['--scope', '--config'] : ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateCacheCheck(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resume
          ? resumeCacheCheck(rest[0], scope, config, { signal, budget })
          : cacheCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'ssrf-callback-check' || command === 'resume-ssrf-callback') {
      const resume = command === 'resume-ssrf-callback';
      if (resume && (!rest[0] || rest[0].startsWith('--'))) throw new Error('Missing callback check directory');
      const flags = options(resume ? rest.slice(1) : rest, resume ? ['--scope', '--config'] : ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateSsrfCallback(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resume
          ? resumeSsrfCallbackCheck(rest[0], scope, config, { signal, budget })
          : ssrfCallbackCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'template-check' || command === 'resume-template-check') {
      const resume = command === 'resume-template-check';
      if (resume && (!rest[0] || rest[0].startsWith('--'))) throw new Error('Missing template check directory');
      const flags = options(resume ? rest.slice(1) : rest, resume ? ['--scope', '--config'] : ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateTemplateCheck(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resume
          ? resumeTemplateCheck(rest[0], scope, config, { signal, budget })
          : templateCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.status === 'unresolved' ? 3 : 0;
      };
    } else if (command === 'evaluate-jwt' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--config', '--out']);
      action = async () => { console.log(JSON.stringify(evaluateJwtIntegrityFile(rest[0], flags.get('--config')!, flags.get('--out')!), null, 2)); };
    } else if (command === 'browser-scenario') {
      const flags = options(rest, ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateScenario(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureScenario(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
      };
    } else if (command === 'browser-check') {
      const flags = options(rest, ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateBrowserCheck(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => browserCheck(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify(result, null, 2)); process.exitCode = result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
      };
    } else if (command === 'evaluate-semantic' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--checks', '--out']);
      action = async () => { console.log(JSON.stringify(evaluateSemanticFile(rest[0], flags.get('--checks')!, flags.get('--out')!), null, 2)); };
    } else if (command === 'artifact-view' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--query']);
      action = async () => { console.log(JSON.stringify(artifactView(rest[0], readJson(flags.get('--query')!)), null, 2)); };
    } else if (command === 'evidence-view' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--query']);
      action = async () => { console.log(JSON.stringify(evidenceViewFile(rest[0], readJson(flags.get('--query')!)), null, 2)); };
    } else if (command === 'compare-runs') {
      const flags = options(rest, ['--before', '--after', '--out']);
      action = async () => { console.log(JSON.stringify(exportComparison(flags.get('--before')!, flags.get('--after')!, flags.get('--out')!), null, 2)); };
    } else if (command === 'inspect-budget' && rest.length === 1 && !rest[0].startsWith('--')) {
      action = async () => { console.log(JSON.stringify(inspectBudget(rest[0]), null, 2)); };
    } else if (command === 'install-skill' || command === 'update-skill') {
      const flags = options(rest, ['--out']);
      action = async () => { console.log(JSON.stringify(installSkill(flags.get('--out')!, command === 'update-skill'), null, 2)); };
    } else if (command === 'prepare') {
      const flags = options(rest, ['--scope', '--target', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        console.log(JSON.stringify(prepareInvestigation(flags.get('--out')!, scope, flags.get('--target')!), null, 2));
      };
    } else if (command === 'hunt') {
      const flags = options(rest, ['--scope', '--config', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const config = readJson(flags.get('--config')!); validateHunt(config, scope);
        const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => hunt(flags.get('--out')!, scope, config, { signal, budget })));
        console.log(JSON.stringify({ requests: result.requests, stopped: result.stopped, findings: result.findings.map(f => ({ status: f.status, url: f.url })) }, null, 2));
        process.exitCode = result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
      };
    } else if (command === 'doctor' && !rest.length) {
      action = async () => { const result = await doctor(); console.log(JSON.stringify(result, null, 2)); process.exitCode = result.ok ? 0 : 1; };
    } else if (command === 'eval') {
      const flags = options(rest, ['--out']);
      action = async () => {
        const { metrics } = await evaluationFile(flags.get('--out')!);
        console.log(JSON.stringify(metrics, null, 2));
        process.exitCode = metrics.passed === metrics.cases ? 0 : 1;
      };
    } else if (command === 'mcp') {
      const allowNetwork = rest.includes('--allow-network');
      const flags = options(rest.filter(a => a !== '--allow-network'), ['--root']);
      action = () => serveMcp({ root: resolve(flags.get('--root')!), allowNetwork, input: process.stdin, output: process.stdout });
    } else if (command === 'setup-mcp') {
      const switches: string[] = rest.filter(a => a === '--apply' || a === '--allow-network' || a === '--replace');
      if (new Set(switches).size !== switches.length) throw new Error('Duplicate setup switch');
      const flags = options(rest.filter(a => !switches.includes(a)), ['--root']);
      action = async () => { console.log(JSON.stringify(setupCodexMcp(flags.get('--root')!, switches.includes('--apply'), switches.includes('--allow-network'), switches.includes('--replace')), null, 2)); };
    } else if (command === 'page-view' && rest.length === 1) {
      action = async () => { console.log(JSON.stringify(readPageSurface(rest[0]), null, 2)); };
    } else if (command === 'inspect-web-page') {
      const flags = options(rest, ['--scope', '--url', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope); assertAuthorized(scope, flags.get('--url')!);
        const plan = { schemaVersion: 1, steps: [{ id: 'seed', method: 'GET', url: flags.get('--url')!, credentialEnv: null }] };
        validatePlan(plan, scope);
        const { capture, pages } = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureSurface(flags.get('--out')!, scope, plan, { signal, budget })));
        console.log(JSON.stringify({ stopReason: capture.stopReason, counts: capture.counts, page: pages.pages[0] ?? null, output: flags.get('--out') }, null, 2));
        process.exitCode = capture.stopReason === 'cancelled' ? 130 : capture.stopReason ? 1 : 0;
      };
    } else if (command === 'capture') {
      const flags = options(rest, ['--scope', '--plan', '--out']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        const plan = readJson(flags.get('--plan')!); validatePlan(plan, scope);
        const { capture, surface } = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureSurface(flags.get('--out')!, scope, plan, { signal, budget })));
        console.log(JSON.stringify({ ...surfaceSummary(surface), stopReason: capture.stopReason, counts: capture.counts }, null, 2));
        process.exitCode = capture.stopReason === 'cancelled' ? 130 : capture.stopReason ? 1 : 0;
      };
    } else if (command === 'import-candidates') {
      const flags = options(rest, ['--format', '--input', '--scope', '--out']);
      const format = flags.get('--format');
      if (format !== 'zap' && format !== 'nuclei' && format !== 'subfinder') throw new Error('Invalid format');
      action = async () => {
        const set = importCandidatesFile(flags.get('--input')!, format, readJson(flags.get('--scope')!), flags.get('--out')!);
        console.log(JSON.stringify(candidateSummary(set), null, 2));
      };
    } else if (command === 'import-surface') {
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
        await usingScopeBudget(scope, flags.get('--scope')!, budget => runCancellable(flags.get('--out')!, scope, budget));
      };
    } else if (command === 'resume' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--scope']);
      action = async () => {
        const scope = readJson(flags.get('--scope')!); validateScope(scope);
        await usingScopeBudget(scope, flags.get('--scope')!, budget => runCancellable(rest[0], scope, budget));
      };
    } else if (command === 'evaluate-run' && rest[0] && !rest[0].startsWith('--')) {
      const flags = options(rest.slice(1), ['--checks', '--out']);
      action = async () => {
        const { findings } = evaluateRunFile(rest[0], flags.get('--checks')!, flags.get('--out')!);
        console.log(JSON.stringify(findings.map(f => ({ check: f.checkId, class: f.class, status: f.status })), null, 2));
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
    console.error(`BBA: ${safeErrorMessage(error)}`); process.exitCode = 1;
  }
}

async function runCancellable(folder: string, scope: import('./scope.ts').Scope, budget?: ProgramBudget): Promise<void> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const state = await executeSession(folder, scope, { signal: controller.signal, budget });
    console.log(JSON.stringify(sessionSummary(state), null, 2));
    process.exitCode = state.status === 'paused' ? 130 : state.status === 'partial' ? 3 : state.status === 'stopped' ? 1 : 0;
  } finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}

async function withCancellation<T>(action: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try { return await action(controller.signal); }
  finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}

await main(process.argv.slice(2));
