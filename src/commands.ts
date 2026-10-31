import { join, resolve } from 'node:path';
import pkg from '../package.json' with { type: 'json' };
import { investigateLab } from './investigation.ts';
import { summary } from './report.ts';
import { exportReport, loadInvestigation, requireNewDirectory, saveInvestigation } from './storage.ts';
import { assertAuthorized, validatePlan, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { createSession, exportSession, inspectSession, readJson, sessionSummary } from './session.ts';
import { executeSession } from './execution.ts';
import { importSurfaceFile, surfaceSummary } from './surface.ts';
import { captureSurface, readPageSurface } from './capture.ts';
import { evaluateRunFile } from './checks.ts';
import { candidateSummary, importCandidatesFile } from './candidates.ts';
import { doctor } from './doctor.ts';
import { evaluationFile } from './evaluation.ts';
import { serveMcp } from './mcp.ts';
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
import { setupMcp } from './mcp-setup.ts';
import type { McpClient } from './mcp-setup.ts';
import { openCampaign, linkCampaign, campaignStatus, campaignCapture, campaignExecute, campaignResume, preparePolicyReview } from './campaign.ts';
import { templateCheck, resumeTemplateCheck, validateTemplateCheck } from './template-check.ts';
import { ssrfCallbackCheck, resumeSsrfCallbackCheck, validateSsrfCallback } from './ssrf-callback.ts';
import { cacheCheck, resumeCacheCheck, validateCacheCheck } from './cache-check.ts';
import { raceCheck, validateRaceCheck } from './race-check.ts';
import { csrfCheck, validateCsrfCheck } from './csrf-check.ts';
import { pickText } from './i18n.ts';
import type { Lang } from './i18n.ts';

export type ParsedCliInput = {
  positional: string | null;
  flags: Map<string, string>;
  switches: Set<string>;
  lang: Lang;
};

export type CommandSpec = {
  name: string;
  usage: string;
  positional?: boolean;
  requiredFlags?: string[];
  optionalFlags?: string[];
  switches?: string[];
  execute: (input: ParsedCliInput) => Promise<number | void>;
};

const subcommandAliases: Record<string, Record<string, string>> = {
  campaign: {
    open: 'campaign-open',
    link: 'campaign-link',
    status: 'campaign-status',
    'policy-review': 'campaign-policy-review',
    capture: 'campaign-capture',
    execute: 'campaign-execute',
    resume: 'campaign-resume',
  },
  check: {
    jwt: 'jwt-check',
    csrf: 'csrf-check',
    race: 'race-check',
    cache: 'cache-check',
    template: 'template-check',
    ssrf: 'ssrf-callback-check',
    browser: 'browser-check',
  },
  study: {
    bundle: 'study-bundle',
    plan: 'study-plan',
    run: 'study-run',
    resume: 'resume-study',
  },
};

export function normalizeCommandArgs(args: string[]): { command: string | undefined; rest: string[] } {
  const [first, second, ...tail] = args;
  if (first && second && Object.hasOwn(subcommandAliases, first)) {
    const group = subcommandAliases[first];
    if (Object.hasOwn(group, second)) {
      return { command: group[second], rest: tail };
    }
  }
  return { command: first, rest: args.slice(1) };
}

export function parseCliInput(rest: string[], spec: CommandSpec, lang: Lang): ParsedCliInput {
  let cursor = rest;
  let positional: string | null = null;
  if (spec.positional) {
    if (!cursor[0] || cursor[0].startsWith('--')) throw new Error('Missing positional argument');
    positional = cursor[0];
    cursor = cursor.slice(1);
  }
  const reqFlags = spec.requiredFlags ?? [];
  const optFlags = spec.optionalFlags ?? [];
  const allowedFlags = new Set([...reqFlags, ...optFlags]);
  const allowedSwitches = new Set(spec.switches ?? []);
  const flags = new Map<string, string>();
  const switches = new Set<string>();

  for (let i = 0; i < cursor.length; i++) {
    const token = cursor[i];
    if (allowedSwitches.has(token)) {
      if (switches.has(token)) throw new Error('Duplicate switch');
      switches.add(token);
      continue;
    }
    if (!allowedFlags.has(token) || flags.has(token)) throw new Error('Invalid flag');
    const val = cursor[i + 1];
    if (!val || val.startsWith('--')) throw new Error('Missing flag value');
    flags.set(token, val);
    i++;
  }
  for (const req of reqFlags) {
    if (!flags.has(req)) throw new Error('Missing required flag');
  }
  return { positional, flags, switches, lang };
}

async function withCancellation<T>(action: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try { return await action(controller.signal); }
  finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}

async function runCancellable(folder: string, scope: Scope, budget?: ProgramBudget): Promise<number> {
  const state = await withCancellation(signal => executeSession(folder, scope, { signal, budget }));
  console.log(JSON.stringify(sessionSummary(state), null, 2));
  return state.status === 'paused' ? 130 : state.status === 'partial' ? 3 : state.status === 'stopped' ? 1 : 0;
}

export const commandSpecs: CommandSpec[] = [
  {
    name: 'lab',
    usage: 'lab --variant vulnerable|fixed --out <new-directory>',
    requiredFlags: ['--variant', '--out'],
    async execute({ flags, lang }) {
      const variant = flags.get('--variant');
      if (variant !== 'vulnerable' && variant !== 'fixed') throw new Error('InvalidUsage');
      const out = await requireNewDirectory(flags.get('--out')!);
      const investigation = await investigateLab(variant);
      await saveInvestigation(out, investigation, lang);
      console.log(JSON.stringify({ ...summary(investigation), output: out }, null, 2));
    },
  },
  {
    name: 'inspect',
    usage: 'inspect <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(summary(await loadInvestigation(positional!)), null, 2));
    },
  },
  {
    name: 'report',
    usage: 'report <directory> --out <new-file.md>',
    positional: true,
    requiredFlags: ['--out'],
    async execute({ positional, flags, lang }) {
      await exportReport(positional!, flags.get('--out')!, lang);
      console.log(pickText(lang, 'Reporte verificado y exportado.', 'Report verified and exported.'));
    },
  },
  {
    name: 'scope-check',
    usage: 'scope-check --scope <scope.json> --plan <plan.json>',
    requiredFlags: ['--scope', '--plan'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const plan = readJson(flags.get('--plan')!); validatePlan(plan, scope);
      console.log(pickText(
        lang,
        'Formato, vigencia y coincidencia con scope válidos; no se verificó el permiso del propietario ni se enviaron solicitudes.',
        'Format, time window and scope match are valid; owner permission was not verified and no requests were sent.',
      ));
    },
  },
  {
    name: 'run',
    usage: 'run --scope <scope.json> --plan <plan.json> --out <new-directory>',
    requiredFlags: ['--scope', '--plan', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const plan = readJson(flags.get('--plan')!); validatePlan(plan, scope);
      createSession(flags.get('--out')!, scope, plan);
      return usingScopeBudget(scope, flags.get('--scope')!, budget => runCancellable(flags.get('--out')!, scope, budget));
    },
  },
  {
    name: 'resume',
    usage: 'resume <directory> --scope <same-scope.json>',
    positional: true,
    requiredFlags: ['--scope'],
    async execute({ positional, flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      return usingScopeBudget(scope, flags.get('--scope')!, budget => runCancellable(positional!, scope, budget));
    },
  },
  {
    name: 'inspect-run',
    usage: 'inspect-run <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(sessionSummary(inspectSession(positional!)), null, 2));
    },
  },
  {
    name: 'export-run',
    usage: 'export-run <directory> --out <new-file.json>',
    positional: true,
    requiredFlags: ['--out'],
    async execute({ positional, flags, lang }) {
      exportSession(positional!, flags.get('--out')!, 'json', lang);
      console.log(pickText(lang, 'Evidencia verificada y exportada.', 'Evidence verified and exported.'));
    },
  },
  {
    name: 'report-run',
    usage: 'report-run <directory> --out <new-file.md>',
    positional: true,
    requiredFlags: ['--out'],
    async execute({ positional, flags, lang }) {
      exportSession(positional!, flags.get('--out')!, 'markdown', lang);
      console.log(pickText(lang, 'Evidencia verificada y exportada.', 'Evidence verified and exported.'));
    },
  },
  {
    name: 'import-surface',
    usage: 'import-surface --format har|openapi|rea --input <file.json> --out <new-file.json> [--quarantine]',
    requiredFlags: ['--format', '--input', '--out'],
    switches: ['--quarantine'],
    async execute({ flags, switches }) {
      const format = flags.get('--format');
      if (format !== 'har' && format !== 'openapi' && format !== 'rea') throw new Error('InvalidUsage');
      const surface = importSurfaceFile(flags.get('--input')!, format, flags.get('--out')!, { quarantine: switches.has('--quarantine') });
      console.log(JSON.stringify(surfaceSummary(surface), null, 2));
    },
  },
  {
    name: 'evaluate-run',
    usage: 'evaluate-run <directory> --checks <checks.json> --out <new-file.json|.md>',
    positional: true,
    requiredFlags: ['--checks', '--out'],
    async execute({ positional, flags, lang }) {
      const { findings } = evaluateRunFile(positional!, flags.get('--checks')!, flags.get('--out')!, lang);
      console.log(JSON.stringify(findings.map(f => ({ check: f.checkId, class: f.class, status: f.status })), null, 2));
    },
  },
  {
    name: 'import-candidates',
    usage: 'import-candidates --format zap|nuclei|subfinder --input <file> --scope <scope.json> --out <new-file.json>',
    requiredFlags: ['--format', '--input', '--scope', '--out'],
    async execute({ flags }) {
      const format = flags.get('--format');
      if (format !== 'zap' && format !== 'nuclei' && format !== 'subfinder') throw new Error('InvalidUsage');
      const set = importCandidatesFile(flags.get('--input')!, format, readJson(flags.get('--scope')!), flags.get('--out')!);
      console.log(JSON.stringify(candidateSummary(set), null, 2));
    },
  },
  {
    name: 'doctor',
    usage: 'doctor',
    async execute() {
      const result = await doctor();
      console.log(JSON.stringify(result, null, 2));
      return result.ok ? 0 : 1;
    },
  },
  {
    name: 'start-case',
    usage: 'start-case --target <canonical-service-url> --out <new-directory>',
    requiredFlags: ['--target', '--out'],
    async execute({ flags }) {
      console.log(JSON.stringify(startCase(flags.get('--out')!, flags.get('--target')!), null, 2));
    },
  },
  {
    name: 'campaign-open',
    usage: 'campaign-open --target <canonical-service-url> --out <new-directory>',
    requiredFlags: ['--target', '--out'],
    async execute({ flags }) {
      console.log(JSON.stringify(openCampaign(flags.get('--out')!, flags.get('--target')!), null, 2));
    },
  },
  {
    name: 'campaign-link',
    usage: 'campaign-link --campaign <directory> --kind scope|policy|surface|page|profile|run|report --artifact <path>',
    requiredFlags: ['--campaign', '--kind', '--artifact'],
    async execute({ flags }) {
      console.log(JSON.stringify(linkCampaign(flags.get('--campaign')!, flags.get('--kind')!, flags.get('--artifact')!), null, 2));
    },
  },
  {
    name: 'campaign-status',
    usage: 'campaign-status <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(campaignStatus(positional!), null, 2));
    },
  },
  {
    name: 'campaign-policy-review',
    usage: 'campaign-policy-review --campaign <directory> --source-url <https-url> --source-kind official-program-policy|owner-written-authorization --decision authorized|uncertain',
    requiredFlags: ['--campaign', '--source-url', '--source-kind', '--decision'],
    async execute({ flags }) {
      console.log(JSON.stringify(preparePolicyReview(
        flags.get('--campaign')!,
        flags.get('--source-url')!,
        flags.get('--source-kind')! as 'official-program-policy' | 'owner-written-authorization',
        flags.get('--decision')! as 'authorized' | 'uncertain',
      ), null, 2));
    },
  },
  {
    name: 'campaign-capture',
    usage: 'campaign-capture <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(await withCancellation(signal => campaignCapture(positional!, signal)), null, 2));
    },
  },
  {
    name: 'campaign-execute',
    usage: 'campaign-execute <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(await withCancellation(signal => campaignExecute(positional!, signal)), null, 2));
    },
  },
  {
    name: 'campaign-resume',
    usage: 'campaign-resume <directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(await withCancellation(signal => campaignResume(positional!, signal)), null, 2));
    },
  },
  {
    name: 'capabilities',
    usage: 'capabilities',
    async execute() {
      console.log(JSON.stringify(capabilities(), null, 2));
    },
  },
  {
    name: 'inspect-budget',
    usage: 'inspect-budget <budget-directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(inspectBudget(positional!), null, 2));
    },
  },
  {
    name: 'plan-investigation',
    usage: 'plan-investigation --scope <scope.json> --surface <surface.json> --profile <profile.json> --out <new-directory>',
    requiredFlags: ['--scope', '--surface', '--profile', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const surface = readJson(flags.get('--surface')!), profile = readJson(flags.get('--profile')!);
      const result = prepareCompiled(flags.get('--out')!, scope, surface, profile);
      console.log(JSON.stringify({ planned: result.checks.checks.length, requests: result.plan?.steps.length ?? 0, coverage: result.coverage }, null, 2));
    },
  },
  {
    name: 'investigate',
    usage: 'investigate --scope <scope.json> --surface <surface.json> --profile <profile.json> --out <new-directory>',
    requiredFlags: ['--scope', '--surface', '--profile', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const surface = readJson(flags.get('--surface')!), profile = readJson(flags.get('--profile')!);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => investigateSurface(flags.get('--out')!, scope, surface, profile, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.stopped === 'cancelled' ? 130 : result.stopped === 'no-testable-hypotheses' ? 3 : result.stopped && result.stopped !== 'proof-complete' ? 1 : 0;
    },
  },
  {
    name: 'resume-investigation',
    usage: 'resume-investigation <case-directory> --scope <canonical-scope.json> --out <new-report.json|.md>',
    positional: true,
    requiredFlags: ['--scope', '--out'],
    async execute({ positional, flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resumeInvestigation(positional!, scope, flags.get('--out')!, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.stopped === 'cancelled' ? 130 : result.stopped && result.stopped !== 'proof-complete' ? 1 : 0;
    },
  },
  {
    name: 'evaluate-semantic',
    usage: 'evaluate-semantic <run-directory> --checks <checks.json> --out <new-file.json|.md>',
    positional: true,
    requiredFlags: ['--checks', '--out'],
    async execute({ positional, flags, lang }) {
      console.log(JSON.stringify(evaluateSemanticFile(positional!, flags.get('--checks')!, flags.get('--out')!, lang), null, 2));
    },
  },
  {
    name: 'evidence-view',
    usage: 'evidence-view <run-directory> --query <view.json>',
    positional: true,
    requiredFlags: ['--query'],
    async execute({ positional, flags }) {
      console.log(JSON.stringify(evidenceViewFile(positional!, readJson(flags.get('--query')!)), null, 2));
    },
  },
  {
    name: 'artifact-view',
    usage: 'artifact-view <hunt-or-browser-directory> --query <view.json>',
    positional: true,
    requiredFlags: ['--query'],
    async execute({ positional, flags }) {
      console.log(JSON.stringify(artifactView(positional!, readJson(flags.get('--query')!)), null, 2));
    },
  },
  {
    name: 'compare-runs',
    usage: 'compare-runs --before <run-directory> --after <run-directory> --out <new-file.json>',
    requiredFlags: ['--before', '--after', '--out'],
    async execute({ flags }) {
      console.log(JSON.stringify(exportComparison(flags.get('--before')!, flags.get('--after')!, flags.get('--out')!), null, 2));
    },
  },
  {
    name: 'browser-check',
    usage: 'browser-check --scope <scope.json> --config <browser-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateBrowserCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => browserCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
    },
  },
  {
    name: 'browser-scenario',
    usage: 'browser-scenario --scope <scope.json> --config <scenario.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateScenario(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureScenario(flags.get('--out')!, scope, config, { signal, budget })));
      console.log(JSON.stringify(result, null, 2));
      return result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
    },
  },
  {
    name: 'jwt-check',
    usage: 'jwt-check --scope <scope.json> --config <jwt-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateJwtIntegrity(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => jwtIntegrityCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.reason === 'Required controls are incomplete.' ? 3 : 0;
    },
  },
  {
    name: 'resume-jwt',
    usage: 'resume-jwt <directory> --scope <scope.json> --config <jwt-check.json>',
    positional: true,
    requiredFlags: ['--scope', '--config'],
    async execute({ positional, flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateJwtIntegrity(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => jwtIntegrityCheck(positional!, scope, config, { signal, budget, resume: true, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.reason === 'Required controls are incomplete.' ? 3 : 0;
    },
  },
  {
    name: 'evaluate-jwt',
    usage: 'evaluate-jwt <run-directory> --config <jwt-check.json> --out <new-file.json>',
    positional: true,
    requiredFlags: ['--config', '--out'],
    async execute({ positional, flags, lang }) {
      console.log(JSON.stringify(evaluateJwtIntegrityFile(positional!, flags.get('--config')!, flags.get('--out')!, lang), null, 2));
    },
  },
  {
    name: 'template-check',
    usage: 'template-check --scope <scope.json> --config <template-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateTemplateCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => templateCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'resume-template-check',
    usage: 'resume-template-check <directory> --scope <same-scope.json> --config <same-template-check.json>',
    positional: true,
    requiredFlags: ['--scope', '--config'],
    async execute({ positional, flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateTemplateCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resumeTemplateCheck(positional!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'ssrf-callback-check',
    usage: 'ssrf-callback-check --scope <scope.json> --config <ssrf-callback.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateSsrfCallback(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => ssrfCallbackCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'resume-ssrf-callback',
    usage: 'resume-ssrf-callback <directory> --scope <same-scope.json> --config <same-ssrf-callback.json>',
    positional: true,
    requiredFlags: ['--scope', '--config'],
    async execute({ positional, flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateSsrfCallback(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resumeSsrfCallbackCheck(positional!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'cache-check',
    usage: 'cache-check --scope <scope.json> --config <cache-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateCacheCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => cacheCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'resume-cache-check',
    usage: 'resume-cache-check <directory> --scope <same-scope.json> --config <same-cache-check.json>',
    positional: true,
    requiredFlags: ['--scope', '--config'],
    async execute({ positional, flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateCacheCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => resumeCacheCheck(positional!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'race-check',
    usage: 'race-check --scope <scope.json> --config <race-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateRaceCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => raceCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'csrf-check',
    usage: 'csrf-check --scope <scope.json> --config <csrf-check.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateCsrfCheck(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => csrfCheck(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify(result, null, 2));
      return result.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'study-plan',
    usage: 'study-plan --input <study-bundle.json> --out <new-directory>',
    requiredFlags: ['--input', '--out'],
    async execute({ flags, lang }) {
      const bundle = readJson(flags.get('--input')!); validateStudyBundle(bundle);
      const compiled = prepareStudy(flags.get('--out')!, bundle, lang);
      console.log(JSON.stringify({ status: compiled.status, reason: compiled.reason, candidates: compiled.candidates.length, output: flags.get('--out') }, null, 2));
    },
  },
  {
    name: 'study-bundle',
    usage: 'study-bundle --case <published-case.json> --policy <policy.json> --surface <surface.json> --historical <historical.json> --profile <profile.json> --out <new-file.json>',
    requiredFlags: ['--case', '--policy', '--surface', '--historical', '--profile', '--out'],
    async execute({ flags }) {
      const bundle = assembleStudyBundle({
        caseFile: flags.get('--case')!, policy: flags.get('--policy')!,
        surface: flags.get('--surface')!, historical: flags.get('--historical')!, profile: flags.get('--profile')!,
      }, flags.get('--out')!);
      console.log(JSON.stringify({ case: bundle.case.id, surfaceEntries: bundle.surface.surface.entries.length, output: flags.get('--out') }, null, 2));
    },
  },
  {
    name: 'study-run',
    usage: 'study-run --input <study-bundle.json> --out <new-directory>',
    requiredFlags: ['--input', '--out'],
    async execute({ flags, lang }) {
      const bundle = readJson(flags.get('--input')!); validateStudyBundle(bundle);
      const compiled = compileStudy(bundle);
      const run = (budget?: ProgramBudget) => withCancellation(signal => executeStudy(flags.get('--out')!, bundle, { budget, signal, lang }));
      const result = compiled.scope ? await usingScopeBudget(compiled.scope, flags.get('--input')!, run) : await run(undefined);
      console.log(JSON.stringify({ status: result.result?.status ?? result.analysis.status, report: result.report, candidates: result.analysis.candidates.length }, null, 2));
      return result.result && !result.report ? inspectSession(join(flags.get('--out')!, 'jwt', 'run')).status === 'paused' ? 130 : 1
        : result.analysis.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'resume-study',
    usage: 'resume-study <directory> --input <same-study-bundle.json>',
    positional: true,
    requiredFlags: ['--input'],
    async execute({ positional, flags, lang }) {
      const bundle = readJson(flags.get('--input')!); validateStudyBundle(bundle);
      const compiled = compileStudy(bundle);
      const run = (budget?: ProgramBudget) => withCancellation(signal => executeStudy(positional!, bundle, { budget, signal, resume: true, lang }));
      const result = compiled.scope ? await usingScopeBudget(compiled.scope, flags.get('--input')!, run) : await run(undefined);
      console.log(JSON.stringify({ status: result.result?.status ?? result.analysis.status, report: result.report }, null, 2));
      return result.result && !result.report ? inspectSession(join(positional!, 'jwt', 'run')).status === 'paused' ? 130 : 1
        : result.analysis.status === 'unresolved' ? 3 : 0;
    },
  },
  {
    name: 'install-skill',
    usage: 'install-skill --out <new-skill-directory>',
    requiredFlags: ['--out'],
    async execute({ flags }) {
      console.log(JSON.stringify(installSkill(flags.get('--out')!, false), null, 2));
    },
  },
  {
    name: 'update-skill',
    usage: 'update-skill --out <existing-skill-directory>',
    requiredFlags: ['--out'],
    async execute({ flags }) {
      console.log(JSON.stringify(installSkill(flags.get('--out')!, true), null, 2));
    },
  },
  {
    name: 'prepare',
    usage: 'prepare --scope <scope.json> --target <authorized-url> --out <new-directory>',
    requiredFlags: ['--scope', '--target', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      console.log(JSON.stringify(prepareInvestigation(flags.get('--out')!, scope, flags.get('--target')!), null, 2));
    },
  },
  {
    name: 'hunt',
    usage: 'hunt --scope <scope.json> --config <hunt.json> --out <new-directory>',
    requiredFlags: ['--scope', '--config', '--out'],
    async execute({ flags, lang }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const config = readJson(flags.get('--config')!); validateHunt(config, scope);
      const result = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => hunt(flags.get('--out')!, scope, config, { signal, budget, lang })));
      console.log(JSON.stringify({ requests: result.requests, stopped: result.stopped, findings: result.findings.map(f => ({ status: f.status, url: f.url })) }, null, 2));
      return result.stopped === 'cancelled' ? 130 : result.stopped ? 1 : 0;
    },
  },
  {
    name: 'eval',
    usage: 'eval --out <new-file.json|.md>',
    requiredFlags: ['--out'],
    async execute({ flags, lang }) {
      const { metrics } = await evaluationFile(flags.get('--out')!, lang);
      console.log(JSON.stringify(metrics, null, 2));
      return metrics.passed === metrics.cases ? 0 : 1;
    },
  },
  {
    name: 'mcp',
    usage: 'mcp --root <workspace-directory> [--allow-network]',
    requiredFlags: ['--root'],
    switches: ['--allow-network'],
    async execute({ flags, switches }) {
      await serveMcp({ root: resolve(flags.get('--root')!), allowNetwork: switches.has('--allow-network'), input: process.stdin, output: process.stdout });
    },
  },
  {
    name: 'setup-mcp',
    usage: 'setup-mcp --root <workspace-directory> [--client codex|claude|gemini] [--apply] [--allow-network] [--replace]',
    requiredFlags: ['--root'],
    optionalFlags: ['--client'],
    switches: ['--apply', '--allow-network', '--replace'],
    async execute({ flags, switches }) {
      const clientRaw = flags.get('--client') ?? 'codex';
      if (clientRaw !== 'codex' && clientRaw !== 'claude' && clientRaw !== 'gemini') throw new Error('InvalidUsage');
      console.log(JSON.stringify(setupMcp(flags.get('--root')!, {
        client: clientRaw as McpClient,
        apply: switches.has('--apply'),
        allowNetwork: switches.has('--allow-network'),
        replace: switches.has('--replace'),
      }), null, 2));
    },
  },
  {
    name: 'capture',
    usage: 'capture --scope <scope.json> --plan <plan.json> --out <new-directory>',
    requiredFlags: ['--scope', '--plan', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope);
      const plan = readJson(flags.get('--plan')!); validatePlan(plan, scope);
      const { capture, surface } = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureSurface(flags.get('--out')!, scope, plan, { signal, budget })));
      console.log(JSON.stringify({ ...surfaceSummary(surface), stopReason: capture.stopReason, counts: capture.counts }, null, 2));
      return capture.stopReason === 'cancelled' ? 130 : capture.stopReason ? 1 : 0;
    },
  },
  {
    name: 'inspect-web-page',
    usage: 'inspect-web-page --scope <scope.json> --url <authorized-url> --out <new-directory>',
    requiredFlags: ['--scope', '--url', '--out'],
    async execute({ flags }) {
      const scope = readJson(flags.get('--scope')!); validateScope(scope); assertAuthorized(scope, flags.get('--url')!);
      const plan = { schemaVersion: 1, steps: [{ id: 'seed', method: 'GET', url: flags.get('--url')!, credentialEnv: null }] };
      validatePlan(plan, scope);
      const { capture, pages } = await usingScopeBudget(scope, flags.get('--scope')!, budget => withCancellation(signal => captureSurface(flags.get('--out')!, scope, plan, { signal, budget })));
      console.log(JSON.stringify({ stopReason: capture.stopReason, counts: capture.counts, page: pages.pages[0] ?? null, output: flags.get('--out') }, null, 2));
      return capture.stopReason === 'cancelled' ? 130 : capture.stopReason ? 1 : 0;
    },
  },
  {
    name: 'page-view',
    usage: 'page-view <capture-directory>',
    positional: true,
    async execute({ positional }) {
      console.log(JSON.stringify(readPageSurface(positional!), null, 2));
    },
  },
];

export function renderHelp(lang: Lang = 'es'): string {
  const lines = commandSpecs.map(spec => `  npm run bba -- ${spec.usage}`).join('\n');
  if (lang === 'en') {
    return `BBA ${pkg.version} — investigations, captures and surface

${lines}

  Subcommands: bba campaign <open|link|status|policy-review|capture|execute|resume>, bba check <jwt|csrf|race|cache|template|ssrf|browser>, bba study <bundle|plan|run|resume>.
  Global flag: [--lang es|en] (default: es).

ACTIVE: run/resume, capture, campaign-capture/campaign-execute/campaign-resume, hunt, investigate/resume-investigation, browser-check, browser-scenario, jwt-check/resume-jwt, template-check/resume-template-check, ssrf-callback-check/resume-ssrf-callback, cache-check/resume-cache-check, race-check, csrf-check and study-run/resume-study.
Planning, surface import, evidence evaluation, inspection and export are strictly offline.
Exit codes: 0 completed, 1 error/stopped, 2 invalid usage, 3 partial/unresolved, 130 cancelled.
`;
  }
  return `BBA ${pkg.version} — investigaciones, capturas y superficie

${lines}

  Subcomandos: bba campaign <open|link|status|policy-review|capture|execute|resume>, bba check <jwt|csrf|race|cache|template|ssrf|browser>, bba study <bundle|plan|run|resume>.
  Flag global: [--lang es|en] (por defecto: es).

ACTIVOS: run/resume, capture, campaign-capture/campaign-execute/campaign-resume, hunt, investigate/resume-investigation, browser-check, browser-scenario, jwt-check/resume-jwt, template-check/resume-template-check, ssrf-callback-check/resume-ssrf-callback, cache-check/resume-cache-check, race-check, csrf-check y study-run/resume-study.
Planificación, importación, evaluación de evidencia, inspección y exportación son offline.
Exit codes: 0 completo, 1 error/detenido, 2 uso inválido, 3 parcial, 130 cancelado.
`;
}

export function renderCommandHelp(command: string, lang: Lang = 'es'): string | null {
  const spec = commandSpecs.find(s => s.name === command);
  if (!spec) return null;
  const header = lang === 'en' ? `BBA ${pkg.version} — help for ${spec.name}` : `BBA ${pkg.version} — ayuda de ${spec.name}`;
  return `${header}\n\n  npm run bba -- ${spec.usage} [--lang es|en]\n`;
}
