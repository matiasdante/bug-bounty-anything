import { lstatSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { captureSurface, readPageSurface } from './capture.ts';
import { candidateSummary, importCandidatesFile } from './candidates.ts';
import { evaluateRunFile } from './checks.ts';
import { executeSession } from './execution.ts';
import { assertAuthorized, validatePlan, validateScope } from './scope.ts';
import { createSession, exportSession, inspectSession, readJson, sessionSummary } from './session.ts';
import { importSurfaceFile, surfaceSummary } from './surface.ts';
import type { Surface } from './surface.ts';
import type { Candidate } from './candidates.ts';
import { hunt, validateHunt } from './hunt.ts';
import { prepareInvestigation, startCase } from './prepare.ts';
import { capabilities } from './capabilities.ts';
import { evaluateSemanticFile } from './semantic.ts';
import { evidenceViewFile, exportComparison } from './evidence.ts';
import { prepareCompiled, investigateSurface, resumeInvestigation } from './planner.ts';
import { browserCheck, validateBrowserCheck } from './browser-checks.ts';
import { usingScopeBudget, inspectBudget } from './budget.ts';
import { captureScenario, validateScenario } from './browser-scenario.ts';
import { artifactView } from './artifacts.ts';
import { evaluateJwtIntegrityFile, jwtIntegrityCheck, validateJwtIntegrity } from './jwt-integrity.ts';
import { assembleStudyBundle, compileStudy, executeStudy, prepareStudy, validateStudyBundle } from './study.ts';
import { openCampaign, linkCampaign, campaignStatus, campaignCapture, campaignExecute, campaignResume, preparePolicyReview } from './campaign.ts';
import { templateCheck, resumeTemplateCheck, validateTemplateCheck } from './template-check.ts';
import { ssrfCallbackCheck, resumeSsrfCallbackCheck, validateSsrfCallback } from './ssrf-callback.ts';
import { cacheCheck, resumeCacheCheck, validateCacheCheck } from './cache-check.ts';
import { raceCheck, validateRaceCheck } from './race-check.ts';
import { csrfCheck, validateCsrfCheck } from './csrf-check.ts';

export type Tool = {
  name: string; description: string; network: boolean; args: Record<string, string>;
  run: (args: Record<string, string>, path: (value: string) => string) => Promise<unknown>;
};

// Every path is resolved inside the workspace root; the server never takes credentials as arguments.
// Links are followed on the deepest existing ancestor, so a link inside the root cannot lead out of it.
export function confine(root: string) {
  const base = realpathSync(root);
  const outside = (from: string, to: string) => { const rel = relative(from, to); return rel.startsWith('..') || isAbsolute(rel); };
  return (value: string): string => {
    const full = resolve(root, value);
    if (!relative(root, full) || outside(root, full)) throw new Error('Path outside the workspace root');
    let probe = full;
    for (;;) { try { lstatSync(probe); break; } catch { probe = dirname(probe); } }
    let real: string;
    try { real = realpathSync(probe); } catch { throw new Error('Path outside the workspace root'); } // dangling link
    if (outside(base, real)) throw new Error('Path outside the workspace root');
    return full;
  };
}

export const tools: Tool[] = [
  { name: 'campaign_open', network: false, description: 'Create a new, offline campaign ledger for one canonical target. Sends no requests and does not claim permission.',
    args: { target: 'Canonical target URL', out: 'New campaign directory' },
    run: async (a, p) => openCampaign(p(a.out), a.target) },
  { name: 'campaign_link', network: false, description: 'Validate and attach a scope, declared policy review, surface, page capture, controlled profile, completed run or draft report inside a campaign. Immutable digest chain; no requests.',
    args: { campaign: 'Campaign directory', kind: 'scope, policy, surface, page, profile, run or report', artifact: 'Artifact inside campaign directory' },
    run: async (a, p) => linkCampaign(p(a.campaign), a.kind, p(a.artifact)) },
  { name: 'campaign_status', network: false, description: 'Verify all linked campaign artifacts, report budget and blockers, and recommend the next supported step. Does not confirm permission or a vulnerability.',
    args: { campaign: 'Campaign directory' }, run: async (a, p) => campaignStatus(p(a.campaign)) },
  { name: 'campaign_policy_review', network: false, description: 'Bind a saved local policy-source.txt by SHA-256 to the current scope and an explicit operator decision. Does not fetch policy or verify owner permission.',
    args: { campaign: 'Campaign directory containing scope and policy-source.txt', sourceUrl: 'Official policy or owner authorization HTTPS URL',
      sourceKind: 'official-program-policy or owner-written-authorization', decision: 'authorized or uncertain' },
    run: async (a, p) => preparePolicyReview(p(a.campaign), a.sourceUrl,
      a.sourceKind as 'official-program-policy' | 'owner-written-authorization', a.decision as 'authorized' | 'uncertain') },
  { name: 'campaign_capture', network: true, description: 'SENDS BOUNDED GET REQUESTS. Capture the exact campaign target after an operator policy review and scoped budget. Saves page facts and an observed surface. One attempt per campaign.',
    args: { campaign: 'Campaign directory with linked scope and authorized policy review' },
    run: async (a, p) => campaignCapture(p(a.campaign)) },
  { name: 'campaign_execute', network: true, description: 'SENDS BOUNDED REQUESTS. Execute the current controlled semantic profile against the linked surface, using the shared campaign budget; save evidence and draft report. One attempt per profile.',
    args: { campaign: 'Campaign directory with current surface and controlled profile' },
    run: async (a, p) => campaignExecute(p(a.campaign)) },
  { name: 'campaign_resume', network: true, description: 'MAY SEND BOUNDED REQUESTS. Validate the current profile and checkpointed run, resume only unstarted steps with the same scope/budget, then link its report. Refuses uncertain reservations and expired authorization.',
    args: { campaign: 'Campaign directory with an interrupted investigation action' },
    run: async (a, p) => campaignResume(p(a.campaign)) },
  { name: 'study_bundle', network: false, description: 'Assemble a sanitized published-case study bundle from a case manifest, operator policy, imported surface, historical route notes and controlled-account profile. Offline.',
    args: { caseFile: 'Published case manifest', policy: 'Operator-extracted program policy JSON', surface: 'Imported surface bundle JSON', historical: 'Structured historical route notes JSON', profile: 'Controlled test profile JSON', out: 'New study bundle JSON file' },
    run: async (a, p) => { const bundle = assembleStudyBundle({ caseFile: p(a.caseFile), policy: p(a.policy), surface: p(a.surface),
      historical: p(a.historical), profile: p(a.profile) }, p(a.out));
      return { case: bundle.case.id, surfaceEntries: bundle.surface.surface.entries.length }; } },
  { name: 'study_plan', network: false, description: 'Compile a published-case study bundle into a provenance graph, one bounded hypothesis and exact execution scope. Offline; unresolved cases send nothing.',
    args: { input: 'Path to sanitized study bundle JSON', out: 'New output directory' },
    run: async (a, p) => { const bundle = readJson(p(a.input)); validateStudyBundle(bundle); const compiled = prepareStudy(p(a.out), bundle);
      return { status: compiled.status, reason: compiled.reason, candidates: compiled.candidates.length, selected: compiled.selected }; } },
  { name: 'study_run', network: true, description: 'MAY SEND FOUR REQUESTS. Compile a published-case study bundle, enforce exact policy and shared budget, run controlled JWT proof, and write a five-question report. No request if no unique candidate.',
    args: { input: 'Path to sanitized study bundle JSON', out: 'New output directory' },
    run: async (a, p) => { const bundle = readJson(p(a.input)); validateStudyBundle(bundle); const compiled = compileStudy(bundle);
      return compiled.scope ? usingScopeBudget(compiled.scope, p(a.input), budget => executeStudy(p(a.out), bundle, { budget }), p)
        : executeStudy(p(a.out), bundle); } },
  { name: 'resume_study', network: true, description: 'MAY SEND REMAINING REQUESTS. Resume a study only with the same bundle, budget location, original controlled token and mutation; uncertain attempts are not replayed.',
    args: { study: 'Existing study directory', input: 'Original sanitized bundle JSON' },
    run: async (a, p) => { const bundle = readJson(p(a.input)); validateStudyBundle(bundle); const compiled = compileStudy(bundle);
      return compiled.scope ? usingScopeBudget(compiled.scope, p(a.input), budget => executeStudy(p(a.study), bundle, { budget, resume: true }), p)
        : executeStudy(p(a.study), bundle, { resume: true }); } },
  { name: 'jwt_check', network: true, description: 'SENDS FOUR BOUNDED REQUESTS. Test signed JWT claim integrity with one controlled account, anonymous denial, two valid-token controls and an altered token retaining its original signature. Saves only selected response fact digests.',
    args: { scope: 'Path to scope.json', config: 'Path to JWT integrity config', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateJwtIntegrity(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => jwtIntegrityCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'resume_jwt', network: true, description: 'MAY SEND REQUESTS. Resume a JWT integrity check only with the same scope, config and original controlled token. Never replays uncertain attempts.',
    args: { check: 'Existing JWT check directory', scope: 'Original canonical scope path', config: 'Original JWT integrity config' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateJwtIntegrity(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => jwtIntegrityCheck(p(a.check), scope, config, { budget, resume: true }), p); } },
  { name: 'template_check', network: true, description: 'SENDS THREE BOUNDED GET REQUESTS. Compare one literal input and two harmless arithmetic template expressions in an exact authorized query parameter and JSON field. Confirms only expression evaluation under an operator-declared literal-input rule.',
    args: { scope: 'Canonical scope.json path', config: 'Template check config JSON', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateTemplateCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => templateCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'resume_template_check', network: true, description: 'MAY SEND REMAINING REQUESTS. Resume a template arithmetic check only with the same scope, config and shared budget; uncertain attempts are not replayed.',
    args: { check: 'Existing template check directory', scope: 'Original canonical scope.json path', config: 'Original config JSON' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateTemplateCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => resumeTemplateCheck(p(a.check), scope, config, { budget }), p); } },
  { name: 'ssrf_callback_check', network: true, description: 'SENDS AT MOST FOUR BOUNDED GET REQUESTS. Test one authorized URL-fetch input with an operator-owned opaque callback and a before/after boolean receipt. No internal-network or metadata probing.',
    args: { scope: 'Canonical scope.json path', config: 'Owned callback config JSON', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateSsrfCallback(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => ssrfCallbackCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'resume_ssrf_callback', network: true, description: 'MAY SEND REMAINING REQUESTS. Resume an owned callback proof with the same exact scope/config/budget; uncertain attempts are not replayed.',
    args: { check: 'Existing callback check directory', scope: 'Original canonical scope.json path', config: 'Original callback config JSON' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateSsrfCallback(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => resumeSsrfCallbackCheck(p(a.check), scope, config, { budget }), p); } },
  { name: 'cache_check', network: true, description: 'SENDS SEVEN BOUNDED GET REQUESTS. Compare two controlled identities, anonymous denial, semantically inert cache-busted controls and one shared URL. Confirms only cache-correlated cross-identity exposure.',
    args: { scope: 'Canonical scope.json path', config: 'Cache check config JSON', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateCacheCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => cacheCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'resume_cache_check', network: true, description: 'MAY SEND REMAINING REQUESTS. Resume a controlled cache exposure check with the same scope, config, identities and budget; uncertain attempts are not replayed.',
    args: { check: 'Existing cache check directory', scope: 'Original canonical scope.json path', config: 'Original cache config JSON' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateCacheCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => resumeCacheCheck(p(a.check), scope, config, { budget }), p); } },
  { name: 'race_check', network: true, description: 'SENDS AT MOST SEVEN REQUESTS. On two disposable owned resources, verify sequential single-use denial, then issue exactly two concurrent declared JSON POSTs and inspect the final count. Requires zero scope interval; no replay.',
    args: { scope: 'Canonical scope.json path', config: 'Single-use race config JSON', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateRaceCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => raceCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'csrf_check', network: true, description: 'SENDS AT MOST FIVE BOUNDED REQUESTS. Verify anonymous denial, an actual browser cross-origin form POST with declared test cookie, and a controlled state change. Requires operator-owned reversible state and a genuinely cross-site origin for a CSRF conclusion.',
    args: { scope: 'Canonical scope.json path', config: 'Cross-origin form config JSON', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const config = readJson(p(a.config)); validateCsrfCheck(config, scope);
      return usingScopeBudget(scope, p(a.scope), budget => csrfCheck(p(a.out), scope, config, { budget }), p); } },
  { name: 'evaluate_jwt', network: false, description: 'Evaluate an existing JWT integrity run offline against its declared proof pointer and controls.',
    args: { run: 'JWT check run directory', config: 'Original JWT integrity config', out: 'New result JSON file' },
    run: async (a, p) => evaluateJwtIntegrityFile(p(a.run), p(a.config), p(a.out)) },
  { name: 'resume_investigation', network: true, description: 'MAY SEND REQUESTS. Resume an interrupted compiled investigation with the original scope and checks. Re-evaluates retained proof before sending anything and stops if already confirmed.',
    args: { investigation: 'Compiled case directory', scope: 'Path to canonical scope.json', out: 'New report JSON or Markdown' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); return usingScopeBudget(scope, p(a.scope), budget => resumeInvestigation(p(a.investigation), scope, p(a.out), { budget }), p); } },
  { name: 'start_case', network: false, description: 'Create an offline case and investigation ledger from a canonical target URL before scope/time window is known. Sends no requests and creates no executable scope or plan.',
    args: { target: 'Canonical service URL without embedded credentials/query', out: 'New case directory' }, run: async (a, p) => startCase(p(a.out), a.target) },
  { name: 'artifact_view', network: false, description: 'Verify sealed hunt/browser journal and result integrity, then read summary or bounded event/field pages by stable IDs. Offline.',
    args: { artifact: 'Hunt, browser-check or scenario output directory', query: 'Path to view query JSON' }, run: async (a, p) => artifactView(p(a.artifact), readJson(p(a.query))) },
  { name: 'browser_scenario', network: true, description: 'SENDS REQUESTS AND DECLARED FORM ACTIONS. Execute a controlled navigate/fill/click/wait workflow with exact request URL/method/body matching, bounded declared redirects and in-memory browser cookie rotation. Captures facts, not automatic vulnerability confirmation.',
    args: { scope: 'Path to scope.json', config: 'Path to scenario.json', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const c = readJson(p(a.config)); validateScenario(c, scope); return usingScopeBudget(scope, p(a.scope), budget => captureScenario(p(a.out), scope, c, { budget }), p); } },
  { name: 'capabilities', network: false, description: 'Report implemented transport, confirmation, evidence and integration capabilities and limitations. Offline; tools/list defines connected tool availability.', args: {}, run: async () => capabilities() },
  { name: 'plan_investigation', network: false, description: 'Build identity controls and semantic hypotheses from a verified surface inventory and explicit business-boundary profile. Offline; leaves unsupported and unbound entries unresolved.',
    args: { scope: 'Path to scope.json', surface: 'Path to imported surface bundle', profile: 'Path to policy/identity profile', out: 'New case directory' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      const r = prepareCompiled(p(a.out), scope, readJson(p(a.surface)), readJson(p(a.profile)));
      return { planned: r.checks.checks.length, requests: r.plan?.steps.length ?? 0, coverage: r.coverage };
    } },
  { name: 'investigate', network: true, description: 'SENDS REQUESTS. Plan from imported surface and declared policy, verify server identities and read boundaries, retain semantic evidence and report. Stops at the first minimal confirmed proof.',
    args: { scope: 'Path to scope.json', surface: 'Path to imported surface bundle', profile: 'Path to policy/identity profile', out: 'New case directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); return usingScopeBudget(scope, p(a.scope), budget => investigateSurface(p(a.out), scope, readJson(p(a.surface)), readJson(p(a.profile)), { budget }), p); } },
  { name: 'browser_check', network: true, description: 'SENDS REQUESTS. Confirm controlled XSS marker execution or cookie-authenticated CORS reads in isolated Chromium with exact declared requests, durable journal and bounded budget.',
    args: { scope: 'Path to scope.json', config: 'Path to browser-check.json', out: 'New output directory' },
    run: async (a, p) => { const scope = readJson(p(a.scope)); validateScope(scope); const c = readJson(p(a.config)); validateBrowserCheck(c, scope); return usingScopeBudget(scope, p(a.scope), budget => browserCheck(p(a.out), scope, c, { budget }), p); } },
  { name: 'inspect_budget', network: false, description: 'Verify and read a shared program request-budget journal offline, including uncertain reservations.', args: { budget: 'Budget directory' }, run: async (a, p) => inspectBudget(p(a.budget)) },
  { name: 'evaluate_semantic', network: false, description: 'Evaluate projected identity, role, ownership, tenant and protected-field evidence under an explicit business rule. Offline; raw body hashes alone never confirm.',
    args: { run: 'Run directory', checks: 'Path to semantic checks', out: 'New JSON or Markdown file' }, run: async (a, p) => evaluateSemanticFile(p(a.run), p(a.checks), p(a.out)) },
  { name: 'evidence_view', network: false, description: 'Read summary or bounded attempts/field pages by stable IDs and optional expected revision digest. Offline; does not rerun requests.',
    args: { run: 'Run directory', query: 'Path to view query JSON' }, run: async (a, p) => evidenceViewFile(p(a.run), readJson(p(a.query))) },
  { name: 'compare_runs', network: false, description: 'Compare verified run definitions, statuses, body digests and selected field facts. Offline; differences are not vulnerability classifications.',
    args: { before: 'Earlier run directory', after: 'Later run directory', out: 'New comparison JSON' }, run: async (a, p) => exportComparison(p(a.before), p(a.after), p(a.out)) },
  { name: 'prepare', network: false, description: 'Prepare a new investigation from a scope and exact seed URL. Writes scope, seed GET plan and investigation ledger. Offline; does not verify owner permission.',
    args: { scope: 'Path to scope.json', target: 'Exact authorized seed URL', out: 'New investigation folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      return prepareInvestigation(p(a.out), scope, a.target);
    } },
  { name: 'hunt', network: true, description: 'SENDS REQUESTS. Discover in-scope HTML links and validate owner-only BOLA using two controlled accounts and server identity controls. Prepares a report without submission.',
    args: { scope: 'Path to scope.json', config: 'Path to hunt.json', out: 'New output folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      const config = readJson(p(a.config)); validateHunt(config, scope);
      const r = await usingScopeBudget(scope, p(a.scope), budget => hunt(p(a.out), scope, config, { budget }), p);
      return { requests: r.requests, stopped: r.stopped, findings: r.findings };
    } },
  { name: 'scope_check', network: false, description: 'Validate scope.json and plan.json offline. Does not verify the owner\'s permission and sends no request.',
    args: { scope: 'Path to scope.json', plan: 'Path to plan.json' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      validatePlan(readJson(p(a.plan)), scope);
      return 'Scope, plan and time window are valid; owner permission was not verified and no request was sent.';
    } },
  { name: 'import_surface', network: false, description: 'Project an endpoint inventory from a HAR 1.2, Swagger 2.0/OpenAPI 3.x JSON or REA capture Evidence file. Offline.',
    args: { format: 'har, openapi or rea', input: 'Path to the source JSON', out: 'New output file' },
    run: async (a, p) => surfaceSummary(importSurfaceFile(p(a.input), a.format as Surface['format'], p(a.out))) },
  { name: 'import_candidates', network: false, description: 'Normalize ZAP, Nuclei or Subfinder output into unvalidated candidates compared with the scope. Nothing is executed or contacted.',
    args: { format: 'zap, nuclei or subfinder', input: 'Path to the scanner output', scope: 'Path to scope.json', out: 'New output file' },
    run: async (a, p) => candidateSummary(importCandidatesFile(p(a.input), a.format as Candidate['source'], readJson(p(a.scope)), p(a.out))) },
  { name: 'inspect_run', network: false, description: 'Verify a run folder and summarize its checkpoints. Offline.',
    args: { run: 'Run folder created by run' }, run: async (a, p) => sessionSummary(inspectSession(p(a.run))) },
  { name: 'report_run', network: false, description: 'Export a verified run as Markdown into a new file. Offline.',
    args: { run: 'Run folder', out: 'New .md file' }, run: async (a, p) => { exportSession(p(a.run), p(a.out), 'markdown'); return 'Evidence verified and exported.'; } },
  { name: 'export_run', network: false, description: 'Export a verified run as JSON into a new file. Offline.',
    args: { run: 'Run folder', out: 'New .json file' }, run: async (a, p) => { exportSession(p(a.run), p(a.out), 'json'); return 'Evidence verified and exported.'; } },
  { name: 'evaluate_run', network: false, description: 'Evaluate bola, bfla or property-exposure checks (control, baseline, probe) against a verified run. Offline.',
    args: { run: 'Run folder', checks: 'Path to checks.json', out: 'New .json or .md file' },
    run: async (a, p) => evaluateRunFile(p(a.run), p(a.checks), p(a.out)).findings.map(f => ({ check: f.checkId, class: f.class, status: f.status })) },
  { name: 'run', network: true, description: 'SENDS REQUESTS. Execute a GET plan inside scope.json with its persisted budget. Credentials come from the server environment.',
    args: { scope: 'Path to scope.json', plan: 'Path to plan.json', out: 'New run folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      const plan = readJson(p(a.plan)); validatePlan(plan, scope);
      createSession(p(a.out), scope, plan);
      return sessionSummary(await usingScopeBudget(scope, p(a.scope), budget => executeSession(p(a.out), scope, { budget }), p));
    } },
  { name: 'resume', network: true, description: 'SENDS REQUESTS. Resume a paused or interrupted run with the same scope.',
    args: { run: 'Run folder', scope: 'Path to the same scope.json' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      return sessionSummary(await usingScopeBudget(scope, p(a.scope), budget => executeSession(p(a.run), scope, { budget }), p));
    } },
  { name: 'capture', network: true, description: 'SENDS REQUESTS. Navigate the plan with headless Chromium; only exact in-scope GETs leave the browser.',
    args: { scope: 'Path to scope.json', plan: 'Path to plan.json', out: 'New output folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      const plan = readJson(p(a.plan)); validatePlan(plan, scope);
      const { capture, surface, pages } = await usingScopeBudget(scope, p(a.scope), budget => captureSurface(p(a.out), scope, plan, { budget }), p);
      return { ...surfaceSummary(surface), stopReason: capture.stopReason, counts: capture.counts, pageFacts: pages.pages.length };
    } },
  { name: 'inspect_web_page', network: true, description: 'SENDS BOUNDED GET REQUESTS. Inspect one authorized page in isolated Chromium; return in-scope status plus bounded link paths, form actions/field names and script paths. Values and query strings are discarded. Discovered paths do not expand scope.',
    args: { scope: 'Canonical scope.json path', url: 'Exact authorized seed URL', out: 'New capture folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope); assertAuthorized(scope, a.url);
      const plan = { schemaVersion: 1, steps: [{ id: 'seed', method: 'GET', url: a.url, credentialEnv: null }] };
      validatePlan(plan, scope);
      const { capture, pages } = await usingScopeBudget(scope, p(a.scope), budget => captureSurface(p(a.out), scope, plan, { budget }), p);
      return { stopReason: capture.stopReason, counts: capture.counts, page: pages.pages[0] ?? null, output: p(a.out) };
    } },
  { name: 'page_view', network: false, description: 'Verify and read bounded DOM route/form/script facts from a saved browser capture. Offline; never returns field values or query strings.',
    args: { capture: 'Capture folder containing pages.json' },
    run: async (a, p) => readPageSurface(p(a.capture)) },
];
