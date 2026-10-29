import { isAbsolute, relative, resolve } from 'node:path';
import { captureSurface } from './capture.ts';
import { candidateSummary, importCandidatesFile } from './candidates.ts';
import { evaluateRunFile } from './checks.ts';
import { executeSession } from './execution.ts';
import { validatePlan, validateScope } from './scope.ts';
import { createSession, exportSession, inspectSession, readJson, sessionSummary } from './session.ts';
import { importSurfaceFile, surfaceSummary } from './surface.ts';
import type { Surface } from './surface.ts';
import type { Candidate } from './candidates.ts';

export type Tool = {
  name: string; description: string; network: boolean; args: Record<string, string>;
  run: (args: Record<string, string>, path: (value: string) => string) => Promise<unknown>;
};

// Every path is resolved inside the workspace root; the server never takes credentials as arguments.
export function confine(root: string) {
  return (value: string): string => {
    const full = resolve(root, value), rel = relative(root, full);
    if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw new Error('Path outside the workspace root');
    return full;
  };
}

export const tools: Tool[] = [
  { name: 'scope_check', network: false, description: 'Validate scope.json and plan.json offline. Does not verify the owner\'s permission and sends no request.',
    args: { scope: 'Path to scope.json', plan: 'Path to plan.json' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      validatePlan(readJson(p(a.plan)), scope);
      return 'Scope, plan and time window are valid; owner permission was not verified and no request was sent.';
    } },
  { name: 'import_surface', network: false, description: 'Project an endpoint inventory from a HAR 1.2, OpenAPI 3.x JSON or REA capture Evidence file. Offline.',
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
      return sessionSummary(await executeSession(p(a.out), scope));
    } },
  { name: 'resume', network: true, description: 'SENDS REQUESTS. Resume a paused or interrupted run with the same scope.',
    args: { run: 'Run folder', scope: 'Path to the same scope.json' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      return sessionSummary(await executeSession(p(a.run), scope));
    } },
  { name: 'capture', network: true, description: 'SENDS REQUESTS. Navigate the plan with headless Chromium; only exact in-scope GETs leave the browser.',
    args: { scope: 'Path to scope.json', plan: 'Path to plan.json', out: 'New output folder' },
    run: async (a, p) => {
      const scope = readJson(p(a.scope)); validateScope(scope);
      const plan = readJson(p(a.plan)); validatePlan(plan, scope);
      const { capture, surface } = await captureSurface(p(a.out), scope, plan);
      return { ...surfaceSummary(surface), stopReason: capture.stopReason, counts: capture.counts };
    } },
];
