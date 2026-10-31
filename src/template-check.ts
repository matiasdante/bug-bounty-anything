import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { executeSession } from './execution.ts';
import { fields, integer, queryParamNameRegex, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';
import { createSession, inspectSession, readJson } from './session.ts';
import type { Session } from './session.ts';
import type { ProgramBudget } from './budget.ts';
import type { Lang } from './i18n.ts';

export type TemplateCheck = { schemaVersion: 1; class: 'template-arithmetic'; policyReference: string;
  url: string; parameter: string; pointer: string; operands: [number, number, number]; credentialEnv: string | null };
const refs = ['BBA_INPUT_TEMPLATE_LITERAL', 'BBA_INPUT_TEMPLATE_FIRST', 'BBA_INPUT_TEMPLATE_SECOND'] as const;

export function validateTemplateCheck(value: unknown, scope: Scope): asserts value is TemplateCheck {
  validateScope(scope);
  fields(value, ['schemaVersion', 'class', 'policyReference', 'url', 'parameter', 'pointer', 'operands', 'credentialEnv']);
  if (value.schemaVersion !== 1 || value.class !== 'template-arithmetic'
    || typeof value.policyReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,199}$/.test(value.policyReference)
    || typeof value.parameter !== 'string' || value.parameter.length > 64 || !queryParamNameRegex.test(value.parameter)
    || typeof value.pointer !== 'string' || value.pointer.length > 512 || !/^(\/(?:[^~]|~[01])*)?$/.test(value.pointer)
    || !Array.isArray(value.operands) || value.operands.length !== 3 || new Set(value.operands).size !== 3
    || value.credentialEnv !== null && (typeof value.credentialEnv !== 'string' || !/^BBA_(TOKEN|COOKIE)_[A-Z0-9_]{1,50}$/.test(value.credentialEnv)))
    throw new Error('Invalid template check');
  value.operands.forEach((n: unknown) => integer(n, 2, 997));
  validatePlan(plan(value as TemplateCheck), scope);
  if (scope.limits.maxRequests < 3) throw new Error('Template proof needs three request reservations');
}

function plan(config: TemplateCheck): Plan {
  return { schemaVersion: 1, steps: ['literal', 'first', 'second'].map((id, i) => ({ id, method: 'GET' as const,
    url: config.url, credentialEnv: config.credentialEnv,
    query: [{ name: config.parameter, valueEnv: refs[i] }], observe: [{ name: 'rendered', pointer: config.pointer }] })) };
}
function inputs(config: TemplateCheck): Record<string, string | undefined> {
  const [a, b, c] = config.operands;
  return { ...process.env, [refs[0]]: `${a}*${b}`, [refs[1]]: `{{${a}*${b}}}`, [refs[2]]: `{{${b}*${c}}}` };
}
export function evaluateTemplate(session: Session, config: TemplateCheck) {
  if (digest(session.plan) !== digest(plan(config))) throw new Error('Template plan changed');
  const fact = (id: string) => session.attempts.find(a => a.stepId === id && a.outcome === 'succeeded'
    && a.response?.status === 200)?.response?.facts?.find(f => f.name === 'rendered');
  const [a, b, c] = config.operands;
  const literal = fact('literal'), first = fact('first'), second = fact('second');
  const matches = (value: typeof literal, expected: string) => value?.kind === 'string' && value.meaningful && value.sha256 === digest(expected);
  const baseline = matches(literal, `${a}*${b}`);
  const status = !baseline ? 'unresolved' : matches(first, `${a * b}`) && matches(second, `${b * c}`) ? 'confirmed'
    : matches(first, `{{${a}*${b}}}`) && matches(second, `{{${b}*${c}}}`) ? 'not-reproduced' : 'unresolved';
  return { schemaVersion: 1, class: config.class, status, sessionId: session.id, scopeDigest: session.scopeDigest,
    configDigest: digest(config), evidence: ['literal', 'first', 'second'].map(id => session.id + ':' + id),
    reason: status === 'confirmed' ? 'Two harmless arithmetic expressions were evaluated while the literal control remained unchanged under the declared literal-input rule.'
      : status === 'not-reproduced' ? 'Both template expressions remained literal in the controlled response.'
        : 'The literal control or both independent expression comparisons were incomplete or ambiguous.',
    limitations: ['Only this template expression syntax and JSON field were checked.',
      'The operator must establish that this field should treat the input as literal text; intentional template rendering is not a vulnerability.',
      'No file, secret, command, database or cross-account access was attempted.'] };
}
function report(result: ReturnType<typeof evaluateTemplate>, config: TemplateCheck, lang: Lang = 'es'): string {
  const [a, b, c] = config.operands;
  if (lang === 'en') {
    return `# BBA — template-arithmetic: ${result.status}\n\nLocal draft for review; not submitted.\n\n`
      + `## What it is\n\nTemplate expression evaluation in parameter \`${config.parameter}\` of \`${config.url}\` under declared rule ${config.policyReference}.\n\n`
      + `## How it was found\n\nCompared a literal control input against two harmless arithmetic expressions in JSON field \`${config.pointer}\`.\n\n`
      + `## Exploitability proof\n\nStatus: **${result.status}**. ${result.reason} Evidence: ${result.evidence.map(id => '`' + id + '`').join(', ')}.\n\n`
      + `## Reproduction\n\nWith the same scope and owned account, send \`${a}*${b}\`, \`{{${a}*${b}}}\`, and \`{{${b}*${c}}}\` in the declared parameter; compare the projected field and checkpoints. Never replay uncertain reservations.\n\n`
      + `## Remediation\n\nTreat user-controlled input strictly as literal data during rendering.\n\n`
      + `## Limitations\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
  }
  return `# BBA — template-arithmetic: ${result.status}\n\nBorrador para revisión; no enviado.\n\n`
    + `## Qué es\n\nEvaluación de expresiones de plantilla en el parámetro \`${config.parameter}\` de \`${config.url}\` bajo la regla declarada ${config.policyReference}.\n\n`
    + `## Cómo se encontró\n\nSe comparó una entrada literal con dos expresiones aritméticas inocuas en el campo JSON \`${config.pointer}\`.\n\n`
    + `## Demostración de explotabilidad\n\nEstado: **${result.status}**. ${result.reason} Evidencia: ${result.evidence.map(id => '`' + id + '`').join(', ')}. No se infiere lectura de archivos, ejecución de comandos ni acceso a otros datos.\n\n`
    + `## Cómo reproducirlo\n\nCon el mismo scope y cuenta propia, enviar \`${a}*${b}\`, \`{{${a}*${b}}}\` y \`{{${b}*${c}}}\` en el parámetro declarado; comparar el campo proyectado y los checkpoints. No repetir reservas inciertas.\n\n`
    + `## Cómo corregirlo\n\nTratar esa entrada como dato literal al renderizar; deshabilitar la evaluación de plantillas sobre texto controlado por usuarios. Agregar una regresión que conserve ambas expresiones como texto.\n\n`
    + `## Límites\n\n${result.limitations.map(item => '- ' + item).join('\n')}\n`;
}
function save(folder: string, name: string, session: Session, config: TemplateCheck, lang: Lang = 'es') {
  const result = evaluateTemplate(session, config);
  writeFileSync(join(folder, name + '.json'), JSON.stringify({ result, sha256: digest(result) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, name + '.md'), report(result, config, lang), { flag: 'wx', mode: 0o600 });
  return result;
}
export async function templateCheck(folder: string, scope: Scope, config: TemplateCheck,
  options: { signal?: AbortSignal; budget?: ProgramBudget; lang?: Lang } = {}) {
  validateTemplateCheck(config, scope);
  mkdirSync(dirname(folder), { recursive: true }); mkdirSync(folder);
  writeFileSync(join(folder, 'scope.json'), JSON.stringify(scope, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(folder, 'config.json'), JSON.stringify(config, null, 2), { flag: 'wx', mode: 0o600 });
  createSession(join(folder, 'run'), scope, plan(config));
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: inputs(config) });
  return save(folder, 'template-check', session, config, options.lang);
}
export async function resumeTemplateCheck(folder: string, scope: Scope, config: TemplateCheck,
  options: { signal?: AbortSignal; budget?: ProgramBudget; lang?: Lang } = {}) {
  validateTemplateCheck(config, scope);
  if (digest(readJson(join(folder, 'scope.json'))) !== digest(scope)
    || digest(readJson(join(folder, 'config.json'))) !== digest(config)) throw new Error('Template definition changed');
  if (existsSync(join(folder, 'template-resumed.json')) || existsSync(join(folder, 'template-resumed.md')))
    throw new Error('Resumed template result already exists');
  const session = await executeSession(join(folder, 'run'), scope, { ...options, credentials: inputs(config) });
  return save(folder, 'template-resumed', session, config, options.lang);
}
