import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { digest } from './contracts.ts';
import { assertAuthorized, strictUrl, validatePlan, validateScope } from './scope.ts';
import type { Plan, Scope } from './scope.ts';

export function startCase(folder: string, target: string) {
  strictUrl(target);
  const out = resolve(folder); mkdirSync(dirname(out), { recursive: true }); mkdirSync(out);
  const manifest = { schemaVersion: 1, createdAt: new Date().toISOString(), target, authorizationVerification: 'unverified', requestsSent: 0 };
  writeFileSync(join(out, 'case.json'), JSON.stringify({ manifest, sha256: digest(manifest) }, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(out, 'investigation.md'), `# Caso BBA pendiente de alcance\n\nObjetivo declarado: \`${target}\`. Cero solicitudes enviadas. Autorización sin verificar.\n\n`
    + '## Política y límites\n\nRegistrar fuente y fecha de lectura, activos/técnicas permitidos y excluidos, ventana UTC y presupuesto. No se generó scope ni plan ejecutable; no inventar fechas para habilitar solicitudes.\n\n'
    + '## Superficie e hipótesis\n\nRegistrar procedencia de documentos y capturas históricas. Ningún hallazgo confirmado. Mantener observaciones, inferencias y desconocidos separados.\n\n'
    + '## Continuidad\n\nContinuar investigación pública e importaciones offline. Al establecer el permiso, escribir un scope canónico con budgetId y preparar/compilar cada fase en una subcarpeta nueva, conservando este registro y su consumo total.\n', { flag: 'wx', mode: 0o600 });
  return { output: out, target, authorizationVerification: 'unverified', requestsSent: 0, files: ['case.json', 'investigation.md'] };
}

// Offline bootstrap: the agent establishes the real program permission first.
// A successful structural check never upgrades it to verified authorization.
export function prepareInvestigation(folder: string, scope: Scope, target: string) {
  validateScope(scope); assertAuthorized(scope, target);
  const plan: Plan = { schemaVersion: 1, steps: [{ id: 'seed', method: 'GET', url: target, credentialEnv: null }] };
  validatePlan(plan, scope);
  const out = resolve(folder);
  mkdirSync(dirname(out), { recursive: true }); mkdirSync(out);
  const write = (name: string, value: string) => writeFileSync(join(out, name), value, { flag: 'wx', mode: 0o600 });
  write('scope.json', JSON.stringify(scope, null, 2) + '\n');
  write('plan.json', JSON.stringify(plan, null, 2) + '\n');
  const manifest = { schemaVersion: 1, createdAt: new Date().toISOString(), target, scopeDigest: digest(scope),
    authorizationVerification: 'operator-required', requestsSent: 0 };
  write('case.json', JSON.stringify({ manifest, sha256: digest(manifest) }, null, 2) + '\n');
  write('investigation.md', `# Investigación BBA\n\nObjetivo: \`${target}\`. Estado inicial: preparado; cero solicitudes enviadas.\n\n`
    + `## Política y alcance\n\nReferencia declarada: ${scope.authorization.reference}. Vigencia: ${scope.authorization.validFrom} a ${scope.authorization.validUntil}.\n\n`
    + `La preparación valida contratos; la verificación real del permiso sigue a cargo del agente/operador. Registrar fuente vigente, fecha de lectura, activos, técnicas permitidas/prohibidas, cuentas controladas y marcadores requeridos antes de ejecutar. No usar una referencia como prueba de permiso.\n\n`
    + `## Presupuesto compartido de la investigación\n\nMáximo declarado: ${scope.limits.maxRequests} solicitudes; intervalo mínimo: ${scope.limits.minIntervalMs} ms. ${scope.budgetId ? `Presupuesto compartido: ${scope.budgetId}; conservar la ubicación del scope original entre fases y revisar su ledger antes de retomar.` : 'Scope histórico sin budgetId: límite por ejecución; registrar consumo entre fases sin reiniciarlo.'} Registrar acá también consumo de herramientas externas.\n\n`
    + `## Superficie y procedencia\n\nSemilla declarada, todavía no observada: \`${target}\`. Agregar endpoints y su evidencia de origen; descubrir una ruta no amplía scope.\n\n`
    + `## Hipótesis y evidencia\n\nSin hipótesis probadas. Por cada una registrar ID estable, recurso/clase, regla esperada, precondiciones/cuentas, baseline/control/sonda, referencias a evidencia, observación, inferencia, desconocidos y estado. Confirmar requiere un efecto de seguridad reproducido; un hash, CVE o resultado de scanner es un indicio.\n\n`
    + `## Continuidad\n\nVerificar la política antes de ejecutar plan.json. Usar una salida nueva dentro de esta investigación para run, capture o hunt. Elegir el siguiente bloque a partir de evidencia y conservar acá preguntas respondidas, pendientes, causa de detención y presupuesto consumido. No repetir intentos inciertos.\n\n`
    + `## Cierre\n\nNo hay hallazgos confirmados ni conclusión sobre seguridad. Al cerrar, enlazar reportes y evidencia, indicar cobertura real y preguntas sin resolver. Preparar el reporte; enviarlo requiere autorización explícita.\n`);
  return { output: out, target, requestsSent: 0, authorizationVerification: manifest.authorizationVerification,
    files: ['scope.json', 'plan.json', 'case.json', 'investigation.md'] };
}
