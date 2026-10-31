import type { Investigation } from './contracts.ts';
import type { Lang } from './i18n.ts';

export function summary(inv: Investigation) {
  return {
    id: inv.id, variant: inv.environment.variant, requests: inv.evidence.length,
    confirmed: inv.findings.filter(f => f.status === 'confirmed').length,
    notReproduced: inv.findings.filter(f => f.status === 'not-reproduced').length,
    unresolved: inv.findings.filter(f => f.status === 'unresolved').length,
  };
}

export function renderReport(inv: Investigation, lang: Lang = 'es'): string {
  const result = summary(inv);
  if (lang === 'en') {
    return `# BBA — laboratory report

Investigation: \`${inv.id}\` · UTC Date: ${inv.createdAt}

Variant: **${inv.environment.variant}** · BBA: ${inv.toolVersion} · Contract: ${inv.schemaVersion}

Outcome: **${result.confirmed} confirmed**, ${result.notReproduced} not reproduced, ${result.unresolved} unresolved.

## Scope and authorization

Disposable laboratory started by BBA at \`${inv.environment.origin}\`, with two accounts and private synthetic documents. Executed ${result.requests} GET requests out of a maximum budget of ${inv.environment.requestBudget}. The server has been closed; that address must not be reused as a target.

Cross-account read (IDOR/BOLA, CWE-639) was evaluated. Both directions test a single root cause, not two independent vulnerabilities. Variant is laboratory metadata; the evaluator decides strictly from responses and controls.

## Reproduction

1. From this project, with Node 22.13 or newer, run \`npm run bba -- lab --variant ${inv.environment.variant} --out runs/reproduction\` using a non-existent directory.
2. BBA creates accounts A/B with distinct ephemeral credentials and one private document per account. Identifiers and markers change on every run.
3. Verify anonymous denial and authorized owner reads for both owners.
4. Read document B as A and document A as B; compare content against each owner baseline.
5. Inspect \`investigation.json\` and \`report.md\` in the generated directory.

## Hypothesis outcomes
${inv.findings.map(f => `
### ${f.id}: ${f.status}

- Actor: \`${f.actor}\`; expected owner: \`${f.owner}\`.
- Resource: \`/documents/${f.documentId}\`.
- Observation: ${f.observation}
- Evidence: ${f.evidenceIds.map(id => '\`' + id + '\`').join(', ')}.
- Limitation: ${f.limitation}
`).join('')}
## Reproducible evidence

Only a projection of the synthetic contract is retained, never a full HTTP capture. Credentials and sensitive headers are omitted.

\`\`\`json
${JSON.stringify(inv.evidence, null, 2)}
\`\`\`

## Impact and remediation

${result.confirmed ? 'Cross-account read of private synthetic data was demonstrated. Validate server-side document ownership before returning data; the fixed variant enforces that check.' : 'Unauthorized read was not confirmed by these checks. Denial on this path does not establish global safety.'}

Production CVSS is not assigned to a laboratory. Writes, deletes, enumeration and other endpoints were not tested. Transport errors abort execution without producing a success report. Local draft; not submitted.
`;
  }
  return `# BBA — informe de laboratorio

Investigación: \`${inv.id}\` · Fecha UTC: ${inv.createdAt}

Variante: **${inv.environment.variant}** · BBA: ${inv.toolVersion} · Contrato: ${inv.schemaVersion}

Resultado: **${result.confirmed} confirmados**, ${result.notReproduced} no reproducidos, ${result.unresolved} inconclusos.

## Alcance y autorización

Laboratorio desechable creado por BBA en \`${inv.environment.origin}\`, con dos cuentas y documentos sintéticos privados. Se ejecutaron ${result.requests} solicitudes GET de un máximo de ${inv.environment.requestBudget}. El servidor ya fue cerrado; esa dirección no debe reutilizarse como target.

Se evaluó lectura entre cuentas (IDOR/BOLA, CWE-639). Las dos direcciones son pruebas de una misma causa raíz, no dos vulnerabilidades independientes. La variante es metadato del laboratorio; el evaluador decide usando respuestas y controles.

## Reproducción

1. Desde este proyecto, con Node 22.13 o posterior, ejecutá \`npm run bba -- lab --variant ${inv.environment.variant} --out runs/reproduction\` usando una carpeta que no exista.
2. BBA crea cuentas A/B con credenciales efímeras distintas y un documento privado por cuenta. Los identificadores y marcadores cambian en cada ejecución.
3. Comprueba acceso anónimo denegado y lectura autorizada de ambos propietarios.
4. Repite la lectura del documento B como A, y del documento A como B; compara el contenido con la respuesta del propietario.
5. Revisá \`investigation.json\` y \`report.md\` en la carpeta generada. La variante vulnerable debe confirmar ambas direcciones; la corregida debe devolver denegaciones.

## Resultados por hipótesis
${inv.findings.map(f => `
### ${f.id}: ${f.status}

- Actor: \`${f.actor}\`; propietario esperado: \`${f.owner}\`.
- Recurso: \`/documents/${f.documentId}\`.
- Observación: ${f.observation}
- Evidencia: ${f.evidenceIds.map(id => '\`' + id + '\`').join(', ')}.
- Límite: ${f.limitation}
`).join('')}
## Evidencia reproducible

Se conserva una proyección del contrato sintético, no una captura HTTP completa. Las credenciales y los headers sensibles no se guardan. Los hashes identifican estos registros redactados.

\`\`\`json
${JSON.stringify(inv.evidence, null, 2)}
\`\`\`

## Impacto y remediación

${result.confirmed ? 'Se demostró lectura de datos sintéticos privados entre cuentas. Validar en el servidor que el actor tenga permiso sobre el documento antes de devolverlo; la variante corregida aplica ese control.' : 'No se confirmó lectura indebida con estas pruebas. Una denegación en este recorrido no acredita seguridad global.'}

No se asigna CVSS de producción a un laboratorio. No se probaron escritura, borrado, enumeración ni otros endpoints. Los errores de transporte abortan la ejecución y no producen un informe de éxito. Este reporte es local y no fue enviado a ningún programa.
`;
}
