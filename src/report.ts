import type { Investigation } from './contracts.ts';

export function summary(inv: Investigation) {
  return {
    id: inv.id, variant: inv.environment.variant, requests: inv.evidence.length,
    confirmed: inv.findings.filter(f => f.status === 'confirmed').length,
    notReproduced: inv.findings.filter(f => f.status === 'not-reproduced').length,
    unresolved: inv.findings.filter(f => f.status === 'unresolved').length,
  };
}

export function renderReport(inv: Investigation): string {
  const result = summary(inv);
  return `# BBA — informe de laboratorio

Investigación: \`${inv.id}\` · Fecha UTC: ${inv.createdAt}

Variante: **${inv.environment.variant}** · BBA: ${inv.toolVersion} · Contrato: ${inv.schemaVersion}

Resultado: **${result.confirmed} confirmados**, ${result.notReproduced} no reproducidos, ${result.unresolved} inconclusos.

## Alcance y autorización

Laboratorio desechable creado por BBA en \`${inv.environment.origin}\`, con dos cuentas y documentos sintéticos privados. Se ejecutaron ${result.requests} solicitudes GET de un máximo de ${inv.environment.requestBudget}. El servidor ya fue cerrado; esa dirección no debe reutilizarse como target.

Se evaluó lectura entre cuentas (IDOR/BOLA, CWE-639). Las dos direcciones son pruebas de una misma causa raíz, no dos vulnerabilidades independientes. La variante es metadato del laboratorio; el evaluador decide usando respuestas y controles.

## Reproducción

1. Desde este proyecto, con Node 26 o posterior, ejecutá \`npm run bba -- lab --variant ${inv.environment.variant} --out runs/reproduction\` usando una carpeta que no exista.
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
