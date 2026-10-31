# Estudios reproducibles de casos publicados

El primer estudio toma como referencia metodológica [el artículo de Faav sobre Titan](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records). El manifiesto `cases/faav-titan-jwt-2026.json` identifica la publicación y la clase de falla; no contiene tokens, datos del servicio ni un objetivo autorizado. La investigación del artículo y una reproducción actual son cosas distintas.

## Recorrido del agente

1. Leer la política vigente del programa y anotar la fuente, ventana, activos, exclusiones, técnicas permitidas, límite de solicitudes y cuenta de prueba propia. Si esto no se puede establecer, detenerse en análisis offline. Una publicación histórica no concede permiso.
2. Importar Swagger 2.0/OpenAPI JSON con `import-surface --format openapi`. La salida omite cuerpos, ejemplos y secretos; conserva rutas, método, autenticación declarada y procedencia. Registrar pistas históricas estructuradas de una fuente pública en `historical.json` sin asumir que aún estén vigentes.
3. Armar `policy.json` y `profile.json` con los hechos comprobados. El agente crea estos archivos; el usuario no tiene que escribir JSON. `profile.json` refiere a variables de entorno, una solicitud inocua sobre datos propios y un único hecho JSON protegido. No incluir secretos en los archivos.
4. Ejecutar `study-bundle` y `study-plan`. El plan selecciona una operación con autenticación declarada opcional junto a una operación protegida del mismo origen, siempre dentro de los prefijos permitidos. Una pista histórica puede desempatar. Si no hay candidato único, el resultado es `unresolved` y se envían cero solicitudes. Revisar `analysis.json`, `scope.json` y `jwt-config.json` antes de la fase activa.
5. Con el token firmado de la cuenta propia y el cuerpo cargados en el entorno, ejecutar `study-run`. El motor hace cuatro solicitudes con presupuesto compartido: anónima, JWT original, JWT con un claim cambiado y firma anterior, JWT original otra vez. Solo confirma aceptación de esa mutación si el control anónimo se deniega y el mismo hecho protegido se observa con los dos tokens. `resume-study` verifica el bundle y los artefactos originales; no repite intentos inciertos.

Ejemplo de comandos desde el paquete compilado:

```powershell
node dist/cli.js import-surface --format openapi --input api.json --out runs/surface.json
node dist/cli.js study-bundle --case cases/faav-titan-jwt-2026.json --policy policy.json --surface runs/surface.json --historical historical.json --profile profile.json --out runs/study-input.json
node dist/cli.js study-plan --input runs/study-input.json --out runs/study-plan
node dist/cli.js study-run --input runs/study-input.json --out runs/study-active
node dist/cli.js resume-study runs/study-active --input runs/study-input.json
```

`study-bundle` y `study-plan` son offline. `study-run` y `resume-study` pueden enviar requests. En MCP se llaman `study_bundle`, `study_plan`, `study_run` y `resume_study`; las dos últimas solo aparecen con `--allow-network`. Los archivos de salida deben ser nuevos. Conservar la ruta canónica de `study-input.json`: el presupuesto persistente queda a su lado, en `.bba-budgets/<budgetId>`.

## Contratos mínimos

- `policy.json`: `schemaVersion: 1`, `mode`, `sourceUrl`, `reviewedAt`, `authorization` (`reference`, `validFrom`, `validUntil`), `assets` y `excluded` como `{origin,pathPrefixes}`, `techniques: ["jwt-signature-integrity"]`, `budgetId` y `limits` del scope. Los prefijos son segmentos de ruta; una exclusión gana. El motor valida el formato y el tiempo, pero la legitimidad de la política declarada la verifica el investigador.
- `historical.json`: `schemaVersion: 1`, `sourceUrl`, `capturedAt`, `routes: [{path,clue}]`; `clue` vale `routing-definition` o `endpoint-reference`. La fuente histórica solo sugiere dónde mirar.
- `profile.json`: `schemaVersion: 1`, `credentialEnv` (`BBA_TOKEN_*`), `proofPointer`, `request` y `mutation` del [contrato JWT](JWT-INTEGRITY.md). Para POST, el cuerpo va en `BBA_BODY_*`; elegí un query inocuo y una cuenta propia. El hecho señalado por `proofPointer` debe ser estable y privado.
- `runs/study-input.json`: bundle validado y portable que contiene los cinco insumos. `runs/study-plan/analysis.json`: candidatos y grafo con fuentes, operaciones e hipótesis; `scope.json` y `jwt-config.json` se crean solo con un candidato único. `runs/study-active/report.md`: borrador de cinco preguntas generado al completar la prueba.

## Qué puede afirmar el reporte

El borrador responde **qué es**, **cómo se encontró**, **demostración de explotación**, **cómo reproducirlo** y **cómo corregirlo**. Incluye IDs de evidencia y límites. `confirmed` prueba aceptación del JWT alterado para la cuenta y el hecho declarados. No prueba privilegios de otra identidad, lectura masiva, severidad determinada ni que el servicio del artículo siga vulnerable. `not-reproduced` solo descarta la mutación probada. El reporte queda local y requiere revisión antes de enviarlo al programa.

Este MVP contiene una clase de hipótesis y un candidato por ejecución. No automatiza recon general, inferencia de identidades o claims, ni los casos Kia, carrera o cache previstos para bloques posteriores.
