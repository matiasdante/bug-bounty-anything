# Guía de CLI

[English](../cli.md) · **Español** · [Português (Brasil)](../pt-BR/cli.md) · [简体中文](../zh/cli.md)

Referencia de comandos del motor local: ejecución con alcance, importaciones, captura, evaluación, firmas, encabezados del programa, archivos del laboratorio, límites y verificación. Primero instalá con la [guía de instalación](installation.md).

## Núcleo con alcance y recuperación

La [guía de ejecución](EXECUTION.md) define los contratos, límites, checkpoints y condiciones de recuperación. Comandos, una vez preparados un alcance y un plan para recursos autorizados:

```powershell
npm run bba -- scope-check --scope scope.json --plan plan.json
npm run bba -- run --scope scope.json --plan plan.json --out runs/investigation
npm run bba -- resume runs/investigation --scope scope.json
npm run bba -- inspect-run runs/investigation
npm run bba -- export-run runs/investigation --out runs/investigation-export.json
npm run bba -- report-run runs/investigation --out runs/investigation-report.md
```

`scope-check` valida formato, vigencia y coincidencia de destinos, **no comprueba el permiso real del propietario**. Ese permiso y las reglas vigentes se relevan antes de crear el scope. `run` y `resume` sí hacen solicitudes; los otros comandos de este grupo son offline.

Ctrl+C cancela la ejecución y guarda lo conocido. `resume` conserva presupuesto y evidencias, requiere el mismo scope vigente y sigue solo pasos no iniciados. Una solicitud iniciada cuyo resultado se perdió queda inconclusa y nunca se reintenta automáticamente. Las detenciones por límites o errores requieren revisar la causa y una nueva investigación; no se reinician con `resume`.

## Importar superficie y políticas

```powershell
npm run bba -- import-surface --format har|openapi|rea|graphql|js-bundle --input source.json --out runs/surface.json [--quarantine]
npm run bba -- import-policy --format hackerone|bugcrowd|intigriti|security-txt --input policy.json --out runs/policy-draft
```

Proyecta un inventario de endpoints desde HAR 1.2, Swagger 2.0 / OpenAPI 3.0/3.1 JSON, Evidence de REA, introspección/SDL de GraphQL o bundles JS / SourceMap v3. Es **offline**: no contacta URLs ni convierte el inventario en autorización. Con `--quarantine`, omite y contabiliza entradas irrepresenables en lugar de abortar todo el lote.

- Cada entrada distingue `observed` (HAR/REA) de `declared` (Swagger/OpenAPI/GraphQL/JS) y conserva su ubicación en el origen (`locator`, y `ordinal`/`evidence_id` para REA).
- Se descartan headers, cuerpos, valores de query, ejemplos y descripciones. Segmentos numéricos, UUID o largos pasan a `{opaque}`; rutas con caracteres RFC 3986 (`:` y `@` en path) y nombres de query con corchetes (`filter[id]`) se admiten sin relajar el bloqueo de escapes ambiguos (`%2E`, `%2F`, `%5C`).
- `import-policy` extrae activos HTTPS exactos hacia `scope.draft.json` (con soporte de `pathPrefixes` y plantillas `{param}` en `scope.json`) y aísla dominios comodín (`*.example.com`) en `manualReviewWildcards` sin expandirlos nunca de forma implícita.

## Capturar superficie con navegador

```powershell
npm run bba -- capture --scope scope.json --plan plan.json --out runs/capture
```

Navega cada paso del plan con Chromium headless y produce `surface.json` (mismo formato que `import-surface`), `capture.json` (conteos y detenciones) y `pages.json` (rutas, acciones y nombres de campos observados en el DOM, sin valores ni query strings). Admite scopes `loopback-lab` y `public-https`. Se verificó con servidores locales y, en 1.2.0, con una navegación pública acotada de `www.dcs.ar`; ese piloto no probó login, permisos ni payloads.

- Cada request del navegador pasa por BBA. Solo se envían GET a origen y path exactos en scope, mediante el mismo transporte de `run` (DNS fijado, IP pública validada, sin redirects, con timeout, tamaño máximo, intervalo y presupuesto). El resto se aborta sin salir (`blocked`). Tras una detención, nada más se envía (`not-sent`).
- **Aislamiento del navegador:** lo que Chromium abriría por su cuenta queda fuera de la ruta de BBA, así que se fuerza a un proxy sumidero en loopback que rechaza y cuenta (`leak-attempts`), se deshabilita la resolución de nombres y WebRTC no puede usar UDP fuera del proxy. Cada capa se verificó con un test que falla si se la quita: un fetch sin enrutar llega al sumidero y no al otro origen; sin la política, WebRTC emitió 4 paquetes STUN. `preconnect` y `dns-prefetch` no abrieron conexiones en el Chromium fijado, así que no son un vector probado.
- Credenciales: `credentialEnv` acepta `BBA_TOKEN_*` (se envía como `Authorization: Bearer`) o `BBA_COOKIE_*` (se envía como `Cookie`, formato `nombre=valor; nombre2=valor2`, sin saltos de línea ni valores vacíos de nombre). Nunca se envían ambas ni se persiste el valor. El operador inicia sesión por su cuenta y exporta la cookie; BBA no automatiza logins ni aplica `Set-Cookie`, así que una sesión que rota puede quedar sin autenticar. Cada paso usa un contexto efímero propio y los service workers están bloqueados.
- En `surface.json`, `status: null` significa que BBA no envió la request; `capture.json.outcomes` está alineado con sus entradas. Las URLs no proyectables (por ejemplo con escapes) solo se cuentan.
- No hay checkpoints: si el proceso muere, la captura se pierde y las requests ya enviadas no quedan registradas. Fuera de alcance: login por formulario, POST, crawling.

Códigos de salida: `0` sin detención, `1` detenida (presupuesto, 3xx/429/5xx, error), `130` cancelada.

## Evaluar hipótesis de autorización

```powershell
npm run bba -- evaluate-run runs/investigation --checks checks.json --out runs/evaluation.md
```

Lee una sesión de `run` ya verificada y evalúa, offline, hipótesis declaradas en `checks.json` (`{ schemaVersion: 1, checks: [{ id, class, control, baseline, probe }] }`). Clases: `bola` (lectura de un objeto ajeno), `bfla` (función reservada a otro rol) y `property-exposure` (respuesta privilegiada entregada a un rol menor). `--out` termina en `.md` para el reporte o en `.json` para el resultado con checksum.

Cada check apunta a tres pasos del plan y su estructura se valida en código: el **control** es anónimo, el **baseline** y la **sonda** usan credenciales distintas, y los tres leen la misma URL.

| Resultado | Condición |
|---|---|
| `needs-validation` | Control 401/403, baseline 200 y sonda 200 con el mismo SHA-256: candidato pendiente de verificar propiedad, permisos e impacto |
| `not-reproduced` | Sonda 401/403/404 con baseline válido; un 200 diferente en `property-exposure` queda `unresolved` porque puede haber fuga parcial |
| `unresolved` | Control abierto, baseline fallido, paso sin respuesta, 5xx, o un 200 distinto en BOLA/BFLA |

**Límites:** compara hashes de respuestas HTTP. No guarda contenido ni mide impacto o severidad, y los roles/dueños de las credenciales los declara el operador: BBA no los verifica. `not-reproduced` no significa seguro. Los laboratorios propios (`src/lab.ts`, `src/role-lab.ts`) tienen variante vulnerable y corregida para las tres clases; los tests ejercen ambas con HTTP real.

## Importar candidatos de scanners

```powershell
npm run bba -- import-candidates --format zap|nuclei|subfinder --input zap-report.json --scope scope.json --out runs/candidates.json
```

BBA **no ejecuta** ZAP, Nuclei ni Subfinder: sus efectos activos no pasan por el transporte con scope y presupuesto de BBA, y el roadmap limita a importación los adaptadores que no se pueden controlar. El operador corre la herramienta por su cuenta, dentro del programa, y BBA normaliza su salida offline: ZAP en JSON (`site[].alerts[].instances[]`), Nuclei en JSONL (`-jsonl`) y Subfinder en JSONL (`-oJ`). Entrada máxima de 2 MiB y 5000 registros.

- Cada candidato queda **siempre `unvalidated`**: un import no puede producir un hallazgo confirmado. Para confirmar, la clase tiene que estar soportada y pasar por `run` + `evaluate-run` con control, baseline y sonda.
- `scopeStatus` compara origen y path exactos con el `scope.json` (las exclusiones ganan): `in-scope`, `excluded`, `out-of-scope` o `unparseable`. Para Subfinder se compara solo el hostname y nunca se resuelve ni se contacta. Un host con paths permitidos cuenta como `in-scope`; sus exclusiones por path se aplican a los endpoints.
- Se descartan descripciones, evidencia, ataques, requests, responses y valores de query. Títulos y paths se limpian de caracteres de control, pero pueden seguir siendo sensibles. La severidad es la etiqueta del scanner, no una evaluación de BBA.
- Duplicados (misma regla, método y path) se colapsan y se cuentan. **Los formatos siguen la documentación de cada herramienta; no se contrastaron con una ejecución real** y los tests usan muestras armadas a mano.
- Advisories y deltas de versión (`references/known-vulns-and-deltas.md`) siguen siendo una tarea manual del operador: BBA no consulta feeds.

## Evaluación congelada

```powershell
npm run bba -- eval --out runs/evaluation.md
```

Corre 18 casos obligatorios contra los laboratorios propios, todos en loopback, y sale con código 1 si alguno no da lo esperado:

- **Comparación de respuestas** (6), revisión 2: BOLA, BFLA y exposición de propiedades producen candidatos `needs-validation` al coincidir hashes. Las denegaciones se clasifican como `not-reproduced`; una respuesta filtrada de propiedades queda `unresolved`. Las métricas reflejan cero confirmaciones en esta suite; el recorrido autónomo tiene pruebas separadas.
- **Inconclusos** (3): la misma hipótesis con el presupuesto agotado antes de la sonda debe quedar `unresolved`.
- **Alcance** (6): otro origen, ruta excluida, autorización vencida, dirección privada en modo público, redirect sin seguir y presupuesto, siempre contando lo que el servidor realmente recibió.
- **Secretos** (2): ni un Bearer ni una cookie aparecen en bytes de la sesión, la exportación JSON o el reporte.
- **Recuperación** (1): tras cancelar a mitad y retomar, ninguna solicitud se repite.

El conjunto está congelado por un digest de ids, grupos y resultados esperados (`FROZEN_DIGEST` en `src/evaluation.ts`): cambiar un caso sin actualizarlo hace fallar la corrida. Se comprobó con mutaciones que la evaluación falla si se rompe el stop por redirect, el presupuesto o se planta un secreto. En la revisión 2, las coincidencias de hashes son candidatos: las métricas reflejan cero confirmaciones y tres omisiones respecto de la verdad de terreno. La prueba autónoma de BOLA se ejecuta aparte; no se mezclan ambos resultados.

**Estas métricas no se extrapolan:** salen de tres clases en laboratorios propios con datos sintéticos. No estiman tasas de detección ni falsos positivos en sistemas reales, y que pasen no demuestra que un objetivo sea seguro. El aislamiento del navegador se cubre en los tests de captura, que requieren Chromium.


## Firma criptográfica, exportación a plataformas e inspector local

```powershell
bba keygen --out keys/operator
bba sign-evidence runs/investigation --key keys/operator/bba-ed25519.key.pem
bba verify-signature runs/investigation --pub keys/operator/bba-ed25519.pub.pem
bba export-submission runs/investigation --platform hackerone|bugcrowd|ghsa --out runs/submission.md
bba ui runs/investigation --out runs/inspector.html
```

- `sign-evidence` y `verify-signature` firman y verifican archivos o directorios completos con claves asimétricas Ed25519 (`node:crypto`), detectando cualquier modificación, agregado o borrado posterior más allá de un simple hash SHA-256.
- `export-submission` genera borradores Markdown para HackerOne, Bugcrowd o GitHub Security Advisories con comandos `curl` redactados (`$BBA_TOKEN_*`, `$BBA_COOKIE_*`) y cálculo conservador CVSS v3.1 / v4.0 solo cuando el hallazgo está `confirmed`.
- `ui` levanta un panel local de solo lectura enlazado exclusivamente a `127.0.0.1` con CSP estricta (`default-src 'none'`) o exporta un HTML autónomo sin JavaScript ni recursos externos.

Para investigar por fases, `campaign-open` crea un expediente sin red, `campaign-link` asocia el scope y una revisión documentada de la política, y `campaign-status` verifica integridad, presupuesto y bloqueos. Con la red habilitada, `campaign-capture` inspecciona una vez la URL exacta, `campaign-execute` ejecuta el perfil semántico actual con cuentas controladas y deja un borrador, y `campaign-resume` continúa una ejecución pausada sin repetir pasos registrados. Los comandos MCP equivalentes usan guiones bajos. Ver [flujo de campaña](CAMPAIGNS.md) para contratos, límites y recuperación tras interrupción.

## Identificación requerida por el programa

`scope.requestHeaders` permite marcadores por origen en `run`, `resume`, `capture` y `hunt`. Ejemplo de estructura para un origen ya permitido:

```json
"requestHeaders": [
  { "origin": "https://servicio-autorizado", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://servicio-autorizado", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

El operador carga esos valores por su entorno. Se admiten `user-agent` o nombres `x-*` en minúsculas; no `Authorization`, `Cookie`, `Host` ni headers de transporte. Los valores deben tener de 1 a 512 caracteres ASCII imprimibles, sin saltos de línea. Las referencias y nombres quedan en el scope; los valores nunca se guardan en evidencia ni se pasan como argumentos. Si falta alguno, la operación falla antes de enviar o reservar requests. Cada marcador se envía solo a su origen declarado, aunque haya otros orígenes permitidos. Los scopes existentes sin este campo siguen funcionando.


## Archivos y contratos

Cada ejecución completa del comando `lab` genera el formato anterior, compatible con 0.1.0:

- `investigation.json`: bundle con contrato versionado, alcance, cinco registros de evidencia, dos hipótesis y checksum SHA-256.
- `report.md`: resultado, pasos de reproducción, referencias de evidencia, impacto y limitaciones.

Los contratos y su validación de entrada están en [src/contracts.ts](../../src/contracts.ts). Cada registro incluye timestamp UTC, actor, ruta, estado HTTP y únicamente los campos sintéticos permitidos. No es una captura HTTP completa. No se guardan headers de autenticación, cookies, cuerpos de error ni respuestas con campos inesperados.

Al leer, BBA valida estructura, versión, identidad de cada evidencia, referencias, checksum y coherencia entre conclusiones y respuestas. Los hashes detectan cambios accidentales; **no son firmas y no acreditan la autenticidad de un archivo enviado por terceros**. El JSON sigue siendo dato, nunca código ejecutable.

En `lab`, una escritura interrumpida conserva `.incomplete` y no se acepta como investigación terminada. Los comandos `run/resume` utilizan otro contrato, con checkpoints y recuperación descritos en la guía. Los artefactos en `runs/` están excluidos de Git.

## Límites del ejecutor

Solo GET a dos rutas exactas del laboratorio, sin query strings, redirecciones ni dominios arbitrarios. Presupuesto de cinco solicitudes; timeout de dos segundos por solicitud y máximo de 4096 bytes por respuesta. Detiene el recorrido ante redirects, 429, errores 5xx, timeout, exceso de tamaño o contenido fuera del contrato.

Estos son los límites fijos de `lab`. En `run/resume` se definen en el scope y se conserva el estado parcial ante fallos. Ambos usan el mismo transporte HTTP; el núcleo general conserva metadatos y hashes de respuestas, sin interpretar esos estados como vulnerabilidades.

## Verificación

`npm test` usa `node:test` y servidores HTTP locales reales. Cubre ambas variantes, controles inconclusos, aislamiento, límites, secretos, scope, checkpoints, integridad y CLI. Incluye cancelar una solicitud y matar un proceso hijo durante otra para verificar recuperación sin repetirla. Los tests crean carpetas temporales propias y las eliminan al finalizar. La selección de DNS público se prueba con respuestas de un resolver controlado; no se contactaron servicios productivos.

`npm run check` ejecuta TypeScript estricto sobre `src/` y `scripts/`, sin emitir JS. `npm run verify` combina `check`, `build` y `test` completo, y cuenta con workflow de CI multiplataforma (`.github/workflows/ci.yml` en Ubuntu y Windows sobre Node 22.13 y 24).

Códigos de salida: `0` completo (en `lab`, incluso si encontró vulnerabilidades); `1` error o ejecución detenida; `2` argumentos inválidos; `3` ejecución parcial terminada con resultados inconclusos; `130` cancelación. Un `0` no significa ausencia de vulnerabilidades: consultá los estados del resultado.


