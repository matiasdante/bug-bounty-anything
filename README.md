# BBA — Bug Bounty Anything

Framework local de investigación de vulnerabilidades con evidencia reproducible. **Versión implementada: 0.9.0**: bloques 1 a 6 y la evaluación congelada del bloque 7 (el bloque 5 solo por importación de candidatos de ZAP, Nuclei y Subfinder) del [roadmap hacia 1.0.0](docs/ROADMAP.md). La metodología general está en [SKILL.md](SKILL.md).

Incluye un laboratorio HTTP para detectar lectura indebida entre cuentas y un núcleo de ejecución GET con alcance explícito, presupuesto persistente, cancelación y recuperación. El núcleo admite laboratorios locales y destinos HTTPS públicos autorizados; todavía no incorpora capturas externas, scanners ni confirmación automática de vulnerabilidades fuera del laboratorio.

## Requisitos y ejecución

- Node.js **26 o posterior**, con npm. Se probó con Node 26.12.0 en Windows.
- TypeScript y SQLite provistos por Node. Única dependencia: `playwright-core` 1.64.1 (Apache-2.0), solo para `capture`. Para usarlo: `npm install` y `npx playwright-core install --only-shell chromium` (descarga el navegador a `%LOCALAPPDATA%\ms-playwright`, fuera del repo). Sin navegador, los tests de captura se marcan como salteados con el motivo.
- El sistema debe permitir conexiones a `127.0.0.1`. Algunos sandboxes bloquean incluso loopback; en ese caso ejecutá los comandos desde una terminal local habilitada. No desactives controles del sistema ni cambies los destinos para sortear el bloqueo.

Desde la raíz del proyecto:

```powershell
npm run bba -- lab --variant vulnerable --out runs/vulnerable
npm run bba -- lab --variant fixed --out runs/fixed
npm run bba -- inspect runs/vulnerable
npm run bba -- report runs/vulnerable --out runs/vulnerable-export.md
npm run demo:core -- --out runs/core-demo
npm test
```

En PowerShell, si la política bloquea `npm.ps1`, usá `npm.cmd` con los mismos argumentos. Las carpetas/archivos de salida deben ser nuevos; BBA nunca sobrescribe una investigación. Para repetir, elegí otro nombre.

`lab` abre un puerto efímero únicamente en `127.0.0.1`, crea dos cuentas y dos documentos sintéticos privados, ejecuta cinco solicitudes secuenciales y cierra el servidor, también ante errores. Las credenciales se generan aleatoriamente en memoria y nunca se imprimen ni persisten. No se instala ni queda corriendo un servicio.

`inspect` y `report` leen evidencia local verificada, sin abrir conexiones de red. `report` regenera el informe desde el JSON, sin depender del reporte anterior ni del historial del chat.

`demo:core` crea otro laboratorio propio, ejecuta cinco pasos con el núcleo 0.2.0 y genera checkpoints SQLite, scope/plan sin credenciales, exportación JSON y reporte. También cierra el servidor. No reutilices su puerto o sus credenciales efímeras para una nueva investigación.

## Núcleo con alcance y recuperación

La [guía de ejecución](docs/EXECUTION.md) define los contratos, límites, checkpoints y condiciones de recuperación. Comandos, una vez preparados un alcance y un plan para recursos autorizados:

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

## Importar superficie

```powershell
npm run bba -- import-surface --format har|openapi|rea --input capture.json --out runs/surface.json
```

Proyecta un inventario de endpoints desde un HAR 1.2, un OpenAPI 3.0/3.1 en JSON o la Evidence de `inspect_web_network_capture` de REA. Es **offline**: no contacta URLs ni convierte el inventario en scope o autorización. La salida es un archivo nuevo con checksum.

- Cada entrada distingue `observed` (HAR/REA) de `declared` (OpenAPI) y conserva su ubicación en el origen (`locator`, y `ordinal`/`evidence_id` para REA).
- Se descartan headers, cuerpos, valores de query, ejemplos y descripciones. Segmentos numéricos, UUID o largos pasan a `{opaque}`; nombres y segmentos literales pueden seguir siendo sensibles.
- `credential-present` solo indica que la captura tenía `Authorization`/`Cookie`; no prueba sesión, rol ni tenant válidos.
- Se rechaza todo el archivo ante rutas ambiguas o con escapes, credenciales en la URL, refs externas o cíclicas, variables de server, YAML o Swagger 2, y nombres de parámetro fuera de `[A-Za-z0-9_.-]` (por ejemplo `filter[a]`).

## Capturar superficie con navegador

```powershell
npm run bba -- capture --scope scope.json --plan plan.json --out runs/capture
```

Navega cada paso del plan con Chromium headless y produce `surface.json` (mismo formato que `import-surface`) y `capture.json` (conteos, motivo de detención y resultado de cada entrada). Admite scopes `loopback-lab` y `public-https`. **La captura pública todavía no se probó contra un host real**: se verificó con servidores locales y el resolver controlado, sin contactar servicios productivos.

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
| `confirmed` | Control 401/403, baseline 200 y sonda 200 con el mismo SHA-256 que el baseline |
| `not-reproduced` | Sonda 401/403/404 con baseline válido; en `property-exposure` también un 200 distinto del baseline (no se descarta una exposición parcial) |
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

- **Detección** (6): BOLA, BFLA y exposición de propiedades, cada una en variante vulnerable (debe dar `confirmed`) y corregida (`not-reproduced`).
- **Inconclusos** (3): la misma hipótesis con el presupuesto agotado antes de la sonda debe quedar `unresolved`.
- **Alcance** (6): otro origen, ruta excluida, autorización vencida, dirección privada en modo público, redirect sin seguir y presupuesto, siempre contando lo que el servidor realmente recibió.
- **Secretos** (2): ni un Bearer ni una cookie aparecen en bytes de la sesión, la exportación JSON o el reporte.
- **Recuperación** (1): tras cancelar a mitad y retomar, ninguna solicitud se repite.

El conjunto está congelado por un digest de ids, grupos y resultados esperados (`FROZEN_DIGEST` en `src/evaluation.ts`): cambiar un caso sin actualizarlo hace fallar la corrida. Se comprobó con mutaciones que la evaluación falla si se rompe el stop por redirect, el presupuesto o se planta un secreto. Última corrida: 18/18, 3 detecciones, 0 omisiones, 0 falsos positivos, 33 solicitudes.

**Estas métricas no se extrapolan:** salen de tres clases en laboratorios propios con datos sintéticos. No estiman tasas de detección ni falsos positivos en sistemas reales, y que pasen no demuestra que un objetivo sea seguro. El aislamiento del navegador se cubre en los tests de captura, que requieren Chromium.

## Instalación, diagnóstico y MCP

```powershell
npm install
npm run build
npm pack
npm install -g .ug-bounty-anything-0.8.0.tgz
npx playwright-core install --only-shell chromium
bba doctor
```

El paquete instalado es JavaScript compilado en `dist/` (Node no quita tipos de archivos dentro de `node_modules`) y expone el comando `bba`, equivalente a `npm run bba --`. Se verificó empaquetando e instalando el tarball en una carpeta aparte; el navegador se descarga aparte con el comando anterior.

`bba doctor` hace solo comprobaciones locales y no contacta ningún host: versión de Node, SQLite, loopback, carpeta temporal, lanzamiento de Chromium con el aislamiento y los **nombres** (no los valores) de las variables `BBA_TOKEN_*` / `BBA_COOKIE_*` presentes. Sale con código 1 si falla algo.

```powershell
bba mcp --root C:utaalworkspace            # solo herramientas offline
bba mcp --root C:utaalworkspace --allow-network
```

Servidor MCP por stdio (JSON-RPC, escrito sin dependencias: solo `initialize`, `ping` y `tools`). Expone `scope_check`, `import_surface`, `import_candidates`, `inspect_run`, `report_run`, `export_run` y `evaluate_run`. **`run`, `resume` y `capture`, que envían requests, solo existen con `--allow-network`.** Todos los paths se resuelven dentro de `--root` (los que salen se rechazan; no se siguen enlaces simbólicos, así que `--root` debe ser un workspace propio) y las salidas son siempre archivos nuevos. Las credenciales no viajan como argumentos: se leen del entorno del proceso servidor, igual que en la CLI. Los límites y el scope los define el `scope.json` que el operador preparó; un agente con permiso de escritura sobre el workspace podría editarlo, así que no le des `--allow-network` sin revisar quién escribe ahí.

## Qué demuestra

| Solicitud | Vulnerable | Corregida |
|---|---|---|
| Anónimo lee documento B | 401 | 401 |
| A lee documento A | 200 | 200 |
| B lee documento B | 200 | 200 |
| A lee documento B | 200 y contenido de B | 403 |
| B lee documento A | 200 y contenido de A | 403 |

El evaluador exige controles válidos y compara el documento completo con la respuesta del propietario. No usa el nombre de la variante para decidir. Un 200 con contenido distinto, una sesión inválida o un control fallido quedan `unresolved`. Una denegación válida queda `not-reproduced`, sin declarar seguro el resto del sistema.

La variante vulnerable confirma dos direcciones de **una misma causa raíz**, no dos vulnerabilidades independientes. No se extrapola severidad a producción ni se asigna CVSS a este laboratorio.

## Archivos y contratos

Cada ejecución completa del comando `lab` genera el formato anterior, compatible con 0.1.0:

- `investigation.json`: bundle con contrato versionado, alcance, cinco registros de evidencia, dos hipótesis y checksum SHA-256.
- `report.md`: resultado, pasos de reproducción, referencias de evidencia, impacto y limitaciones.

Los contratos y su validación de entrada están en [src/contracts.ts](src/contracts.ts). Cada registro incluye timestamp UTC, actor, ruta, estado HTTP y únicamente los campos sintéticos permitidos. No es una captura HTTP completa. No se guardan headers de autenticación, cookies, cuerpos de error ni respuestas con campos inesperados.

Al leer, BBA valida estructura, versión, identidad de cada evidencia, referencias, checksum y coherencia entre conclusiones y respuestas. Los hashes detectan cambios accidentales; **no son firmas y no acreditan la autenticidad de un archivo enviado por terceros**. El JSON sigue siendo dato, nunca código ejecutable.

En `lab`, una escritura interrumpida conserva `.incomplete` y no se acepta como investigación terminada. Los comandos `run/resume` utilizan otro contrato, con checkpoints y recuperación descritos en la guía. Los artefactos en `runs/` están excluidos de Git.

## Límites del ejecutor

Solo GET a dos rutas exactas del laboratorio, sin query strings, redirecciones ni dominios arbitrarios. Presupuesto de cinco solicitudes; timeout de dos segundos por solicitud y máximo de 4096 bytes por respuesta. Detiene el recorrido ante redirects, 429, errores 5xx, timeout, exceso de tamaño o contenido fuera del contrato.

Estos son los límites fijos de `lab`. En `run/resume` se definen en el scope y se conserva el estado parcial ante fallos. Ambos usan el mismo transporte HTTP; el núcleo general conserva metadatos y hashes de respuestas, sin interpretar esos estados como vulnerabilidades.

## Verificación

`npm test` usa `node:test` y servidores HTTP locales reales. Cubre ambas variantes, controles inconclusos, aislamiento, límites, secretos, scope, checkpoints, integridad y CLI. Incluye cancelar una solicitud y matar un proceso hijo durante otra para verificar recuperación sin repetirla. Los tests crean carpetas temporales propias y las eliminan al finalizar. La selección de DNS público se prueba con respuestas de un resolver controlado; no se contactaron servicios productivos.

Node elimina los tipos al ejecutar; **no hace comprobación estática de TypeScript**. Este bloque verifica ejecución y contratos en runtime. No se configuraron todavía compilador, linter ni CI.

Códigos de salida: `0` completo (en `lab`, incluso si encontró vulnerabilidades); `1` error o ejecución detenida; `2` argumentos inválidos; `3` ejecución parcial terminada con resultados inconclusos; `130` cancelación. Un `0` no significa ausencia de vulnerabilidades: consultá los estados del resultado.

## Próximo bloque

Piloto en un programa con recompensa: falta elegir programa, scope y cuentas de prueba (ver docs/ROADMAP.md). El servicio productivo y la autorización concreta todavía no están seleccionados.
