# BBA — Bug Bounty Anything

**Español** · [English](README.en.md)

Skill y motor local de descubrimiento, comprobación y documentación de vulnerabilidades con evidencia verificable. Al invocarlo sobre un servicio autorizado, el agente resuelve alcance y política, prepara el expediente, proyecta superficie y ejecuta comparaciones acotadas hasta generar el borrador. La versión `2.0.0` unifica el registro declarativo CLI/MCP, baja el piso de runtime a Node.js `>=22.13.0`, agrega soporte bilingüe (`--lang es|en`, español por defecto) y suma comprobadores de autorización GraphQL, conformidad OAuth 2.0 `redirect_uri`, redirección abierta, mutaciones/mass-assignment sobre recursos descartables, variantes JWT `alg=none`/`expired-token`, carreras multiplexadas sobre HTTP/2, bootstrap efímero de credenciales en memoria, importación offline de políticas y bundles JS/SourceMap, compilación de candidatos a planes, plantillas de envío con línea base CVSS v3.1/v4.0, firma criptográfica Ed25519 e inspector HTML local en `127.0.0.1`. El [roadmap](docs/ROADMAP.md) detalla el estado real y los límites de cada bloque.

`investigate` compila hipótesis desde superficie importada y reglas declaradas; confirma BOLA, BFLA, exposición de propiedades, aislamiento de tenants y mutación/mass-assignment sobre recursos descartables verificando identidades del servidor y estado antes/después. `graphql-check` verifica autorización por operación GraphQL. `oauth-check` y `redirect-check` clasifican cabeceras `Location` 3xx sin seguir redirecciones ni persistir códigos o query strings. `browser-check` verifica XSS por ejecución de marcador y CORS por lectura real en Chromium con aislamiento WebRTC reforzado. `hunt` conserva su descubrimiento HTML y prueba BOLA especializada. `evaluate-run` sigue siendo el comparador de hashes (`needs-validation`). Los importadores de scanners (`import-candidates`) y políticas (`import-policy`) operan offline sin validar ni expandir comodines automáticamente.

`jwt-check` comprueba si un JWT de una cuenta propia sigue aceptándose tras alterar un claim con su firma original (`add-canary`, `replace`), eliminar la firma (`alg-none`) o presentar un token vencido (`expired-token`), preservando tipos JSON nativos; ver [contrato y límites](docs/JWT-INTEGRITY.md). No infiere identidades privilegiadas ni estima alcance sobre terceros.

`study-bundle` → `study-plan` → `study-run` conecta un caso publicado, la política vigente, una superficie API importada y pistas históricas con el comprobador JWT, propagando también `requestHeaders` de la política al scope compilado. [Guía, contratos y límites](docs/PUBLISHED-CASE-STUDIES.md).

Los comprobadores de entrada y estado se documentan en [entradas y callback](docs/INPUT-PROOFS.md), [cache](docs/CACHE-CHECK.md), [carrera](docs/RACE-CHECK.md) (con transporte `http1` o multiplexación de conexión única `http2`) y [CSRF](docs/CSRF-CHECK.md). Cada recorrido exige rutas y métodos autorizados en el scope, recursos propios y controles negativos.

```powershell
node dist/cli.js capabilities
node dist/cli.js investigate --scope scope.json --surface surface.json --profile profile.json --out runs/investigation
node dist/cli.js check graphql --scope scope.json --config graphql.json --out runs/graphql-proof
node dist/cli.js export-submission runs/graphql-proof --platform hackerone --out runs/h1-draft.md
```

Contratos y condiciones de confirmación: [investigación y evidencia](docs/INVESTIGATION.md), [pruebas de navegador](docs/BROWSER-CHECKS.md), [escenarios con login y rotación](docs/SCENARIOS.md) y [modelo persistente](docs/database.md). El agente prepara los perfiles; no se infieren privacidad, propiedad o roles por nombres de campos.

```powershell
npm run bba -- hunt --scope scope.json --config hunt.json --out runs/hunt
```

El comando requiere scope vigente, dos cuentas controladas y la semántica de identidad/propiedad del servicio; descubre los recursos sin una lista manual de pruebas. No envía reportes. La configuración, alcance real y límites se explican en [HUNT.md](docs/HUNT.md).

## Invocar la skill

Con las dependencias del proyecto ya disponibles:

```powershell
npm run build
node dist/cli.js install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
```

La salida debe ser nueva. Copia instrucciones, referencias y metadata de UI; `runtime.json` apunta al Node y CLI compilada de este paquete. Conservá el proyecto en esa ubicación. No instala dependencias ni modifica MCP u otras skills. Abrí un chat nuevo si el catálogo todavía no la muestra.

Para una instalación de este mismo paquete, `node dist/cli.js update-skill --out <carpeta-existente>` actualiza los recursos administrados y conserva un backup en `.bba-backups/`. Valida el vínculo al paquete, rechaza enlaces en recursos y conserva archivos ajenos. `installation.json` registra hashes de los archivos administrados; una actualización interrumpida no se presenta como completa.

Para **Claude Code, Codex o Gemini CLI**, `npm run package:skill -- --out dist-skill.zip` (multiplataforma en TypeScript sin dependencias externas) genera un ZIP portable con `SKILL.md`, el CLI compilado y referencias. También sigue disponible `powershell -File scripts/package-claude-code.ps1` en Windows. Descomprimí `bug-bounty-anything` en `.claude/skills/` o `~/.claude/skills/`; el registro MCP inicial expone únicamente herramientas offline. Chromium se instala aparte si necesitás pruebas de navegador.

Invocación: **`$bug-bounty-anything investigá https://servicio-autorizado/ y prepará los hallazgos`**. El agente busca la política vigente, genera los archivos necesarios y ejecuta los bloques cubiertos por el permiso. Solo pide datos que no puede resolver, como cuentas de prueba o una regla de acceso. La falta de autorización frena las pruebas activas sobre ese activo; la investigación pública puede continuar. La skill usa CLI sin exigir MCP y deriva artefactos cliente a REA cuando corresponde.

Si todavía falta política o ventana, `node dist/cli.js start-case --target https://servicio-autorizado/ --out runs/case` crea únicamente el registro pendiente, sin scope/plan ni requests. No inventa fechas para superar una validación. Cuando el permiso está establecido, se usa `prepare`:

```powershell
node dist/cli.js prepare --scope scope.json --target https://servicio-autorizado/ --out runs/investigation
```

Genera `scope.json`, un `plan.json` GET anónimo a la semilla, `case.json` con checksum y `investigation.md` para política, superficie, hipótesis, evidencia y continuidad. No contacta el destino ni acredita el permiso real. Rechaza URLs excluidas/fuera de scope, ventanas vencidas y salidas existentes. `prepare` también está disponible en MCP sin habilitar red. Con `scope.budgetId`, las fases comparten contador, intervalo y duración persistentes junto al archivo de scope canónico. Los scopes históricos sin ese campo conservan límites por ejecución.

## Requisitos y ejecución

- Node.js **22.13.0 o posterior** (incluidos Node 22 LTS, 24 y 26), con npm.
- Para desarrollar o correr tests sobre Node 22.13, habilitá el stripping nativo de TypeScript con `$env:NODE_OPTIONS = '--experimental-strip-types'` en PowerShell. El paquete publicado ejecuta JavaScript compilado y no necesita esa opción.
- TypeScript (strip-types nativo en desarrollo y JS compilado en `dist/`) y SQLite (`node:sqlite`) provistos por Node. Única dependencia de producción: `playwright-core` 1.64.1 (Apache-2.0), para captura, inspección de páginas y pruebas de navegador. Para usarlo: `npm install` y `npx playwright-core install --only-shell chromium` (descarga el navegador a `%LOCALAPPDATA%\ms-playwright` o `~/.cache/ms-playwright`, fuera del repo). Los demás comandos no necesitan Chromium.
- El sistema debe permitir conexiones a `127.0.0.1` para laboratorios locales y el inspector UI. Algunos sandboxes bloquean loopback; en ese caso ejecutá los comandos desde una terminal local habilitada sin desactivar controles del sistema.

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

## Instalación, diagnóstico y MCP

Para usar el CLI una vez desde npm, sin instalarlo de forma global:

```powershell
npx --yes bug-bounty-anything@latest capabilities
npx --yes bug-bounty-anything@latest --help
```

`npx` descarga el paquete publicado y ejecuta su comando `bba`. Para registrar una skill o MCP de forma persistente, instalá el paquete globalmente: los registros guardan la ruta del CLI y una entrada temporal de la caché de `npx` podría desaparecer.

```powershell
npm install --global bug-bounty-anything@latest
bba install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
bba doctor
```

Para pruebas de navegador, instalá Chromium aparte con `npx playwright-core install --only-shell chromium`. Desde el repositorio fuente, `npm install`, `npm run build` y `npm test` siguen siendo los comandos de desarrollo. El paquete público y su código están bajo [licencia MIT](LICENSE).

El paquete instalado es JavaScript compilado en `dist/` y expone el comando `bba` (incluidos subcomandos jerárquicos `bba campaign ...`, `bba check ...`, `bba study ...`, ayuda puntual `<comando> --help` e idioma `--lang es|en`).

`bba doctor` hace solo comprobaciones locales y no contacta ningún host: versión de Node (`>=22.13`), SQLite, loopback, carpeta temporal, lanzamiento de Chromium con aislamiento WebRTC reforzado y los **nombres** (nunca los valores) de las variables `BBA_TOKEN_*` / `BBA_COOKIE_*` / `BBA_HEADER_*` / `BBA_INPUT_*` / `BBA_BODY_*` presentes.

```powershell
bba mcp --root C:/ruta/al/workspace            # solo herramientas offline
bba mcp --root C:/ruta/al/workspace --allow-network
```

Servidor MCP por stdio (JSON-RPC sin dependencias externas: `initialize`, `ping` fuera de banda, cancelación real `notifications/cancelled` con `AbortSignal` y `tools`). `tools/list` es el inventario autoritativo; las herramientas activas solo existen con `--allow-network`. Todos los paths se confinan dentro de `--root` en Windows y POSIX; salidas fuera de raíz y escapes por enlaces simbólicos o junctions se rechazan, y los errores internos se sanitizan mediante `SafeError`.

Para conectar el MCP a Codex, Claude Code o Gemini CLI: `node dist/cli.js setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` muestra o aplica el registro preservando backups locales.

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

Para investigar por fases, `campaign-open` crea un expediente sin red, `campaign-link` asocia el scope y una revisión documentada de la política, y `campaign-status` verifica integridad, presupuesto y bloqueos. Con la red habilitada, `campaign-capture` inspecciona una vez la URL exacta, `campaign-execute` ejecuta el perfil semántico actual con cuentas controladas y deja un borrador, y `campaign-resume` continúa una ejecución pausada sin repetir pasos registrados. Los comandos MCP equivalentes usan guiones bajos. Ver [flujo de campaña](docs/CAMPAIGNS.md) para contratos, límites y recuperación tras interrupción.

## Identificación requerida por el programa

`scope.requestHeaders` permite marcadores por origen en `run`, `resume`, `capture` y `hunt`. Ejemplo de estructura para un origen ya permitido:

```json
"requestHeaders": [
  { "origin": "https://servicio-autorizado", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://servicio-autorizado", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

El operador carga esos valores por su entorno. Se admiten `user-agent` o nombres `x-*` en minúsculas; no `Authorization`, `Cookie`, `Host` ni headers de transporte. Los valores deben tener de 1 a 512 caracteres ASCII imprimibles, sin saltos de línea. Las referencias y nombres quedan en el scope; los valores nunca se guardan en evidencia ni se pasan como argumentos. Si falta alguno, la operación falla antes de enviar o reservar requests. Cada marcador se envía solo a su origen declarado, aunque haya otros orígenes permitidos. Los scopes existentes sin este campo siguen funcionando.

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

`npm run check` ejecuta TypeScript estricto sobre `src/` y `scripts/`, sin emitir JS. `npm run verify` combina `check`, `build` y `test` completo, y cuenta con workflow de CI multiplataforma (`.github/workflows/ci.yml` en Ubuntu y Windows sobre Node 22.13 y 24).

Códigos de salida: `0` completo (en `lab`, incluso si encontró vulnerabilidades); `1` error o ejecución detenida; `2` argumentos inválidos; `3` ejecución parcial terminada con resultados inconclusos; `130` cancelación. Un `0` no significa ausencia de vulnerabilidades: consultá los estados del resultado.

## Próximo bloque

Pendientes del motor: inferencia de login/SSO y tokens dinámicos, confirmación de otras clases y ejecución confinada de scanners. Los escenarios ya ejecutan formularios/acciones declaradas y rotación real de cookies en memoria; no se reanudan tras una caída. Las generaciones semánticas y pruebas XSS/CORS tienen cobertura GET acotada. La skill dirige investigación asistida más amplia con herramientas controlables, sin prometer detección automática universal.
