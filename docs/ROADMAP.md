# Roadmap interno — BBA

**Español** · [English](ROADMAP.en.md)

Actualizado: 2026-10-31. La versión **2.0.0** consolida correcciones de transporte/protocolo/aislamiento, unifica la arquitectura CLI/MCP sobre esquemas declarativos y suma doce capacidades nuevas manteniendo cero dependencias externas adicionales y preservando los invariantes de alcance, presupuesto y cero persistencia de secretos.

Objetivo: investigación reproducible de web/API, con skill, CLI/MCP, motor local, adaptadores, evidencia persistente, evaluación controlada y piloto sobre un programa con bug bounty. Distinguir detección automatizada, investigación asistida e indicios por capacidad. No prometer cobertura universal ni exigir un hallazgo productivo para declarar honesto el resultado.

| Bloque | Estado | Entregable y criterio de salida |
|---|---|---|
| 1. Contratos y laboratorio | Implementado en 0.1.0 | Contratos runtime, laboratorio reiniciable con dos cuentas, variantes vulnerable/corregida, controles independientes, evidencia y reporte. Ambas variantes deben producir sus resultados esperados con HTTP real. |
| 2. Núcleo y ejecución | Ampliado en 1.2.0: métodos HTTP, query/body por entorno, bindings de inputs y presupuesto durable entre fases | Scope exacto/exclusiones/vigencia, checkpoints SQLite, cancelación y recuperación sin repetir intentos inciertos. Límites en [EXECUTION.md](EXECUTION.md). |
| 3. Captura y superficie | HAR/Swagger 2.0/OpenAPI 3.x/REA offline, captura aislada y planificación con procedencia; piloto público DCS repetido en 1.2.0 | Captura pública limitada a rutas GET elegidas; assets fuera de scope bloqueados. No equivale a ejecutar toda la aplicación. |
| 4. Investigación y confirmación | 1.3.0: BOLA, BFLA, propiedad y tenant con hechos; XSS/CORS con navegador real; integridad JWT con token firmado propio; escenarios de sesión declarados; `hunt` especializado | [Investigación](INVESTIGATION.md), [browser proofs](BROWSER-CHECKS.md), [JWT](JWT-INTEGRITY.md) y [escenarios](SCENARIOS.md). Faltan inferencia de flujos, tokens dinámicos y confirmadores de otras clases. |
| 4a. Caso publicado reproducible | 1.4.0: caso Titan, bundle validado, grafo de procedencia, selección de una hipótesis, prueba JWT y reporte local | [Estudio publicado](PUBLISHED-CASE-STUDIES.md). Faltan otras clases y validación externa con autorización. |
| 4b. Descubrimiento de página | 1.5.0: `inspect_web_page` usa captura aislada y proyecta links, formularios y scripts sin valores ni query strings | La captura conserva `pages.json` con checksum; `page_view` lo lee offline. Las rutas observadas no amplían el scope. |
| 4c. Expediente y ejecución guiada | 1.6.0: ledger de campaña con alcance/política/evidencia enlazados; `campaign_capture` y `campaign_execute` usan la autorización declarada y el presupuesto compartido | Un intento por captura/perfil, bloqueo de acciones interrumpidas, informe de cobertura y borrador. La veracidad de la política y las reglas de negocio sigue a cargo del operador. |
| 4d. Pruebas acotadas de otras clases | 1.9.0: plantilla aritmética, callback propio, exposición entre identidades correlacionada con cache, carrera de uso único y formulario de otro origen | Controles negativos, rutas exactas, presupuesto compartido, evidencia y reporte de cinco secciones. Requieren cuentas/recursos propios y reglas explícitas; no son detectores genéricos de cada familia. |
| 5. Adaptadores | Implementado en 0.7.0 solo por importación (ZAP, Nuclei, Subfinder); BBA no ejecuta scanners ni consulta advisories | ZAP, Nuclei revisado/versionado y Subfinder; advisories y deltas. Normalizar resultados, respetar presupuestos y validar candidatos antes de confirmar. |
| 6. Producto utilizable | CLI/MCP, capacidades, vistas/comparación de evidencia, `doctor`, instalación/actualización con backup y TypeScript estricto | `npm run verify` combina check/build/tests y GitHub Actions lo ejecuta en Ubuntu y Windows. MCP expone red solo con `--allow-network`. |
| 7. RC y piloto productivo | Suite local completa, chequeo TypeScript estricto, doctor, validación de skill y piloto de navegación pública en DCS | Falta validación con cuentas controladas en un servicio real y un programa externo de bounty. Un sitio público sin hallazgos no valida todas las clases. |

## Decisiones de implementación

- TypeScript, núcleo local compartido por CLI y futuro MCP. 0.1.0 usa Node 26 sin dependencias.
- Los bundles JSON del laboratorio se conservan. Las sesiones generales usan SQLite nativo de Node: checkpoints transaccionales y bloqueo de ejecución liberado por el SO ante caída de proceso, con exportación JSON/Markdown.
- Laboratorio propio mínimo ahora; Juice Shop y crAPI para ampliar escenarios. Las variantes corregidas y controles negativos siguen siendo obligatorios.
- REA para artefactos/capturas; Playwright para navegador y sesiones; ZAP como primer adaptador general; Nuclei con templates seleccionados; Subfinder opcional para candidatos pasivos.
- Fijar versiones, licencias, requisitos y efectos al implementar cada adaptador. No instalar herramientas en conjunto sin necesidad concreta.

## Cobertura prevista de 1.0.0

1. Identidad/permisos: BOLA, autorización funcional y por propiedad, tenants, sesiones, recuperación, JWT y OAuth/OIDC.
2. Navegador: XSS, CSRF, CORS y redirecciones, comprobadas en contexto real.
3. Entradas: familias de injection, traversal, uploads, XXE y SSRF, con condiciones de parada por clase.
4. API/negocio: GraphQL, mass assignment, exposición, secuencias y concurrencia controlada.
5. Componentes/exposición: secretos, configuración cloud, candidatos de takeover, advisories y deltas.

Documentar una clase no significa implementarla. Las confirmaciones que requieran una acción fuera de alcance permanecen inconclusas. El análisis de clientes móviles/binarios se delega a REA; el permiso sobre un artefacto no habilita contactar su backend.

## Condiciones de release

- Todos los casos obligatorios del conjunto congelado pasan, incluidos alcance y secretos; las variantes corregidas no generan confirmaciones.
- Medir detecciones, falsos positivos, omisiones, solicitudes, tiempo y repetición al retomar, sin extrapolar métricas del laboratorio a todos los sistemas.
- Reportes reproducibles desde un entorno limpio, instalación y diagnóstico comprobados, cancelación/recuperación/exportación funcionales.
- Ningún adaptador productivo puede escapar a destinos y presupuestos autorizados. Si no es posible controlar sus efectos, limitarlo a laboratorio o importación.
- El piloto conserva alcance, cobertura, limitaciones y evidencia. Encontrar un bug no es requisito para fingir éxito ni motivo para ampliar el scope.

## Piloto 1.0.0 — www.dcs.ar (2026-10-29)

Sitio propio de DCS, autorizado internamente por el operador; no es un programa de bug bounty de terceros. Alcance: solo GET anónimos a `https://www.dcs.ar`, sin login, formularios, POST, scanners, subdominios ni terceros. Evidencia en `runs/pilot-dcs/` (local, fuera de Git).

| Paso | Requests de BBA | Resultado |
|---|---|---|
| `capture` de 6 páginas públicas | 6 enviadas, 366 bloqueadas en el navegador, 0 fugas | Todas 200; Cloudflare no desafió |
| `run` exposición (1ª investigación) | 2 | `/wp-json/wp/v2/users` 401 (no lista usuarios); `/xmlrpc.php` 301 → detenida sin seguir |
| `run` exposición (2ª, pasos restantes) | 3 | `/readme.html` 200 (readme estándar, sin versión de WP); `/wp-login.php` 200 (login público normal); `/wp-content/debug.log` 403 |

Sin hallazgos confirmados. Observaciones informativas: la versión de WordPress figura en `meta generator`, y algunos assets de Elementor Pro se sirven con `?ver=3.7.5` mientras otros indican 3.25/3.26; es un **candidato** a plugin desactualizado que se confirma solo en el panel de administración.

Lo que el piloto mostró de la herramienta: BBA no conserva el destino de un redirect (no se supo a dónde va `/xmlrpc.php`), no envía `User-Agent` ni un header identificatorio configurable, y `run` no guarda contenido, así que una exposición con 200 requiere revisión manual. La captura pública y el aislamiento funcionaron contra un host real detrás de Cloudflare.

## Selección de un programa de terceros — más adelante

Relevar programas con recompensa vigente, scope claro, cuentas de prueba accesibles y reglas compatibles. Elegir un programa y una superficie acotada; registrar presupuesto y condiciones de parada antes de probar. El envío de un reporte requiere autorización explícita del usuario.

## Verificación y piloto 1.2.0 — 2026-10-29

`npm run verify`: TypeScript estricto, 159 pruebas aprobadas sin omisiones y build de 36 módulos JS. `doctor` comprobó Node 26.12.0, SQLite, loopback y Chromium 156.0.8078.4. El validador de skill pasó con PyYAML 6.0.3 instalado solo en una carpeta local de verificación. npm audit informó cero vulnerabilidades conocidas para el inventario instalado durante la actualización de dependencias de desarrollo.

La evaluación independiente offline no trató una captura autenticada histórica como identidad vigente ni copió sus secretos al informe. Se corrigieron las contradicciones detectadas en la ayuda CLI y se agregó `start-case` para registrar un caso sin fabricar ventana de permiso. Su comprobación posterior validó esa entrada y la ayuda corregida.

El usuario eligió `https://www.dcs.ar` para el piloto. Se limitaron las operaciones del motor a navegación pública: GET a `/`, `/servicios/` y `/contacto/`, todos HTTP 200, y una captura de inicio. **4 GET enviados, 67 recursos bloqueados por scope, 0 fugas detectadas por el sumidero y 0 reservas inciertas**, compartiendo contador/intervalo/duración. Los artefactos locales están en `runs/pilot-dcs-20261029-v12/`, fuera de Git. Las consultas públicas con la herramienta web se registraron aparte del contador del motor.

No se probaron formularios, credenciales, permisos ni payloads en producción. No hay vulnerabilidades confirmadas en este piloto y no se deduce que el sitio sea seguro. No se estableció un programa público de bounty; la herramienta web no obtuvo security.txt, lo que tampoco prueba ausencia del archivo. Para comprobar fronteras de aplicación reales hacen falta recursos/cuentas controlados, sus reglas y condiciones específicas.

## Bloque JWT 1.3.0

El [caso Titan](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records) motivó una distinción entre indicios de validación (errores de tenant/audiencia/aplicación), aceptación de un JWT cuya firma ya no corresponde al payload, y alcance sobre otros datos. BBA automatiza **solo** la segunda comprobación sobre una cuenta propia y un hecho protegido inocuo. Un Swagger importado o una configuración archivada aportan candidatos con procedencia; no acreditan permiso ni prueban que una ruta siga activa. La estimación de filas del artículo fue calculada desde metadatos, no es una prueba que BBA deba repetir sobre un tercero.

`jwt-check` usa la misma ejecución y presupuesto durables, liga el token original y su mutación mediante hashes salados para retomar sin cambiar identidad o valor, y no guarda JWTs ni cuerpos. El importador ahora proyecta Swagger 2.0 JSON, incluida la indicación de seguridad por operación, sin ejecutar sus rutas. Quedan sin automatizar la exploración genérica de JWT/OIDC, la inferencia de claims válidos, claves/JWKS, la progresión semántica de mensajes de error y la atribución de roles o datos más allá de la cuenta propia. El piloto DCS público no incluye JWT ni autorización para probarlo allí.

Verificación 1.3.0: `npm run verify` aprobó **165 pruebas sin omisiones**, TypeScript estricto y build de 37 módulos. Se comprobaron variantes JWT vulnerable/corregida, rechazo previo a la red, reanudación ligada a token y mutación, importación Swagger 2.0, inventario MCP y paquete con la guía JWT. El validador de la skill pasó para fuente e instalación. No hubo pruebas JWT sobre servicios externos.

## Bloque de estudios publicados 1.4.0

Se agregó el manifiesto del artículo Titan y un [recorrido local](PUBLISHED-CASE-STUDIES.md): la política declarada, la superficie Swagger/OpenAPI importada, las rutas históricas y el perfil de cuenta propia forman un bundle validado. `study-plan` genera candidatos y un grafo de procedencia; solo el candidato único dentro de scope produce una configuración ejecutable. `study-run` reutiliza el control JWT de cuatro requests y el presupuesto duradero; genera un borrador que responde qué es, cómo se encontró, cómo se demostró, cómo reproducirlo y cómo corregirlo. La variante corregida queda `not-reproduced`; candidatos múltiples o excluidos quedan offline.

Este bloque no descubre por sí solo una falla crítica en cualquier enlace ni acredita el impacto del caso original. Para llevar el método a otros casos hacen falta detectores, pruebas de impacto acotadas y evaluaciones independientes por clase. Los siguientes corpus previstos son Kia (fronteras de rol), carreras y cache; sus comprobadores no forman parte de 1.4.0. Tampoco se hicieron pruebas activas sobre los servicios del artículo.

Verificación 1.4.0: `npm run verify` aprobó **170 pruebas sin omisiones**, TypeScript estricto y build de 38 módulos. Incluye laboratorio vulnerable/corregido, ambigüedad y exclusiones sin tráfico, reanudación ligada al bundle, recorrido completo por CLI e inventario MCP. El paquete incluye el manifiesto, el módulo compilado y la guía; el validador de skill pasó para fuente e instalación personal.

## Comparación con REA y bloque MCP 1.5.0

[REA](https://github.com/morluto/rea) registra su MCP con el agente y organiza muchas familias de herramientas de análisis por artefacto, runtime y evidencia. BBA ya tenía MCP para sus confirmadores, pero la instalación de la skill dejaba el servidor sin conectar y la captura web no entregaba estructura del DOM. `setup-mcp` usa la CLI oficial de Codex para registrar o reemplazar el servidor con vista previa, backup, verificación y herramientas offline por defecto. `inspect_web_page` reduce el paso manual entre una URL autorizada y las primeras rutas/formularios observados; `page_view` recupera esa evidencia sin repetir tráfico.

La brecha restante es funcional, no una cuenta de nombres MCP: BBA todavía requiere una política verificada y reglas de negocio aportadas por el operador, no infiere automáticamente identidad/propiedad ni cubre inyección, SSRF, CSRF, carreras o cache. Un próximo bloque debe tomar una clase y un recorrido completo con controles negativos, presupuesto común y reporte antes de sumar otra familia. La conexión MCP por sí sola no aumenta cobertura de vulnerabilidades.

Verificación 1.5.0: `npm run verify` aprobó **172 pruebas sin omisiones**, TypeScript estricto y build de 39 módulos. El registro MCP se probó con un `CODEX_HOME` aislado, incluyendo vista previa, backup, idempotencia, conflicto y reemplazo explícito de modo; la instalación local quedó registrada en modo offline. La captura DOM se probó contra un servidor sintético con valores secretos en query y campos; esos valores no aparecen en los artefactos y no se enviaron requests fuera del scope.

## Expediente de campaña 1.6.0

La [guía de campaña](CAMPAIGNS.md) une las fases bajo un identificador, una cadena de eventos y el presupuesto durable del scope. `campaign_status` vuelve a leer los artefactos y detecta cambios. `campaign_capture` exige el scope y la revisión de política declarada antes de un GET acotado, enlaza hechos DOM y superficie; `campaign_execute` exige una superficie y perfil actual con checks semánticos, ejecuta los controles y enlaza el borrador. Cada acción reserva su carpeta antes de hacer requests para que una caída no provoque una repetición silenciosa. Los tests de laboratorio comprueban el bloqueo sin política, la ejecución con dos identidades, el presupuesto y la ausencia de requests en un segundo intento.

Esto coordina las capacidades actuales; no convierte a BBA en un detector genérico de vulnerabilidades críticas. La automatización todavía depende de reglas de negocio y cuentas controladas, y no cubre las familias de inyección, SSRF, CSRF, cache o carreras. El operador debe validar la política vigente y revisar la demostración y el impacto antes de reportar. No hubo pruebas activas de 1.6.0 sobre un servicio externo.

Verificación 1.6.0: `npm run verify` aprobó **175 pruebas sin omisiones**, TypeScript estricto y build de 40 módulos. Los fixtures incluyen un flujo completo de campaña con dos cuentas sintéticas, una captura Chromium contra loopback, denegación previa a la red sin revisión de política y bloqueo de un segundo intento. La suite limita la concurrencia a dos archivos para estabilizar pruebas de navegador y ventanas temporales cortas; las dos pruebas que fallaron en una corrida paralela pasaron aisladas y luego dentro de la suite completa.

## Reanudación de campaña 1.7.0

`campaign_resume` recupera un run pausado usando el checkpoint persistente, el mismo scope y el perfil/superficie actuales. Rechaza definiciones cambiadas, ventanas vencidas y reservas inciertas; enlaza un run terminal con su reporte sin enviar solicitudes adicionales. La prueba local cancela una campaña antes del primer request, comprueba `interrupted-action`, reanuda cinco pasos pendientes y bloquea una segunda reanudación. El CLI propaga SIGINT mediante `AbortSignal` a captura, ejecución y reanudación de campaña. La captura Chromium sigue sin reanudación automática y necesita inspección manual si se interrumpe.

Verificación 1.7.0: `npm run verify` aprobó **176 pruebas sin omisiones**, TypeScript estricto y build de 40 módulos. Todos los requests de la prueba nueva se enviaron al servidor loopback descartable.

## Reporte semántico 1.8.0

Cada hallazgo del evaluador semántico ahora responde en secciones separadas qué es, cómo se encontró, cuál es la demostración de explotabilidad, cómo reproducirla y cómo corregirla. La demostración cita IDs de evidencia y conserva el estado `confirmed`, `not-reproduced` o `unresolved`; solo `confirmed` describe la lectura protegida observada, sin extrapolar alcance o severidad. La guía de cobertura sigue en `coverage.json` y el borrador requiere revisión del programa antes de enviarse.

Verificación 1.8.0: `npm run verify` aprobó **176 pruebas sin omisiones**, TypeScript estricto y build de 40 módulos. Las pruebas semánticas de las cuatro clases comprueban ahora las cinco secciones del reporte.

## Comprobadores y política vinculada 1.9.0

Se agregaron recorridos concretos de evaluación aritmética en una entrada literal, solicitud saliente a un callback propio, exposición de un campo privado entre dos cuentas correlacionada con una URL compartida, doble uso concurrente de un recurso descartable y cambio de estado propio mediante formulario de otro origen. Todos verifican precondiciones, usan rutas y métodos exactos y producen evidencia y un borrador con qué es, cómo se encontró, demostración, reproducción y corrección. La carrera y el formulario son acciones de una sola vez: una interrupción requiere revisar el journal antes de volver a probar. Ver [entrada y SSRF](INPUT-PROOFS.md), [cache](CACHE-CHECK.md), [carrera](RACE-CHECK.md) y [CSRF](CSRF-CHECK.md).

`campaign_policy_review` liga por SHA-256 una copia local `policy-source.txt` a la decisión documentada y `campaign_status` detecta alteraciones. La fuente y su vigencia siguen requiriendo comprobación humana: el digest no prueba autorización del dueño. También hacen falta reglas de negocio y cuentas o recursos controlados para evaluar acceso e impacto. Continúan pendientes confirmadores genéricos de SQL/NoSQL/comandos, destinos internos SSRF, variantes CSRF con otros tipos de solicitud, atribución causal de cache y carreras en flujos distintos. No hay paridad funcional con REA ni capacidad de garantizar una falla crítica para cualquier web o app; REA además resuelve otro problema, el análisis de artefactos y runtimes. La evidencia de laboratorio no se extrapola a un servicio externo.

Verificación 1.9.0: `npm run verify` aprobó **194 pruebas sin omisiones**, TypeScript estricto y build de 45 módulos. Incluye variantes vulnerables/corregidas de los cinco recorridos, rechazos antes de enviar tráfico fuera de scope, integridad de la copia de política también mediante MCP y retención de dos reservas inciertas para una pareja concurrente. Solo se usaron servidores loopback sintéticos para estos recorridos.

## Consolidación arquitectónica y expansión de capacidades 2.0.0

Se ejecutaron tres bloques sobre la línea base 1.9.0:

1. **Correcciones de seguridad, transporte y protocolo (13 fixes):** sanitización de errores en fronteras CLI/MCP (`SafeError`), soporte RFC 6265 en cookies (`|` y `:`), fijación DNS dual-stack pública + cierre prematuro de respuestas (`incomplete-response`), validación RFC 6901 de índices de arreglo, contención multiplataforma Win32 + locks transaccionales SQLite (`withSqliteLockSync`), atención fuera de banda de `ping` y `notifications/cancelled` con `AbortSignal` real en MCP, liberación fuera de orden de pares concurrentes en `ProgramBudget`, preservación completa de cookies en `csrf-check`, preservación de tipos JSON en `jwt-check`, propagación de `requestHeaders` en `study.ts`, chequeo de deadline previo a esperas + congelamiento de `RTCPeerConnection` contra fugas STUN UDP en Chrome 145+ y soporte de caracteres `pchar` (`:`, `@`) en rutas RFC 3986.
2. **Refactorización estructural y DX (12 cambios):** registro declarativo de comandos CLI (`src/commands.ts`) con subcomandos jerárquicos (`bba campaign|check|study ...`) y ayuda por comando, esquemas declarativos sin dependencias (`src/schema.ts`) con proyección JSON Schema y rutas exactas de campo, módulo compartido `src/journal.ts` y enrutamiento cruzado `evidence-view` / `artifact-view`, build recursivo seguro (`scripts/build.ts`), CI multiplataforma GitHub Actions (`.github/workflows/ci.yml`), sello `producerVersion`, internacionalización `--lang es|en` (`src/i18n.ts`), soporte de `pathPrefixes`, plantillas `{param}` y parámetros `filter[id]` en `scope.ts`, compatibilidad Node `>=22.13.0`, `setup-mcp` multi-cliente (`codex`, `claude`, `gemini`), empaquetador PKZIP nativo (`scripts/package-skill.ts`) y modo `--quarantine` con proyección `O(N)` de HAR.
3. **Nuevas capacidades de comprobación, superficie y evidencia (12 features):** confirmador semántico de escritura/mutación y `mass-assignment` con verificación antes/después sobre recursos descartables, importación offline de GraphQL (introspección/SDL) y bundles JS/SourceMap v3 + `graphql-check`, modos JWT `alg-none` y `expired-token` + `oauth-check` (`redirect_uri`), bootstrap efímero de credenciales en memoria (`--auth-bootstrap`), `redirect-check` con clasificación de `Location` 3xx sin seguir redirecciones, `import-policy` (HackerOne, Bugcrowd, Intigriti, `security.txt`) con cuarentena de comodines, `plan-candidates` desde salidas de scanners, `export-submission` con línea base CVSS v3.1/v4.0 y `curl` redactados, carreras multiplexadas sobre una única conexión HTTP/2 (`transport: "http2"`), firma y verificación criptográfica Ed25519 (`keygen`, `sign-evidence`, `verify-signature`) e inspector HTML local en `127.0.0.1` con CSP estricta (`ui`).

