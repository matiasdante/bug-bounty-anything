# BBA — Bug Bounty Anything

Framework local de investigación de vulnerabilidades con evidencia reproducible. **Versión implementada: 0.2.0**, bloques 1 y 2 del [roadmap hacia 1.0.0](docs/ROADMAP.md). La metodología general está en [SKILL.md](SKILL.md).

Incluye un laboratorio HTTP para detectar lectura indebida entre cuentas y un núcleo de ejecución GET con alcance explícito, presupuesto persistente, cancelación y recuperación. El núcleo admite laboratorios locales y destinos HTTPS públicos autorizados; todavía no incorpora capturas externas, scanners ni confirmación automática de vulnerabilidades fuera del laboratorio.

## Requisitos y ejecución

- Node.js **26 o posterior**, con npm. Se probó con Node 26.12.0 en Windows.
- TypeScript y SQLite provistos por Node; no hay dependencias de terceros ni hace falta `npm install`.
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

Captura y superficie: importación HAR/OpenAPI, procedencia del inventario e integración con REA. El servicio productivo y la autorización concreta todavía no están seleccionados.
