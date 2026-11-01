# Instalación y configuración

[English](../installation.md) · **Español** · [Português (Brasil)](../pt-BR/installation.md) · [简体中文](../zh/installation.md)

Cómo instalar la skill de BBA, ejecutarla desde el código fuente o desde npm, diagnosticar el entorno local y registrar el servidor MCP. Para los comandos que envían solicitudes, consultá la [guía de CLI](cli.md).

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

Para pruebas de navegador, instalá Chromium aparte con `npx playwright-core install --only-shell chromium`. Desde el repositorio fuente, `npm install`, `npm run build` y `npm test` siguen siendo los comandos de desarrollo. El paquete público y su código están bajo [licencia MIT](../../LICENSE).

El paquete instalado es JavaScript compilado en `dist/` y expone el comando `bba` (incluidos subcomandos jerárquicos `bba campaign ...`, `bba check ...`, `bba study ...`, ayuda puntual `<comando> --help` e idioma `--lang es|en`).

`bba doctor` hace solo comprobaciones locales y no contacta ningún host: versión de Node (`>=22.13`), SQLite, loopback, carpeta temporal, lanzamiento de Chromium con aislamiento WebRTC reforzado y los **nombres** (nunca los valores) de las variables `BBA_TOKEN_*` / `BBA_COOKIE_*` / `BBA_HEADER_*` / `BBA_INPUT_*` / `BBA_BODY_*` presentes.

```powershell
bba mcp --root C:/ruta/al/workspace            # solo herramientas offline
bba mcp --root C:/ruta/al/workspace --allow-network
```

Servidor MCP por stdio (JSON-RPC sin dependencias externas: `initialize`, `ping` fuera de banda, cancelación real `notifications/cancelled` con `AbortSignal` y `tools`). `tools/list` es el inventario autoritativo; las herramientas activas solo existen con `--allow-network`. Todos los paths se confinan dentro de `--root` en Windows y POSIX; salidas fuera de raíz y escapes por enlaces simbólicos o junctions se rechazan, y los errores internos se sanitizan mediante `SafeError`.

Para conectar el MCP a Codex, Claude Code o Gemini CLI: `node dist/cli.js setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` muestra o aplica el registro preservando backups locales.


