# Conexión y recuperación

**Español** · [English](connection-and-recovery.md)

Usá esta guía solo ante un bloqueo observado de runtime o conexión. La skill puede guiar una investigación con las herramientas existentes sin MCP. Identificá la falla antes de inspeccionar configuraciones ajenas o reinstalar dependencias.

## Skill instalada o repositorio

- En una skill instalada, leé `runtime.json` junto a `SKILL.md`: `command` es Node y `args` contiene la ruta absoluta del CLI compilado. Conservá el array de argumentos y ubicá trabajo/salidas en el workspace del caso.
- En el repositorio, `node src/cli.ts --help`; en el paquete compilado, `node dist/cli.js --help`. Requiere Node 22.13+. Para una ejecución puntual desde npm, usá `npx --yes bug-bounty-anything@latest --help` y comprobá la identidad del paquete antes de usar nombres parecidos.
- Si falta el CLI compilado, ejecutá `npm run build` desde la fuente confiable con prerrequisitos existentes. Si el paquete cambió de lugar, instalá en una carpeta nueva o actualizá solo la ruta obsoleta según permisos de escritura reales; no sobrescribas otra instalación.
- Para una skill o MCP persistente, preferí `npm install --global bug-bounty-anything@latest`: el registro guarda la ruta del CLI y una entrada temporal de la caché de `npx` puede desaparecer.
- Para instalar: `node dist/cli.js install-skill --out <carpeta-nueva>`. Copia instrucciones, referencias y metadatos de UI, registra el runtime, pero no copia dependencias ni configura MCP. Mantené disponible el paquete original. Una salida existente se rechaza.
- Para actualizar esa instalación: `node dist/cli.js update-skill --out <carpeta-existente>`. Comprueba vínculo con el paquete, rechaza enlaces en recursos, guarda backups en `.bba-backups/` y conserva archivos ajenos. No actualiza dependencias ni MCP. Revisá un update interrumpido antes de borrar `.bba-update.lock.sqlite`.

Descubrir la skill puede requerir un chat nuevo o reinicio. Su existencia en disco no prueba que el catálogo del agente se haya actualizado; leer `SKILL.md` expresamente permite usar el flujo actual.

## Diagnosticar la capacidad afectada

Ejecutá `doctor` una vez si no están claros los prerrequisitos locales; no contacta el target. Chromium ausente afecta captura e inspección/pruebas de navegador, pero no importación, ejecución HTTP, `prepare` ni `hunt`. Loopback fallido puede deberse al sandbox del host. Informá la causa sin debilitar validación de destino, TLS ni disfrazar requests bloqueadas. No instales Node, navegador o paquetes salvo que lo autoricen la tarea y el host; explicá descargas antes. Mientras tanto, aprovechá capacidades offline.

## Registro MCP en Codex

Desde el paquete compilado, `node dist/cli.js setup-mcp --root <workspace-del-caso>` muestra vista previa. `--apply` registra `bba` mediante `codex mcp add`. Reemplazar una entrada diferente exige `--replace`; se guarda backup de `~/.codex/config.toml` en `~/.codex/.bba-backups/` y se comprueba con `codex mcp get bba`. No instala Codex ni dependencias. Por defecto solo expone herramientas offline; `--allow-network` habilita herramientas activas, pero cada target todavía exige scope vigente y revisado. Reconectá Codex y verificá `tools/list`.

## MCP manual

Para un registro solicitado, prepará un cambio revisable a la configuración existente con las rutas reales de Node, CLI y un workspace:

```json
{
  "command": "<ejecutable-node-absoluto>",
  "args": ["<paquete-absoluto>/dist/cli.js", "mcp", "--root", "<workspace-del-caso>"]
}
```

Resolvé esas rutas ilustrativas antes de editar. Offline es el modo inicial. Agregá `--allow-network` solo para una ejecución autorizada: habilita capacidad del servidor, no acredita permiso del dueño. El proceso hereda credenciales y valores de headers del entorno, nunca de argumentos; restringí acceso a él. Conservá servidores y secretos existentes. Reconectá el cliente y verificá descubrimiento real. Ante un bloqueo, inspeccioná el error específico antes de repetir setup o afirmar que CLI probó MCP. Los paths MCP se confinan a `--root`; mantené allí scope, entradas y salidas. El scope es una declaración del operador: revisá quién puede modificarlo antes de habilitar red.
