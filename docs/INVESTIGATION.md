# Investigación desde superficie y evidencia semántica

**Español** · [English](INVESTIGATION.en.md)

La skill prepara estos contratos a partir del servicio, su documentación y la política vigente. El operador aporta cuentas controladas y reglas de negocio que no puedan comprobarse públicamente. Una importación o una regla escrita no demuestra autorización real.

## Recorrido

```powershell
node dist/cli.js capabilities
node dist/cli.js import-surface --format openapi --input api.json --out surface.json
node dist/cli.js plan-investigation --scope scope.json --surface surface.json --profile profile.json --out runs/plan
node dist/cli.js investigate --scope scope.json --surface surface.json --profile profile.json --out runs/investigation
```

`plan-investigation` es offline. `investigate` envía GET: verifica identidades, ejecuta control/baseline/sonda, evalúa los hechos y genera el reporte. Se detiene en la primera confirmación (`proof-complete`); las otras hipótesis quedan pendientes. Sin hipótesis representables, escribe cobertura y reporte sin enviar requests; la CLI sale con código 3.

La salida incluye scope, perfil, plan, checks, `coverage.json` con checksum/procedencia/digest de checks, `run/` con checkpoints, `semantic.json` y `report.md`. Una caída conserva las reservas SQLite. Usá `resume-investigation <carpeta-del-caso> --scope <scope-canónico> --out <reporte-nuevo.md>`: verifica definición y scope, vuelve a evaluar lo retenido y no envía nada si ya existe una prueba confirmada. Las reservas inciertas no se repiten. Una detención terminal por otra causa requiere revisar el error, el presupuesto y la necesidad de otra investigación.

## Perfil

Ejemplo estructural para dos cuentas propias y documentos privados. Los dominios y paths ilustran el contrato; no son objetivos a ejecutar:

```json
{
  "schemaVersion": 1,
  "accounts": ["BBA_TOKEN_A", "BBA_TOKEN_B"],
  "identity": {
    "url": "https://service.example/me",
    "fact": "identity",
    "observe": [{ "name": "identity", "pointer": "/id" }]
  },
  "rules": [{
    "class": "bola",
    "origin": "https://service.example",
    "pathPrefix": "/documents",
    "protectedPointer": "/privateNotes",
    "subjectPointer": "/ownerId",
    "query": [],
    "policy": {
      "reference": "program private document rule",
      "boundary": "owner-only",
      "ownerFact": "owner"
    }
  }]
}
```

Las reglas se aplican por origen y prefijo de segmentos, dentro del scope exacto. No convierten todos los documentos en datos propios: los recursos deben ser de las cuentas controladas. Los endpoints con query necesitan referencias `{ name, valueEnv: "BBA_INPUT_..." }` y reglas de transporte que permitan esos nombres.

Una URL histórica con IDs numéricos/UUID puede haberse proyectado como template. El planificador la deja sin ejecutar. `bindings` opcional contiene `{ entryId, url }` para vincular un endpoint con una URL concreta de un recurso propio; valida el template y el scope. Los orígenes desconocidos, métodos sin generador, reglas faltantes y presupuestos insuficientes quedan explícitos en cobertura.

## Clases confirmadas

| Clase | Política | Hechos adicionales requeridos |
|---|---|---|
| `bola` | `owner-only`, `ownerFact` | El propietario del recurso coincide con la identidad del baseline |
| `bfla` | `role-private`, `roleFact`, `baselineRole`, `probeRole` | Roles distintos retornados por el servidor y coincidentes con los roles requeridos |
| `property-exposure` | Igual que BFLA | La propiedad privada seleccionada cruza esa frontera de roles |
| `tenant-isolation` | `tenant-private`, `tenantFact`, `resourceTenantFact` | Tenants distintos retornados por el servidor; tenant del recurso igual al del baseline |

Para roles, agregá la proyección correspondiente al endpoint de identidad y usá `subjectPointer: null`. Para tenants, proyectá el tenant en identidad y configurá el selector del tenant del recurso. `protectedPointer` siempre identifica el dato que la regla prohíbe devolver a la cuenta restringida.

Las identidades deben ser distintas, del mismo tipo y obtenidas antes de la comparación, con las mismas credenciales que después usan baseline/sonda. El endpoint de identidad y el recurso deben compartir origen. El control anónimo tiene que denegarse y el baseline tener un dato protegido significativo. La confirmación requiere que la sonda devuelva ese dato y cumpla los controles de propiedad/rol/tenant.

Una respuesta completa puede variar por timestamps o nonces: se compara la propiedad seleccionada. Un hash de cuerpo igual no confirma nada por sí solo. Un 401 en la sonda queda inconcluso porque la sesión puede haber expirado; 403/404 con controles válidos es `not-reproduced` para esa comparación. Una propiedad ausente puede ser negativa para esa propiedad; un valor diferente o un JSON ilegible queda inconcluso. La privacidad y ausencia de permisos compartidos siguen siendo precondiciones verificadas por el operador.

## Hechos y evidencia

Los pasos de `run` admiten `observe: [{ name, pointer }]`, con JSON Pointer RFC 6901. Se conserva nombre, presencia, tipo, si el valor era significativo y su SHA-256. Se distinguen propiedad ausente, null y respuesta no interpretable. Nunca se guardan los valores originales.

```powershell
node dist/cli.js evaluate-semantic runs/investigation/run --checks runs/investigation/checks.json --out runs/result.md
node dist/cli.js evidence-view runs/investigation/run --query view.json
node dist/cli.js compare-runs --before runs/old --after runs/new --out runs/comparison.json
```

`view.json`: `{ "kind": "summary", "offset": 0, "limit": 20 }`. Para páginas, usar `kind: "attempts"` o `"fields"`, `offset`, `limit` de 1 a 50 y opcional `stepId`. Conservar `revisionDigest` como `expectedDigest` para rechazar una revisión que cambió al reanudar. Los IDs son `sessionId:stepId` y `sessionId:stepId:factName`.

La comparación conserva referencias a ambas revisiones y distingue cambios de definición, respuesta y hechos. No clasifica vulnerabilidades. Los valores de credenciales/inputs no están disponibles para comparar; los digests de inputs están ligados a una sesión y no se toman como identidad entre ejecuciones. Los hashes de valores de poca entropía pueden adivinarse. Estos artefactos no autentican al operador.

Para `hunt`, `browser-check` y `browser-scenario`, `artifact.json` vincula el journal y resultado con digests de scope/config. `artifact-view <carpeta> --query view.json` verifica esos archivos y permite `kind: "summary"`, `"events"` o `"fields"`, con offset/limit, `eventType` y `expectedDigest` opcionales. Los eventos tienen IDs estables por ordinal. El summary no vuelca los objetos completos del inicio. Los artefactos anteriores sin sello y las ejecuciones interrumpidas conservan su formato original: revisar los archivos crudos y el presupuesto sin asumir que hay un registro completo.

## Presupuesto entre fases

Un scope nuevo debe incluir `budgetId`, por ejemplo `dcs-public-pilot`. CLI/MCP usan `.bba-budgets/<budgetId>/` junto al archivo de scope original. Reutilizá esa ubicación canónica para run/resume, capture, hunt, investigate y browser-check.

```powershell
node dist/cli.js inspect-budget .bba-budgets/dcs-public-pilot
```

El contador, intervalo y duración total sobreviven a carpetas nuevas y procesos caídos. La autorización y los límites de ese presupuesto no se pueden cambiar; las fases pueden restringir su superficie bajo la misma autorización. Un lock SQLite impide fases concurrentes. La reserva global se confirma antes de enviar y queda consumida si el resultado es incierto. Una reserva local puede consumir su presupuesto aunque no llegue a reservar red globalmente.

El runner fija la ubicación del presupuesto en sus checkpoints y rechaza retomar con otro ledger. No borrar, copiar a otra ubicación ni renombrar el ID para reiniciar consumo. Los scopes históricos sin `budgetId` conservan su semántica por ejecución. Las herramientas externas y la navegación fuera de BBA requieren contabilidad adicional. El presupuesto es un control operativo, no una prueba de permiso ni una defensa frente a un operador que pueda reescribir todos los archivos.
