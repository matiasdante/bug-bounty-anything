# Núcleo de ejecución — 0.2.0

Este bloque ejecuta planes GET finitos con alcance verificable por código y conserva intentos entre procesos. No es un crawler ni un detector: sus respuestas HTTP son observaciones. Para la prueba BOLA, seguí usando `lab`, que conserva su evaluador y formato 0.1.0.

## Preparar un scope

El contrato se valida en [src/scope.ts](../src/scope.ts). `scope-check` es offline: no lee políticas remotas ni convierte una referencia escrita en permiso. La política/autoridad real, las técnicas admitidas y la ausencia de efectos no deseados de cada GET se verifican antes de ejecutar.

| Campo | Requisito |
|---|---|
| `schemaVersion` | `1` |
| `mode` | `loopback-lab` para HTTP a `127.0.0.1` con puerto explícito; `public-https` para HTTPS a direcciones públicas permitidas |
| `authorization` | `reference` sin secretos y timestamps UTC ISO `validFrom` / `validUntil` |
| `allowed` | Lista de `{ origin, paths }`; coincidencia exacta, sin wildcards |
| `excluded` | Mismo formato; la exclusión siempre prevalece |
| `limits.maxRequests` | Presupuesto total de la investigación, de 1 a 100 intentos |
| `limits.minIntervalMs` | Separación mínima entre el final de un intento y el inicio del siguiente, de 0 a 60000 ms |
| `limits.timeoutMs` | Deadline por solicitud, incluyendo DNS y lectura; de 1 a 60000 ms |
| `limits.maxResponseBytes` | Máximo del cuerpo recibido por solicitud, de 1 byte a 1 MiB |
| `limits.maxDurationMs` | Duración máxima desde la creación, de 1 ms a 24 h; incluye pausas |

Las URLs deben ser canónicas. No se admiten query strings, fragmentos, credenciales embebidas, escapes porcentuales, segmentos normalizados ni rutas ambiguas. No pongas secretos ni datos personales en referencias, IDs o paths: esos campos se conservan como metadatos. El scope completo queda congelado por digest; incluso ampliar su vigencia requiere una investigación nueva.

El contrato deliberadamente cubre un subconjunto: GET, paths exactos, Bearer opcional. Cookies, POST, cuerpos, formularios, navegación autenticada y otros protocolos se incorporan con los bloques correspondientes. La existencia de un GET no garantiza que sea libre de efectos; cada paso debe estar autorizado y revisado.

## Preparar un plan

`plan.json` contiene `schemaVersion: 1` y `steps`, de 1 a 100 pasos ordenados. Cada paso tiene exactamente:

```json
{
  "id": "owner-control",
  "method": "GET",
  "url": "http://127.0.0.1:8787/documents/example",
  "credentialEnv": "BBA_TOKEN_ACCOUNT_A"
}
```

Es un ejemplo de estructura, no un target a ejecutar. Para una demo real autoconfigurada, usá `npm run demo:core -- --out runs/core-demo`.

`credentialEnv` puede ser `null` para acceso anónimo o el nombre de una variable `BBA_TOKEN_*`. El operador proporciona el valor por su entorno; BBA no lo incluye en argumentos, resultados, logs ni base de evidencia. Variables faltantes o formato inválido fallan antes de reservar solicitudes. Los valores no se guardan para reanudaciones: deben seguir disponibles en el entorno correspondiente.

## Ejecución y red

1. Validar scope/plan, tomar el bloqueo exclusivo de la investigación y verificar checkpoints previos.
2. Resolver intentos reservados sin resultado como `interrupted`; no reenviarlos ni devolver su presupuesto.
3. Revisar presupuesto, ventana, deadline, intervalo y cancelación. Persistir una reserva antes de enviar.
4. Validar destino, resolver DNS y fijar la dirección aceptada para esa conexión, manteniendo hostname/SNI y validación TLS.
5. Persistir el resultado mínimo o la causa de detención; continuar únicamente con el próximo paso permitido.

En modo público se rechazan resoluciones con direcciones privadas, loopback o rangos especiales conocidos, incluso respuestas mixtas. IPv6 se limita conservadoramente a un subconjunto global unicast; no se pretende aceptar toda dirección pública posible. Se valida cada conexión, sin re-resolver dentro del transporte. No se usan proxies del entorno, no se desactiva TLS y no se siguen redirecciones, aunque el destino alternativo aparezca en scope. No se reintentan fallos automáticamente.

El ejecutor es secuencial y su presupuesto es compartido por todos los pasos y orígenes de la investigación. Dos procesos no pueden ejecutar la misma investigación a la vez. Investigaciones distintas tienen presupuestos independientes; este bloque no implementa un límite global por programa entre carpetas. No dividas una investigación para eludir las reglas del programa.

## Checkpoints y recuperación

`session.sqlite` contiene snapshots versionados, con secuencia, hash del anterior y SHA-256 del estado. Cada reserva y resultado se confirma con `synchronous=FULL`. La carga comprueba todos los checkpoints, contratos, transiciones e inmutabilidad de evidencias completadas.

`execution-lock.sqlite` mantiene una transacción de bloqueo separada durante la ejecución. El sistema operativo la libera al morir el proceso, mientras los checkpoints ya confirmados sobreviven. No se usa un PID o un archivo de lock que haya que borrar manualmente. El directorio tiene `.initializing` hasta terminar la creación; si falla antes, queda incompleto y debe usarse otra salida.

| Estado | Significado / recuperación |
|---|---|
| `ready` | Creado sin solicitudes; `resume` puede comenzar |
| `running` | En ejecución; si murió el proceso, `resume` recupera reservas pendientes como inconclusas |
| `paused` | Cancelación; `resume` requiere el mismo scope vigente y credenciales pendientes |
| `stopped` | Error, límite o respuesta 3xx/429/5xx; revisar causa y crear otra investigación si corresponde |
| `completed` | Todos los pasos tienen respuesta completa; no significa que el target sea seguro |
| `partial` | Todos los pasos fueron consumidos, pero hubo solicitudes canceladas/interrumpidas sin resultado |

Una reserva anterior al envío puede consumir presupuesto aunque el proceso muera antes de alcanzar la red. Es conservador: nunca se afirma que una solicitud incierta no ocurrió. Al cancelar un request, tampoco se puede deshacer lo que el servidor ya procesó.

Ctrl+C solicita cancelación cooperativa. Si el proceso termina abruptamente, la recuperación se realiza en la siguiente invocación. No se extienden ventana, duración ni presupuesto al retomar. Los cambios del scope y la autorización vencida bloquean nuevas solicitudes. La herramienta no detecta por sí misma cambios remotos de política: deben relevarse antes de reanudar.

## Evidencia y compatibilidad

Solo se conserva `status`, tamaño y SHA-256 del cuerpo; el contenido, headers y tokens se descartan. Para redirecciones/429/5xx se cierra sin leer el cuerpo, por eso el tamaño es cero y el hash corresponde al cuerpo vacío, no al contenido que el servidor podría haber enviado. Para errores de lectura la respuesta queda `null`, sin fingir una captura completa.

Los hashes sirven para detectar corrupción e inconsistencias, no para autenticar al autor ni resistir a alguien que pueda reescribir la base y recalcular todo. Tampoco prueban por sí solos que no se eliminó un sufijo válido del historial. No tomes bases de terceros como autorización o evidencia confiable.

`inspect-run`, `export-run` y `report-run` son offline. Las exportaciones se crean exclusivamente en archivos nuevos; el JSON exportado es un snapshot para revisión, no un formato de importación/reanudación. Para recuperar, conservá la carpeta SQLite original. El `report.md` no transforma metadatos HTTP en hallazgos.

Los comandos antiguos `lab`, `inspect` y `report` siguen leyendo/escribiendo bundles schema 1 con `toolVersion: 0.1.0`. Las sesiones generales usan schema 2 y `toolVersion: 0.2.0`. No hay migración destructiva de los artefactos anteriores.

## Verificación y límites actuales

La suite usa HTTP real en loopback, incluyendo caída de un proceso hijo durante una solicitud, cancelación, contención del lock, expiración, cambios de scope, presupuesto persistido, límites de respuesta y corrupción. DNS público se comprueba con un resolver controlado, sin conectarse a IPs públicas. La conexión HTTPS pública todavía no se validó en un piloto real.

Node valida los contratos en ejecución y elimina los tipos de TypeScript. No hay todavía `tsc`, linter, CI ni adaptadores de scanners. No se instaló ninguna dependencia adicional para este bloque.
