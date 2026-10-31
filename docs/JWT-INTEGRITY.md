# Integridad de JWT firmado

**Español** · [English](JWT-INTEGRITY.en.md)

Este bloque responde una pregunta acotada: ¿el servicio acepta un JWT de una
cuenta de prueba propia después de cambiar su payload **sin volver a firmarlo**?
Un resultado positivo demuestra que esa ruta aceptó un token cuya firma ya no
corresponde al contenido. No acredita acceso a identidades ajenas, permisos de
administrador ni alcance sobre otros datos.

## Cómo llega la skill a esta hipótesis

En el [caso Titan](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records),
el investigador encontró una API separada de un frontend restringido, leyó su
Swagger público, usó configuración archivada como pista histórica y observó que
distintas mutaciones de claims avanzaban por las validaciones sin cambiar la
firma. Finalmente confirmó el efecto con una consulta mínima; el volumen total
fue una **estimación de metadatos**, no un volcado de registros.

Para investigar una cadena similar, BBA distingue cuatro estados de evidencia:

1. **Declarado:** ruta y esquema en OpenAPI/Swagger importado offline.
2. **Histórico:** valores o endpoints en archivos públicos; pueden haber caducado.
3. **Observado:** respuesta actual a una solicitud dentro del alcance vigente.
4. **Confirmado:** control anónimo denegado, token válido estable y token alterado
   aceptado para un hecho protegido de la cuenta propia.

Una página de VPN en el frontend no implica que la API tenga el mismo control.
Tampoco convierte los hosts descubiertos en objetivos autorizados. Revisá la
política para **cada** host, técnica, método y recurso antes de enviar tráfico.
Importá Swagger 2.0 en JSON con `import-surface --format openapi`; sus rutas son candidatos,
no requests ejecutables. Los errores de validación son pistas para formular una
hipótesis; un error distinto, por sí solo, no confirma un bypass.

## Contrato

Ejemplo de una ruta de consulta **del laboratorio o de un activo autorizado**.
El cuerpo debe ser inocuo y devolver únicamente un hecho propio, como un valor
escalar de prueba. Los secretos y el cuerpo se suministran por variables de
entorno; el archivo no contiene sus valores.

```json
{
  "schemaVersion": 1,
  "policyReference": "program rule for owned account",
  "boundary": "jwt-signature-integrity",
  "url": "https://service.example/v2/Query",
  "request": { "method": "POST", "body": { "format": "json", "valueEnv": "BBA_BODY_QUERY" } },
  "credentialEnv": "BBA_TOKEN_OWNED",
  "proofPointer": "/result",
  "mutation": { "claim": "bba_probe", "mode": "add-canary" }
}
```

La configuración también acepta `"mutation": {"claim":"claim_name",
"mode":"replace","valueEnv":"BBA_INPUT_OWN_VALUE"}` para un valor controlado
por el investigador. Debe ser un claim existente y cambiar su valor. No uses
identidades ajenas, usuarios adivinados ni roles privilegiados que no controles.
`add-canary` incorpora un claim nuevo con un valor determinista derivado del
token original; no cambia la firma. En ambos modos, el token original debe ser
un JWT compacto firmado de tres partes; se rechaza `alg: none` como punto de
partida.

El `scope.json` debe permitir la URL exacta y, para POST, una `requestRule` que
autorice ese método y el formato `json`. Si la ruta hace cambios, la política
debe cubrir esa acción y se requieren recursos descartables. `proofPointer` es
un JSON Pointer hacia un valor no público pero inocuo de la cuenta de prueba.
El cuerpo bruto no se guarda: se conserva tipo, presencia, significado y SHA-256.
Un valor de poca entropía puede deducirse a partir de su hash.

## Ejecución y lectura

```powershell
$env:BBA_TOKEN_OWNED = '<JWT firmado de cuenta de prueba propia>'
$env:BBA_BODY_QUERY = '{"query":"SELECT 1","tableName":"OwnedTestData","rowLimit":1}'
node dist/cli.js jwt-check --scope scope.json --config jwt-check.json --out runs/jwt-check
node dist/cli.js evaluate-jwt runs/jwt-check/run --config jwt-check.json --out runs/jwt-evaluation.json
```

El ejemplo SQL ilustra una consulta **sobre datos de prueba propios**. No es
una invitación a consultar metadatos, tablas de clientes o un servicio real sin
permiso concreto. El agente debe elegir el menor request que revele un hecho
protegido y no reiterar la consulta después de confirmarlo.

El motor envía exactamente cuatro requests al mismo endpoint y con el mismo
cuerpo: anónimo, JWT original, JWT alterado y JWT original otra vez. No sigue
redirects. El presupuesto compartido del scope contabiliza los cuatro intentos
y sus intervalos; 429/5xx detienen el flujo. Los JWT viven solo en memoria. La
carpeta guarda bindings salados del token original y de la mutación, el plan sin credenciales,
checkpoints SQLite, `result.json` y el borrador `report.md` cuando terminan los
cuatro pasos. `evaluate-jwt` también acepta un archivo de salida `.md`.

`confirmed` requiere anónimo 401/403/404, ambos controles válidos 200 con el
mismo hecho protegido significativo, y 200 con ese mismo hecho para el token
alterado. `not-reproduced` significa que esta mutación fue denegada mientras
el token original seguía válido. Cualquier control ausente, respuesta distinta
o hecho no interpretable queda `unresolved`.

Una interrupción se retoma únicamente con el **mismo token original**, scope,
configuración y presupuesto canónico:

```powershell
node dist/cli.js resume-jwt runs/jwt-check --scope scope.json --config jwt-check.json
```

El motor no repite reservas inciertas. Si el proceso murió luego de enviar un
request y antes de registrar la respuesta, esa comparación queda inconclusa;
creá otra investigación dentro del presupuesto vigente si la política y la
ventana todavía lo permiten. `evaluate-jwt` es offline y puede volver a
evaluar la evidencia existente sin enviar requests.

El reporte debe expresar el impacto observado en esa cuenta y ruta. Escalar
desde allí a otro usuario, roles o inventarios de datos exige autorización y
una nueva hipótesis con controles propios. No enumeres registros para inflar
una estimación: los metadatos agregados y las muestras acotadas se documentan
como tales, con sus supuestos.
