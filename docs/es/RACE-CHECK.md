# Carrera de operación de uso único (1.9.0)

[English](../RACE-CHECK.md) · **Español** · [Português (Brasil)](../pt-BR/RACE-CHECK.md) · [简体中文](../zh/RACE-CHECK.md)

`race-check` / `race_check` prueba una sola regla de uso único sobre **dos
recursos descartables propios**. El config incluye `schemaVersion: 1`,
`class: "single-use-race"`, `policyReference`, `credentialEnv`, `actionUrl`,
`actionField`, `controlResourceId`, `raceResourceId`, `controlStateUrl`,
`raceStateUrl` y `countPointer`. Las tres URLs deben estar en el mismo origen,
ser exactas y distintas. El scope debe permitir JSON POST sobre `actionUrl`,
GET sobre ambos estados, al menos siete requests y `minIntervalMs: 0`. El
token/cookie se lee de `BBA_TOKEN_*` / `BBA_COOKIE_*` en el entorno.

El motor verifica contador inicial cero, ejecuta la acción dos veces en el
recurso de control y exige que el segundo uso sea rechazado. Si falla ese
control, **no ejecuta la carrera**. En el segundo recurso verifica contador
cero, reserva dos requests del presupuesto compartido en una pareja y envía
exactamente dos POST simultáneos. Confirma solo si ambos fueron aceptados,
las ventanas de envío se solaparon y el contador final es dos. Una sola
aceptación con contador final uno y ventanas solapadas queda `not-reproduced`; lo demás es
`unresolved`. La variante vulnerable y la corregida están probadas con
servidores loopback sintéticos.

El journal se sella con `artifact.json` y se consulta con `artifact-view`.
Una caída deja reservas inciertas y este check no reanuda ni repite acciones
de estado. El operador debe crear, controlar y limpiar ambos recursos y
establecer que la regla realmente es uso único. Un doble efecto local no
demuestra impacto financiero ni otras rutas. El reporte trae las cinco
preguntas y evidencia de estado, sin guardar credenciales ni cuerpos.
