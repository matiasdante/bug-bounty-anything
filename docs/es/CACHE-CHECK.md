# Exposición correlacionada con cache (1.9.0)

[English](../CACHE-CHECK.md) · **Español** · [Português (Brasil)](../pt-BR/CACHE-CHECK.md) · [简体中文](../zh/CACHE-CHECK.md)

`cache-check` / `cache_check` ejecuta siete GET exactos contra un recurso propio
con dos cuentas controladas. El config lleva `schemaVersion: 1`,
`class: "cross-identity-cache"`, `policyReference`, `identityUrl`,
`identityPointer`, `resourceUrl`, `protectedPointer`, `accountA`, `accountB`,
`bustQueryName` y dos `bustTokens` opacos distintos. Las cuentas se referencian
por `BBA_TOKEN_*` o `BBA_COOKIE_*`; los valores no entran en la configuración.
El scope debe permitir ambas rutas, el nombre de query y al menos siete requests.

El recorrido establece identidades distintas y denegación anónima, confirma que
A puede leer el dato protegido con un parámetro de cache busting y B no puede,
precalienta la URL sin parámetro con A y la lee con B. `confirmed` exige que B
reciba el mismo campo protegido de A en esa URL compartida. `not-reproduced`
exige que B sea denegado. Controles incompletos o una lectura de B también con
cache busting quedan `unresolved`, pues allí la causa puede ser autorización
general y no cache. `resume-cache-check` / `resume_cache_check` conserva el
mismo scope, cuentas, config y presupuesto sin repetir reservas inciertas.

El operador debe comprobar que los tokens de busting son semánticamente
inertes, que las cuentas no comparten permisos y que el recurso es suyo. El
resultado demuestra una exposición **correlacionada** con cache; no atribuye
con certeza la capa, el algoritmo de clave ni otras rutas. Solo se guardan
hechos proyectados y digests, nunca el valor protegido. El borrador responde
las cinco preguntas del reporte y limita el impacto al campo comprobado.
