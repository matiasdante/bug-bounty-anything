# Objetivo y flujo autónomo de BBA

[English](../HUNT.md) · **Español** · [Português (Brasil)](../pt-BR/HUNT.md) · [简体中文](../zh/HUNT.md)

Objetivo principal: partiendo de una web autorizada, descubrir superficie, generar y ejecutar hipótesis, confirmar una vulnerabilidad con controles, documentar su prueba y dejar el reporte listo para revisión y envío al bug bounty. Las cuentas, reglas y alcance se configuran una vez; el framework debe proponer y ejecutar pruebas dentro de esos límites, sin exigir una lista manual de bugs esperados.

## Implementación actual

`hunt --scope scope.json --config hunt.json --out runs/hunt` implementa ese recorrido para lectura indebida de campos privados entre dos cuentas (BOLA). Está disponible por CLI y por MCP con `--allow-network`.

La skill prepara estos archivos por el operador a partir del servicio y la política vigente; `prepare` inicia el caso y su registro sin red. `hunt` es una ruta especializada dentro de la investigación asistida por el agente. No exige usar esta ruta cuando faltan cuentas o la regla owner-only no corresponde.

Configuración de estructura (URLs ilustrativas; reemplazalas únicamente por las del servicio autorizado):

```json
{
  "schemaVersion": 1,
  "seed": "https://service.example/",
  "identityUrl": "https://service.example/api/me",
  "identityField": "id",
  "ownerField": "ownerId",
  "privateField": "privateNotes",
  "accounts": ["BBA_TOKEN_A", "BBA_TOKEN_B"],
  "boundary": "owner-only"
}
```

Los secretos se proporcionan mediante las variables de entorno referenciadas; `BBA_COOKIE_*` permite cookies. Se requieren cuentas de prueba distintas que controles, sin permisos compartidos sobre los recursos ensayados. El operador debe establecer que el campo privado solo corresponde al propietario. La herramienta no puede inferir esa regla de negocio de un campo llamado `ownerId`: se declara explícitamente y se conserva como precondición en el reporte.

El scope conserva el contrato existente de orígenes y rutas exactas. Puede incluir rutas autorizadas aún no visitadas; eso no prescribe qué probar. El descubrimiento no amplía ese permiso: enlaces externos, excluidos, con query o fuera de la representación admitida quedan sin visitar. No hay wildcards ni enumeración de objetos ajenos.

## Cómo confirma

1. Consulta el endpoint de identidad con cada credencial y exige dos identificadores distintos retornados por el servidor.
2. Recorre enlaces HTML desde la semilla como ambas cuentas, dentro de scope, con presupuesto, intervalo, timeout, tamaño máximo y deadline comunes.
3. Al encontrar un documento JSON cuyo propietario coincide con una de esas identidades y contiene el campo privado configurado, genera la hipótesis automáticamente.
4. Lee el mismo recurso sin credencial y con la otra cuenta; confirma solo si el acceso anónimo se deniega y la otra identidad recibe el mismo propietario y valor protegido.
5. Produce el resultado, referencias de evidencia y reporte. Una sesión inválida, datos públicos o controles incompletos no son confirmaciones.

Se detiene después de la primera confirmación para no leer más recursos privados de la misma causa. Los enlaces descubiertos que quedaron sin visitar permanecen como cobertura pendiente; una prueba positiva no cierra las otras clases. `scope.requestHeaders` identifica todas las solicitudes con marcadores por origen tomados del entorno, sin persistir sus valores.

Un 200 o un hash idéntico no bastan. El reporte enlaza respuestas, las pruebas de identidad y los digests de los campos comparados. La propiedad y confidencialidad reales dependen de las precondiciones declaradas; confirmar bajo esas condiciones no demuestra que todo contenido sea privado en cualquier política del servicio.

## Artefactos

- `requests.jsonl`: intención sincronizada a disco antes de cada envío, metadatos de respuesta, prueba redactada de identidad y comparación de campos. IDs numéricos enlazan el reporte con las operaciones concretas.
- `hunt.json`: superficie descubierta con la respuesta de origen, hipótesis y estados, presupuesto consumido, detención y limitaciones, con checksum.
- `report.md`: regla de acceso, precondiciones, pasos numerados de reproducción, actor/recurso, evidencia, efecto observado, propuesta de corrección y pendientes de triage.

No se guardan credenciales, cookies ni valores privados originales. Se guardan URLs autorizadas y nombres de campos: no pongas secretos en esos metadatos. La evidencia redactada es reproducible con cuentas de prueba, pero no es una captura completa de tráfico. Los hashes no autentican quién produjo los archivos. Los intentos iniciados sin respuesta quedan visibles en el journal.

Ctrl+C pide cancelación y deja el resultado parcial conocido; la CLI sale con código 130. También se verifica cancelación, deadline y autorización después de esperar el intervalo. No hay reanudación automática de `hunt`; nunca repite un intento incierto ni reinicia el presupuesto dentro de la misma ejecución. Para una ejecución nueva se requiere otra carpeta y revisión de lo ya consumido. `run/resume` conserva su mecanismo anterior para planes estáticos.

## Cobertura pendiente

`hunt` no ejecuta JavaScript ni infiere roles/tenants: su generador particular sigue limitado a BOLA mediante enlaces HTML. La versión 1.2 agrega por otras rutas [planificación y comprobaciones semánticas](INVESTIGATION.md), [XSS/CORS en Chromium](BROWSER-CHECKS.md) y [escenarios de sesión](SCENARIOS.md). No hay confirmación genérica de injection/SSRF ni inferencia universal de reglas de negocio. Cada clase necesita su criterio y controles propios.

Un target sin recursos descubiertos adecuados puede terminar sin hipótesis; no significa que sea seguro. Tampoco hay envío automático, garantía de recompensa, deduplicación con un programa real ni validación de producción en esta revisión.

## Revisión histórica del trabajo previo de Claude, anterior a 1.2

Se revisaron los flujos de scope/transporte, captura, importación, evaluación, persistencia, CLI/MCP, empaquetado y evaluación congelada. Componentes útiles conservados: presupuesto y checkpoints, aislamiento de destinos, importadores con procedencia, navegador separado por identidad, MCP restringido y paquete JS.

Correcciones realizadas:

- Agregado el flujo autónomo anterior: antes había que seleccionar manualmente URLs y triples de prueba.
- `evaluate-run` deja las coincidencias de hashes como `needs-validation`; respuestas diferentes en exposición de propiedades quedan `unresolved`. No había evidencia suficiente para afirmar confirmación ni ausencia de fuga parcial.
- Revisión 2 explícita del manifiesto congelado: conserva el digest anterior en código; las tres comparaciones hash pasan a candidatos y sus métricas muestran cero confirmaciones y tres omisiones. No se reetiquetan como detecciones para mantener una métrica alta. Las pruebas autónomas se verifican en una suite aparte.
- La captura no reenvía la credencial de la página a un origen diferente y vuelve a comprobar cancelación/deadline después de la espera.
- El build valida que la ruta a borrar sea exactamente `dist` o `.build-test` del workspace y rechaza links; antes aceptaba una ruta arbitraria.
- El piloto propio documentado por Claude no satisface la selección de un programa de bug bounty de terceros. Su autorización histórica no habilita pruebas nuevas.

En aquella revisión inicial las seis pruebas de navegador quedaron omitidas por falta de Chromium. En 1.2 se instaló el navegador, se verificó la suite sin omisiones y se repitió un piloto público acotado en DCS. Eso no demuestra cobertura web completa ni detección general.
