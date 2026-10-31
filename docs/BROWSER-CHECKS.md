# Pruebas de XSS y CORS en Chromium

`browser-check --scope scope.json --config browser.json --out <carpeta-nueva>` y MCP `browser_check` ejecutan comparaciones finitas sobre datos y orígenes controlados. Requieren Chromium instalado y scope/técnicas autorizados. La presencia de headers o texto reflejado no alcanza como prueba.

Todas las solicitudes pasan por el transporte de BBA. Solo salen GET cuya URL completa y método coincidan con los pasos declarados y sus inputs del entorno. Se preservan headers CSP, CORS, aislamiento de orígenes y `nosniff`; no se siguen redirects. Service workers, WebSockets, descargas y accesos fuera del plan están bloqueados. Se mantienen el proxy sumidero y la política WebRTC. Un presupuesto compartido se aplica cuando el scope incluye `budgetId`.

## Campos comunes

`schemaVersion: 1`, `class`, `policyReference`, `observationMs` (50–5000), `baseline`, `probe` y `resources`. Los pasos usan el contrato de `run`: ID, GET, URL base y `credentialEnv`, con query opcional desde `BBA_INPUT_*`. IDs únicos. `resources` enumera los assets que las páginas realmente necesitan; no se amplía a hosts descubiertos automáticamente. Los pasos no admiten bodies ni proyecciones en estas pruebas.

## XSS

Configurar `class: "xss"`, `boundary: "untrusted-input-script"` y `markerEnv: "BBA_INPUT_MARKER"`. Baseline y sonda navegan la misma URL base con las mismas credenciales y distintos inputs concretos. El marcador es opaco y único, de 12 a 128 caracteres alfanuméricos, guion o underscore.

El agente prepara un input benigno y otro mínimo que, en el contexto identificado, intente llamar a `window.__bbaProof(marcador)`. El payload queda en una variable de entorno; no se agrega al plan o reporte. Chromium expone esa función para observar únicamente el marcador esperado, llamado desde el origen de la aplicación. No se leen cookies, archivos, tokens ni datos de otros usuarios.

Se confirma si la sonda ejecuta el marcador y el baseline no. El contenido escapado o bloqueado por CSP no confirma. Ejecución en ambos controles, cargas necesarias bloqueadas, presupuesto agotado o fallas quedan inconclusos. Un negativo solo describe el input/contexto y ventana observados. El operador debe establecer que el input es controlable por un atacante y llega a un contexto donde no debería ejecutar; self-XSS o HTML intencional no son automáticamente reportables. No hay generador universal de payloads ni pruebas almacenadas que puedan alcanzar usuarios reales.

## CORS

Configurar `class: "cors"`, `boundary: "private-cross-origin-read"`, `protectedPointer` y `target` (GET al dato privado). `baseline` abre una página del origen de target; `probe`, una página de un origen distinto controlado y permitido. Se configura:

```json
"cookie": {
  "origin": "https://service.example",
  "valueEnv": "BBA_COOKIE_A",
  "sameSite": "Lax"
}
```

El `credentialEnv` de target debe coincidir con esa cookie. Solo los pasos de su origen pueden usarla; la página extranjera no la recibe por el relay. El valor tiene formato `nombre=valor; nombre2=valor2`. Chromium recibe las cookies de prueba con URL y SameSite declarados; el atributo Secure deriva de HTTPS. Esa configuración debe representar la sesión real: no se infieren los atributos ni se automatiza login/rotación.

Se ejecuta un control anónimo, una lectura desde el propio origen y otra desde el origen extranjero mediante `fetch` con `credentials: "include"`. El relay conserva `Origin`, los headers CORS y la entrega real de cookies del navegador; nunca agrega una cookie que Chromium omitió. La confirmación requiere control anónimo denegado y lectura del mismo campo privado desde el origen extranjero.

El caso `Access-Control-Allow-Origin: *` con credenciales es rechazado por Chromium. Una sonda 401, datos públicos, valor diferente o evidencia insuficiente quedan inconclusos. Si el relay recibió el dato y el navegador no pudo leerlo, no se reprodujo esa lectura; no se deduce que todas las políticas CORS sean correctas. El origen atacante y los atributos de cookie son precondiciones materiales del reporte.

## Evidencia y recuperación

Se copian scope/config sin valores del entorno. `requests.jsonl` sincroniza reservas antes del envío, respuesta mínima y comparaciones redactadas. `browser-check.json` conserva observaciones, resultado y checksum; `artifact.json` vincula los archivos y sus fuentes para consulta paginada con `artifact-view`. `report.md` es un borrador. No se guardan bodies, cookies, payloads ni el marcador original; antes de enviar se deben reconstruir los inputs de prueba seguros y la reproducción exacta con sus precondiciones.

No hay reanudación de una prueba de navegador. Si el proceso cae, el journal y el presupuesto compartido conservan las reservas inciertas; revisar antes de una nueva salida. La ventana total, el intervalo, los bytes, 3xx/429/5xx y cancelación mantienen sus condiciones de parada. Se verificó con aplicaciones sintéticas vulnerables/corregidas, CSP, wildcard CORS, credenciales ausentes, filtrado y sesión vencida.
