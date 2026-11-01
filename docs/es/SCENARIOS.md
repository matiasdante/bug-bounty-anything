# Escenarios controlados con sesión real de navegador

[English](../SCENARIOS.md) · **Español** · [Português (Brasil)](../pt-BR/SCENARIOS.md) · [简体中文](../zh/SCENARIOS.md)

```powershell
node dist/cli.js browser-scenario --scope scope.json --config scenario.json --out runs/scenario
```

MCP: `browser_scenario`, solo con red habilitada. Ejecuta un flujo declarado en un contexto Chromium efímero: navegación, llenado de campos, click y espera de un selector visible. Las cookies de login y su rotación se aplican en memoria con los atributos Set-Cookie reales. La salida describe observaciones; no declara automáticamente una vulnerabilidad.

## Contrato

`scenario.json` tiene exactamente `schemaVersion: 1`, `policyReference`, `boundary: "controlled-workflow"`, `sessionOrigin`, `plan`, `actions`, `maxRedirects` y `observe`.

- `sessionOrigin`: origen permitido al que se pueden devolver cookies/Bearer generados por el navegador.
- `plan`: contrato de `run`, con hasta 100 requests conocidas. Todas tienen `credentialEnv: null`: las credenciales de sesión vienen del navegador. Los datos de login se ingresan con acciones y bodies del entorno. Fuera de `sessionOrigin` solo se admiten GET y no se reenvían credenciales.
- `actions`: de 1 a 30, empezando por navigate. Formas: `{ "kind": "navigate", "stepId": "home" }`, `{ "kind": "fill", "selector": "#username", "valueEnv": "BBA_INPUT_USER" }`, `{ "kind": "click", "selector": "#submit" }` y `{ "kind": "wait", "selector": "#dashboard" }`.
- `maxRedirects`: de 0 a 5. Cada destino debe coincidir con una request declarada; el método y body del salto también deben coincidir cuando Chromium lo solicita.
- `observe`: hasta 20 entradas `{ "name": "identity", "selector": "#identity", "attribute": null }`. Con null se toma textContent; también se puede elegir un atributo. Se conserva presencia/digest y si se truncó a 4096 caracteres.

Las requests se comparan con URL completa, método y bytes del body antes de enviarse. Por ejemplo, un formulario conocido puede usar un paso POST con `body: { "format": "form", "valueEnv": "BBA_BODY_LOGIN" }` y acciones fill con `BBA_INPUT_USER` / `BBA_INPUT_PASSWORD`. El body esperado debe representar exactamente la serialización del formulario, incluyendo orden, encoding y campos ocultos. Inputs faltantes, bodies distintos o dinámicos sin binding quedan bloqueados. POST/PUT/PATCH/DELETE necesitan reglas explícitas del scope, recursos propios y cleanup cuando cambian estado.

## Aislamiento y fidelidad

Se usa CDP Fetch para interceptar también cada salto de redirect: las rutas de Playwright solo cubren la primera URL de una cadena. No se desactiva la política de red del navegador ni se permite que siga destinos directamente. El proxy sumidero y la política WebRTC siguen activos; service workers y WebSockets están bloqueados, y no se aceptan descargas.

El relay devuelve Set-Cookie y los headers de CSP/CORS seleccionados al navegador. Solo reenvía las cookies o Bearer que el navegador produjo para `sessionOrigin`; no carga cookies del perfil personal, no persiste la sesión y no transfiere sus headers a otro origen. No se infieren logins, formularios, tokens dinámicos o dominios de SSO. Nuevas ventanas y proveedores externos necesitan otra definición explícita; no amplían alcance.

Los parámetros de query, cuerpos esperados y valores de fill se leen del entorno. No deben ponerse credenciales en selectores, IDs, URLs base o referencias. Los pasos pueden proyectar hechos JSON de las respuestas, igual que `run`. El escenario no crea checkpoints reanudables de la sesión: una caída conserva reservas y presupuesto, pero la sesión se pierde.

## Artefactos

`scope.json` y `config.json` conservan referencias, sin valores. `requests.jsonl` sincroniza cada reserva antes del envío y guarda metadatos/facts, acciones completadas y errores de red con códigos sanitizados. `scenario.json` contiene resultado, conteos, hechos DOM y checksum. `artifact.json` sella journal, resultado y fuentes para vistas paginadas con `artifact-view`. No se guardan cuerpos, passwords, cookies ni tokens.

Una acción completada o un cambio de DOM describe el flujo observado, no su seguridad. Para informar un bug hace falta establecer la regla esperada, controles, identidad/estado e impacto con las evidencias pertinentes. Las pruebas locales verifican login por formulario, redirect, dos cookies, rotación posterior, lectura autenticada, redacción y rechazo de requests no declaradas.
