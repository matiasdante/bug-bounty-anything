# Formulario de otro origen y estado propio (1.9.0)

[English](../CSRF-CHECK.md) · **Español** · [Português (Brasil)](../pt-BR/CSRF-CHECK.md) · [简体中文](../zh/CSRF-CHECK.md)

`csrf-check` / `csrf_check` usa Chromium para enviar **un** formulario POST
desde un origen atacante declarado hacia una acción de una cuenta propia.
El config lleva `schemaVersion: 1`, `class: "cross-origin-form"`,
`policyReference`, `attackerPageUrl`, `stateUrl`, `actionUrl`, `cookieEnv`,
`sameSite`, `formField`, `formValue`, `statePointer`, `beforeValue` y
`afterValue`. El scope debe autorizar ambos orígenes, GET de la página y del
estado, POST form al action exacto y al menos cinco requests. La cookie
`BBA_COOKIE_*` viene del entorno y nunca se persiste.

El motor comprueba el estado inicial y que la acción anónima sea denegada.
Luego navega en un contexto aislado a la página atacante, crea un formulario
simple con el campo declarado, verifica que el navegador envíe la cookie y el
header `Origin` esperado, y compara el estado final. `confirmed` exige la
transición declarada y respuesta exitosa. Si el estado no cambia y el
navegador no envía cookie o el servidor deniega la acción, queda
`not-reproduced`; controles incompletos quedan `unresolved`. Una cookie con
SameSite distinto, un token dinámico o acciones fuera del config no se
infieren ni se fuerzan.

El operador debe crear y restaurar el estado de prueba. Para llamar al
resultado **CSRF**, el origen atacante debe ser realmente de otro sitio y la
acción debe requerir intención autenticada según la política. Dos puertos
`127.0.0.1` del laboratorio son distintos orígenes pero pueden ser del mismo
sitio: ese test solo valida el recorrido de formulario/cookie/estado del
motor. El journal se sella y se consulta con `artifact-view`; una caída
requiere inspección y no reintenta la acción.
