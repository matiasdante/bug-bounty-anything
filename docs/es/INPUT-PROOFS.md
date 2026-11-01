# Pruebas acotadas de entrada (1.9.0)

[English](../INPUT-PROOFS.md) · **Español** · [Português (Brasil)](../pt-BR/INPUT-PROOFS.md) · [简体中文](../zh/INPUT-PROOFS.md)

Estas dos herramientas reutilizan el scope exacto, `requestRules`, el presupuesto
compartido y los checkpoints SQLite. Sus entradas se generan o ligan al config;
las credenciales salen del entorno. Una ejecución incompleta conserva las
reservas y solo puede retomar pasos no iniciados con el mismo scope/config.

## Expresión de plantilla

`template-check` / `template_check` recibe un config JSON con
`schemaVersion: 1`, `class: "template-arithmetic"`, `policyReference`, `url`,
`parameter`, `pointer`, `operands: [a,b,c]` y `credentialEnv` (`null` o una
referencia `BBA_TOKEN_*` / `BBA_COOKIE_*`). Los operandos son enteros distintos
entre 2 y 997. El scope debe autorizar el GET exacto y ese nombre de query.

El motor envía `a*b` literal, `{{a*b}}` y `{{b*c}}` al mismo recurso, proyecta
un campo JSON y guarda solo sus digests. Confirma **evaluación de esa sintaxis**
si el control permanece literal y ambas expresiones dan sus productos. Si ambas
permanecen literales, marca `not-reproduced`; otros resultados quedan
`unresolved`. El operador debe establecer que el campo debía tratar la entrada
como texto literal. No se prueban SQL, NoSQL, comandos, archivos ni datos ajenos.
`resume-template-check` / `resume_template_check` usa el mismo config y scope.

## Callback de URL

`ssrf-callback-check` / `ssrf_callback_check` recibe `schemaVersion: 1`,
`class: "outbound-fetch"`, `policyReference`, `triggerUrl`, `queryName`,
`credentialEnv`, `callbackUrl`, `receiptUrl` y `receiptPointer`. El trigger,
callback y recibo deben ser rutas exactas declaradas en el scope. El callback
debe estar en un origen propio distinto del trigger y terminar en un token opaco
de al menos 12 caracteres. El receptor propio devuelve un JSON booleano en
`receiptPointer` que pasa de `false` a `true` únicamente al recibir ese callback.

El motor consulta el recibo antes, envía el callback como valor de query al
trigger y consulta el recibo hasta dos veces. Un cambio `false` → `true` con
trigger 200 demuestra una salida hacia **ese receptor propio**, siempre que el
receptor esté bien configurado y la política declarada prohíba ese destino.
No prueba acceso a redes internas, metadatos ni divulgación de respuesta. No
se generan URLs internas, no se siguen redirects y no hay barrido de destinos.
`resume-ssrf-callback` / `resume_ssrf_callback` conserva los mismos límites.

El callback que hace el servicio al receptor es un request adicional externo
al contador del cliente BBA; el operador conserva el log de su receptor y debe
considerarlo en el presupuesto del programa. Ambos reportes responden qué es,
cómo se encontró, prueba, reproducción y corrección sin extrapolar severidad.
