# Roadmap interno — BBA 1.0.0

Actualizado: 2026-10-29. La release actual es **0.8.0**. Este documento conserva el alcance acordado y distingue implementación de planificación; no declara lista la 1.0.0.

Objetivo: investigación reproducible de web/API, con skill, CLI/MCP, motor local, adaptadores, evidencia persistente, evaluación controlada y piloto sobre un programa con bug bounty. Distinguir detección automatizada, investigación asistida e indicios por capacidad. No prometer cobertura universal ni exigir un hallazgo productivo para declarar honesto el resultado.

| Bloque | Estado | Entregable y criterio de salida |
|---|---|---|
| 1. Contratos y laboratorio | Implementado en 0.1.0 | Contratos runtime, laboratorio reiniciable con dos cuentas, variantes vulnerable/corregida, controles independientes, evidencia y reporte. Ambas variantes deben producir sus resultados esperados con HTTP real. |
| 2. Núcleo y ejecución | Implementado en 0.2.0 para planes GET | Scope exacto/exclusiones/vigencia, presupuesto compartido por investigación, checkpoints SQLite, cancelación y recuperación sin repetir intentos inciertos. Pruebas negativas y caída real de proceso. Límites y semántica en [EXECUTION.md](EXECUTION.md). |
| 3. Captura y superficie | Implementado en 0.5.0: importación offline HAR/OpenAPI/REA, captura con navegador (Bearer o Cookie) con aislamiento; captura pública sin probar contra un host real | HAR/OpenAPI, navegación autenticada, inventario con procedencia y REA. Importar no debe contactar URLs; separar observaciones e inferencias. |
| 4. Investigación y confirmación | Implementado en 0.6.0 para BOLA, BFLA y exposición de propiedades en laboratorio propio | Ampliar controles baseline/probe, roles y clases. Cada capacidad declarada debe distinguir sus casos vulnerables, corregidos e inconclusos. |
| 5. Adaptadores | Implementado en 0.7.0 solo por importación (ZAP, Nuclei, Subfinder); BBA no ejecuta scanners ni consulta advisories | ZAP, Nuclei revisado/versionado y Subfinder; advisories y deltas. Normalizar resultados, respetar presupuestos y validar candidatos antes de confirmar. |
| 6. Producto utilizable | Implementado en 0.8.0: CLI, recuperación, exportación, MCP por stdio, `doctor` y paquete instalable | Instalación comprobada desde el tarball; el MCP expone herramientas de red solo con `--allow-network`. |
| 7. RC y piloto productivo | Pendiente | Evaluación congelada, selección de programa, recorrido acotado, revisión de resultados y correcciones. |

## Decisiones de implementación

- TypeScript, núcleo local compartido por CLI y futuro MCP. 0.1.0 usa Node 26 sin dependencias.
- Los bundles JSON del laboratorio se conservan. Las sesiones generales usan SQLite nativo de Node: checkpoints transaccionales y bloqueo de ejecución liberado por el SO ante caída de proceso, con exportación JSON/Markdown.
- Laboratorio propio mínimo ahora; Juice Shop y crAPI para ampliar escenarios. Las variantes corregidas y controles negativos siguen siendo obligatorios.
- REA para artefactos/capturas; Playwright para navegador y sesiones; ZAP como primer adaptador general; Nuclei con templates seleccionados; Subfinder opcional para candidatos pasivos.
- Fijar versiones, licencias, requisitos y efectos al implementar cada adaptador. No instalar herramientas en conjunto sin necesidad concreta.

## Cobertura prevista de 1.0.0

1. Identidad/permisos: BOLA, autorización funcional y por propiedad, tenants, sesiones, recuperación, JWT y OAuth/OIDC.
2. Navegador: XSS, CSRF, CORS y redirecciones, comprobadas en contexto real.
3. Entradas: familias de injection, traversal, uploads, XXE y SSRF, con condiciones de parada por clase.
4. API/negocio: GraphQL, mass assignment, exposición, secuencias y concurrencia controlada.
5. Componentes/exposición: secretos, configuración cloud, candidatos de takeover, advisories y deltas.

Documentar una clase no significa implementarla. Las confirmaciones que requieran una acción fuera de alcance permanecen inconclusas. El análisis de clientes móviles/binarios se delega a REA; el permiso sobre un artefacto no habilita contactar su backend.

## Condiciones de release

- Todos los casos obligatorios del conjunto congelado pasan, incluidos alcance y secretos; las variantes corregidas no generan confirmaciones.
- Medir detecciones, falsos positivos, omisiones, solicitudes, tiempo y repetición al retomar, sin extrapolar métricas del laboratorio a todos los sistemas.
- Reportes reproducibles desde un entorno limpio, instalación y diagnóstico comprobados, cancelación/recuperación/exportación funcionales.
- Ningún adaptador productivo puede escapar a destinos y presupuestos autorizados. Si no es posible controlar sus efectos, limitarlo a laboratorio o importación.
- El piloto conserva alcance, cobertura, limitaciones y evidencia. Encontrar un bug no es requisito para fingir éxito ni motivo para ampliar el scope.

## Selección del piloto — más adelante

Relevar programas con recompensa vigente, scope claro, cuentas de prueba accesibles y reglas compatibles. Elegir un programa y una superficie acotada; registrar presupuesto y condiciones de parada antes de probar. El envío de un reporte requiere autorización explícita del usuario. No hay un target productivo seleccionado.
