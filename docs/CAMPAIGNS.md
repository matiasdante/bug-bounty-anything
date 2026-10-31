# Expediente de campaña (1.9.0)

**Español** · [English](CAMPAIGNS.en.md)

El expediente coordina una investigación de un solo objetivo. Conserva la fuente
de alcance, la revisión de política, la superficie, el perfil de cuentas propias,
la ejecución y el borrador. Cada enlace queda en un journal con digest encadenado.
`campaign_status` vuelve a validar los archivos y muestra el presupuesto y el
siguiente paso. Esta verificación detecta cambios accidentales o inconsistencias;
no autentica al dueño de la política ni convierte una observación en un hallazgo.

## Inicio y autorización

1. `campaign_open` / `campaign-open --target <url> --out <carpeta-nueva>` crea el
   expediente sin requests. El objetivo debe ser una URL canónica.
2. Escribí dentro del expediente un `scope.json` con `budgetId` estable, ventana
   vigente, activos/rutas y métodos precisos, límites y referencia de autorización.
   `campaign_link` / `campaign-link --kind scope` valida que el objetivo esté
   cubierto y deja el alcance inmutable para el caso.
3. Consultá la política oficial vigente o autorización escrita del dueño.
   Guardá una copia de texto como `policy-source.txt` dentro del expediente.
   `campaign-policy-review` / `campaign_policy_review` genera un `policy.json`
   que liga el SHA-256 de esos bytes al scope y a la decisión explícita del
   operador. Revisá el archivo y enlazalo con `campaign-link --kind policy`.
   La forma histórica sin copia local también se acepta; por ejemplo:

```json
{
  "schemaVersion": 1,
  "sourceUrl": "https://program.example/policy",
  "reviewedAt": "2026-10-30T12:00:00.000Z",
  "scopeDigest": "<sha256 canónico del scope>",
  "authorizationReference": "<igual a scope.authorization.reference>",
  "sourceKind": "official-program-policy",
  "operatorDecision": "authorized"
}
```

Usá `uncertain` cuando no se pueda establecer el permiso. El registro documenta
la decisión humana: la herramienta no descarga ni valida la política. En particular,
la URL de una política, un `security.txt` o el interés del usuario no habilitan
pruebas activas por sí solos. `campaign_link --kind policy` la fija al scope.
`campaign_status` indica `policySourceBound` y detecta si cambia la copia local.
El digest acredita integridad de esa copia, no autenticidad de su origen ni
permiso del dueño; conservá también el enlace y fecha de consulta.

## Recorrido MCP y CLI

Con el MCP en modo `--allow-network`, `campaign_capture` captura **una vez** la
URL exacta del objetivo mediante GET acotados. Guarda `pages.json`, `capture.json`
y `surface.json` en `actions/capture/output`, y enlaza los hechos de página y la
superficie observada cuando tiene entradas. Si el DOM menciona otras rutas, quedan
como indicios: no se visitan automáticamente ni cambian el scope. En CLI:
`bba campaign-capture <expediente>`.

También se puede importar una superficie OpenAPI, Swagger, HAR o REA y vincular
su bundle JSON con `campaign_link --kind surface`. El perfil de investigación,
escrito con dos identidades controladas y reglas de negocio explícitas, se
enlaza con `--kind profile`. `campaign_status` informa cuántos checks semánticos
se compilaron y qué clases o entradas quedaron sin regla. Un perfil nuevo puede
seguir a una superficie nueva; el antiguo permanece en el historial.

`campaign_execute` / `bba campaign-execute <expediente>` ejecuta **una vez por
perfil actual** los controles anónimo, propietario y otra cuenta, usando el
presupuesto compartido del scope. Se detiene al primer proof semántico confirmado
por el evaluador. Guarda el run y `report.md` en
`actions/investigation-<secuencia>/output` y enlaza ambos si el run terminó o se
detuvo con `proof-complete`. Las credenciales se leen de `BBA_TOKEN_*` o
`BBA_COOKIE_*` en el entorno del MCP; nunca se aceptan como argumentos ni se
guardan en el expediente. El reporte es un borrador que requiere revisión de
impacto, reproducción y reglas de divulgación antes de presentarlo.

## Detenciones y reanudación

El directorio de acción se reserva antes de iniciar requests. Si la captura o
investigación se interrumpe, `campaign_status` muestra `interrupted-action` y
no vuelve a lanzar la misma acción. Inspeccioná `started.json`, el output y
`inspect_budget` antes de decidir cómo continuar. Las reservas inciertas y una
ventana vencida bloquean nuevas acciones. Para una investigación con sesión
pausada, `campaign_resume` / `bba campaign-resume <expediente>` verifica que el
scope, la superficie y el perfil aún coinciden con el checkpoint. Reanuda solo
los pasos no iniciados, escribe `report-resumed.md` y enlaza el run y el reporte
si termina. Un run ya terminal con reporte guardado se enlaza sin más requests.
La captura de navegador no se reanuda automáticamente.

El borrador semántico responde por separado qué es, cómo se encontró, qué prueba
existe, cómo reproducirla y cómo corregirla. La sección de demostración conserva
el estado exacto de cada check y sus IDs de evidencia; no convierte un resultado
`unresolved` en un impacto declarado.

El journal registra a lo sumo 100 eventos, con rutas reales dentro de la carpeta
del expediente. Los checks automáticos cubren actualmente BOLA, BFLA, exposición
de propiedades y separación de tenants en GET JSON con identidades y reglas
declaradas. Otros vectores requieren sus herramientas específicas o quedan como
brechas de cobertura. El expediente no afirma haber encontrado una vulnerabilidad
crítica ni haber revisado todas las superficies.
