# Alcance y autorización

**Español** · [English](scope-and-authorization.md)

Este control precede a toda prueba activa, incluidas sondas de lectura e introspección. Leer páginas públicas de política/contacto sirve para establecer permiso; que una request parezca navegación normal no lo acredita.

## 1. Identificar programa y política vigente

Buscá el programa oficial en HackerOne, Bugcrowd, YesWeHack, Intigriti o en `/security`, `/.well-known/security.txt` y `/vulnerability-disclosure` del proveedor. `security.txt` (RFC 9116) ayuda a encontrar el contacto, pero su presencia no autoriza pruebas: seguí la política enlazada ([RFC 9116 §5.5](https://www.rfc-editor.org/rfc/rfc9116.html#section-5.5)). También vale una autorización escrita del dueño que precise persona, activos, técnicas, ventana y canal de reporte. Leé la política **ahora**, no una memoria o script: scope, exclusiones y estado del programa cambian.

## 2. Confirmar el activo exacto

Compará dominio/subdominio literal, ID de app móvil, URL base de API o rango IP con la autorización. Un subdominio hermano o parecido no entra automáticamente. Revisá exclusiones con la misma fuerza que inclusiones: staging, demos, SaaS de terceros, productos adquiridos u otros activos marcados fuera de alcance. Si no hay política vigente ni permiso escrito que cubra el target, detené pruebas activas en ese activo y explicá qué falta; no infieras autorización por una relación corporativa.

## 3. Confirmar técnicas y clases permitidas

Cada programa puede restringir scanners sin rate limit, volumen que degrade el servicio, ingeniería social, phishing, acceso físico, datos de usuarios reales, spam, creación masiva de cuentas, ataques a proveedores externos o reportes basados solo en salida de scanner. Leé sus reglas específicas; ante silencio, elegí la interpretación más conservadora.

### Límites operativos de este flujo

- Excluí DoS/carga, ingeniería social y evasión de CAPTCHA/bot detection. Usá acceso de prueba documentado o frená.
- Usá cuentas y datos sintéticos propios creados por el flujo permitido o provistos por el programa; una cuenta de prueba no habilita datos reales ajenos.
- Para lógica financiera, usá sandbox y fondos de prueba; no hagas pedidos, transferencias ni pagos reales.
- Scope no se expande por redirects, CNAME, callbacks o descubrimiento backend. Verificá cada destino y no pases cookies, auth o marcadores a hosts ajenos.
- Para callbacks, usá un endpoint autorizado que controles y marcadores opacos; no envíes datos o secretos del target a servicios públicos.
- Frená ante datos personales inesperados, degradación, 429 o efectos fuera de recursos de prueba. Conservá evidencia mínima redactada y evitá reintentos que empeoren el efecto.

## 4. Anotar restricciones operativas

Registrá límite de tasa y volumen, flujo de cuentas, sandbox/datos de prueba, y marcadores de investigador requeridos (header, `User-Agent` o campo indicado). Aplicá el marcador a cada request activa una vez conocido. Anotá condiciones de safe harbor tal como están escritas, sin presentarlas como garantía legal universal. Falta de límite explícito no significa permiso ilimitado: mantené sondas mínimas y resolvé dudas materiales antes de ejecutarlas.

## 5. Si falta una confirmación

Si el activo cae entre inclusión y exclusión, o la técnica carece de política/autorización escrita, detené pruebas activas allí. Podés continuar solo investigación pasiva de información ya pública y decir qué falta. No hagas una determinación legal sobre usuario o target. Una empresa con varios dominios/apps puede tener programas y scopes distintos; repetí esta revisión por activo.

## Volver a verificar

Releé vigencia de política o permiso escrito al iniciar una nueva sesión sobre el target y al encontrar activos/subdominios inesperados durante recon.
