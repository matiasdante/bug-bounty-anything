# Vulnerabilidades conocidas y diferencias entre versiones

**Español** · [English](known-vulns-and-deltas.md)

Antes de inventar un ataque nuevo, revisá si un componente identificado tiene un aviso público y si el programa acepta reportes de dependencias desactualizadas. Primero obtené un indicio concreto; buscar algo que solo «parece» un framework produce falsos positivos.

## Identificar el componente

- Headers HTTP `Server`, `X-Powered-By`, nombres de cookies (`JSESSIONID`, `laravel_session`, `_wordpress_session`) y headers de CDN/cache.
- Páginas de error que nombren framework o versión.
- Assets con versiones explícitas en source maps, comentarios o parámetros. `app.3f2a91.js` identifica un build, no una versión de producto; atribuile `?v=6.4.2` al componente correcto.
- Rutas públicas como `/CHANGELOG`, `/README`, `/release-notes`, `/version`, `/.well-known/` y rutas CMS (`/wp-json`, `/wp-content`, Drupal, Joomla).
- Manifiestos expuestos como `package.json`, `composer.lock`, `requirements.txt`, `go.sum`; evaluá datos protegidos e impacto antes de afirmar divulgación.
- Firmas de frameworks cliente o banners de build en JS.

## Relacionar el indicio con un aviso

Buscá producto y versión exactos en avisos del fabricante, NVD, GitHub Security Advisories y CHANGELOG del proyecto. Leé rangos afectados, prerrequisitos, configuración y versiones corregidas; anotá URL y fecha. Considerá backports, funciones deshabilitadas y código alcanzable. Un diff de corrección apoya la hipótesis, pero puede cubrir solo una rama o parte de la falla. En código abierto, compará la versión identificada con la que corrige el CVE: el cambio concreto ayuda a diseñar una prueba mínima y no destructiva de la conducta anterior.

## Confirmar sin confiar en el banner

Un header o changelog puede estar desactualizado, alterado o equivocado. Antes de informar «vulnerable por versión X», ejecutá solo la sonda específica, mínima y permitida que comprueba la ruta sin parche. Sin esa prueba, registrá una hipótesis, no un hallazgo confirmado; explicá que el fingerprint sugiere versión y aviso, pero la acción de confirmación quedó fuera del alcance o pendiente.

## Comparar versiones del propio target

Si dos versiones están disponibles y en scope, el diff puede revelar una corrección silenciosa, una regresión o un endpoint/feature flag exclusivo. Antes de reportar una falla activa, confirmá que la conducta anterior sigue alcanzable en el target permitido. Para comparar binarios o bundles cliente, usá `reverse-engineer-anything` y traé a BBA solo las implicancias servidor/API, con su evidencia.
