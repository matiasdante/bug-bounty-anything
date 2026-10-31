# Reportes y divulgación responsable

**Español** · [English](reporting.md)

Armá el borrador desde el registro de hallazgos mantenido durante las pruebas, sin reconstruir pasos de memoria. Prepará evidencia primero. Enviá un reporte o contactá a alguien solo con autorización explícita del usuario para esa acción; el permiso de pruebas no autoriza por sí solo el envío. Registrá ID y estado de envío únicamente después de que el portal o canal confirme recepción.

## Estructura del reporte

1. **Título:** clase de falla y endpoint o función exacta, por ejemplo «IDOR en `GET /api/orders/{id}` permite leer pedidos ajenos».
2. **Resumen e impacto:** quién puede hacer qué y contra quién; distinguí el peor caso realista de consecuencias especulativas.
3. **Severidad:** seguí la rúbrica vigente del programa. Si usás CVSS, indicá versión, vector completo, puntaje y motivo; separá impacto probado del condicionado.
4. **Activos:** URL, parámetro, endpoint y versión exactos, vinculados a política o autorización escrita confirmada.
5. **Reproducción:** pasos numerados con requests literales (método, URL, headers, body) o acciones UI, desde un estado que triage pueda crear, como dos cuentas de prueba.
6. **Prueba mínima:** request/response redactados, grabación breve o `curl`. Ocultá datos de otros usuarios, tokens de sesión y claves. Si la estructura de un token importa, mostrá estructura, nunca uno vigente. Si aparece un secreto, informá su existencia y ubicación sin su valor.
7. **Corrección sugerida:** control concreto para esa causa, no una frase genérica.
8. **CWE/CVE:** solo cuando corresponda a la clase o un aviso conocido ya confirmado.

## Canales

En HackerOne, Bugcrowd, Intigriti o YesWeHack, completá cada campo del formulario; no pegues todo en «resumen». Para un VDP propio, seguí el canal indicado en `/security` o `/.well-known/security.txt`, incluidas instrucciones de cifrado. Un VDP sin recompensa sigue siendo un canal válido; no justifica divulgar en otro lugar.

## Tiempos y privacidad

Presentá primero por el canal del programa. No publiques detalles antes de que su política lo permita. Si establece un plazo, no supongas que el silencio lo cumple; cualquier seguimiento o escalamiento debe decidirlo el usuario. Mantené privado el registro y la PoC; compartilos solo con el programa y, si corresponde y se solicita, mediación de la plataforma.

## Antes de enviar

- Volvé a comprobar que el activo exacto sigue en scope y que la autorización está vigente.
- Buscá reportes divulgados de la misma clase y endpoint para detectar duplicados.
- Verificá que la PoC pruebe el impacto afirmado.
- Asegurate de que alguien sin contexto previo pueda reproducirlo con el reporte.
