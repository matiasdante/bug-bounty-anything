export type RawJsRoute = {
  method: string;
  origin: string | null;
  path: string;
  queryNames: string[];
  locator: string;
};

const MAX_JS_BYTES = 2 * 1024 * 1024;
const knownApiPrefix = /^\/(?:api|v[1-9]\d*|graphql|oauth|auth|admin|internal|users|accounts|orders|items|projects|orgs|tenants)(?:\/|$)/;
const validParam = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

function inferMethodFromContext(before: string, after: string, path: string): string {
  const axiosMatch = /\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*$/i.exec(before);
  if (axiosMatch) return axiosMatch[1].toUpperCase();
  const methodProp = /\bmethod\s*:\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]/i.exec(after);
  if (methodProp) return methodProp[1].toUpperCase();
  if (path === '/graphql' || path.startsWith('/graphql/')) return 'POST';
  return 'GET';
}

function normalizeCandidateString(raw: string, contextBefore: string, contextAfter: string, locator: string): RawJsRoute | null {
  if (!raw || raw.length > 2048 || /[\x00-\x20\\]/.test(raw)) return null;
  // Reemplaza interpolaciones ${...} por {param} antes de parsear rutas.
  const templated = raw.replace(/\$\{[^}]{1,120}\}/g, '{param}');
  let origin: string | null = null;
  let pathAndQuery = templated;

  if (/^https?:\/\//i.test(templated)) {
    const withoutPlaceholders = templated.replace(/\{param\}/g, 'param');
    let parsed: URL;
    try { parsed = new URL(withoutPlaceholders); } catch { return null; }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    origin = parsed.origin;
    const afterHost = templated.replace(/^https?:\/\/[^/?#]+/i, '');
    pathAndQuery = afterHost || '/';
  } else if (!templated.startsWith('/') || templated.startsWith('//') || !knownApiPrefix.test(templated)) {
    return null;
  }

  const [rawPath, rawQuery = ''] = pathAndQuery.split('#')[0].split('?');
  if (!rawPath.startsWith('/') || rawPath.includes('//')) return null;
  // Descarta rutas de assets estáticos comunes.
  if (/\.(?:js|mjs|cjs|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)$/i.test(rawPath)) return null;

  const queryNames: string[] = [];
  if (rawQuery) {
    for (const part of rawQuery.split('&')) {
      if (!part) continue;
      const key = part.split('=')[0];
      if (key && key !== '{param}' && validParam.test(key)) queryNames.push(key);
    }
  }
  const method = inferMethodFromContext(contextBefore, contextAfter, rawPath);
  return { method, origin, path: rawPath, queryNames, locator };
}

function scanJsSource(source: string, sourceLabel: string, defaultOrigin: string | null): RawJsRoute[] {
  const routes: RawJsRoute[] = [];
  const len = source.length;
  let i = 0;
  while (i < len) {
    const ch = source[i];
    // Comentarios de línea y bloque
    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < len && source[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < len && !(source[i] === '*' && source[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (ch === '\'' || ch === '"' || ch === '`') {
      const quote = ch;
      const start = i;
      i++;
      let content = '';
      let depth = 0;
      while (i < len) {
        const cur = source[i];
        if (cur === '\\') {
          content += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        if (quote === '`' && cur === '$' && source[i + 1] === '{') {
          depth++;
          content += '${';
          i += 2;
          while (i < len && depth > 0) {
            if (source[i] === '{') depth++;
            else if (source[i] === '}') depth--;
            content += source[i];
            i++;
          }
          continue;
        }
        if (cur === quote && depth === 0) {
          i++;
          break;
        }
        if ((quote === '\'' || quote === '"') && (cur === '\n' || cur === '\r')) break;
        if (content.length <= 2048) content += cur;
        i++;
      }
      const before = source.slice(Math.max(0, start - 64), start);
      const after = source.slice(i, Math.min(len, i + 120));
      const candidate = normalizeCandidateString(content, before, after, `${sourceLabel}@${start}`);
      if (candidate) {
        if (candidate.origin === null && defaultOrigin !== null) candidate.origin = defaultOrigin;
        routes.push(candidate);
        if (routes.length > 5000) throw new Error('JS bundle route limit exceeded');
      }
      continue;
    }
    i++;
  }
  return routes;
}

export function extractJsBundleRoutes(input: unknown): RawJsRoute[] {
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_JS_BYTES) throw new Error('JS bundle exceeds 2 MiB');
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        return extractJsBundleRoutes(parsed);
      } catch {
        // Si no es JSON válido (p. ej. bloque JS que empieza con `{`), escanear como código JS.
      }
    }
    return scanJsSource(input, 'bundle', null);
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Invalid JS bundle surface input');
  }
  const obj = input as Record<string, unknown>;
  const defaultOrigin = typeof obj.origin === 'string' ? obj.origin : null;
  if (typeof obj.code === 'string') {
    if (Buffer.byteLength(obj.code, 'utf8') > MAX_JS_BYTES) throw new Error('JS bundle exceeds 2 MiB');
    return scanJsSource(obj.code, 'code', defaultOrigin);
  }
  if ( obj.version === 3 && Array.isArray(obj.sourcesContent) ) {
    if (obj.sourcesContent.length > 1000) throw new Error('SourceMap sourcesContent count exceeds limit');
    let totalBytes = 0;
    const all: RawJsRoute[] = [];
    for (let idx = 0; idx < obj.sourcesContent.length; idx++) {
      const content = obj.sourcesContent[idx];
      if (typeof content !== 'string') continue;
      totalBytes += Buffer.byteLength(content, 'utf8');
      if (totalBytes > MAX_JS_BYTES) throw new Error('SourceMap sourcesContent exceeds 2 MiB');
      const srcName = Array.isArray(obj.sources) && typeof obj.sources[idx] === 'string' ? obj.sources[idx] : `source[${idx}]`;
      all.push(...scanJsSource(content, `sourcemap:${srcName}`, defaultOrigin));
      if (all.length > 5000) throw new Error('JS bundle route limit exceeded');
    }
    return all;
  }
  throw new Error('Expected JS source text, { code, origin? } or SourceMap v3 with sourcesContent');
}

