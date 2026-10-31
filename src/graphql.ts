export type RawGraphqlOperation = {
  rootKind: 'query' | 'mutation';
  fieldName: string;
  argNames: string[];
  locator: string;
};

const gqlIdent = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

function parseIntrospectionObject(doc: Record<string, unknown>): RawGraphqlOperation[] {
  const container = (doc.data && typeof doc.data === 'object' && !Array.isArray(doc.data))
    ? (doc.data as Record<string, unknown>)
    : doc;
  const schema = container.__schema;
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new Error('Expected GraphQL __schema introspection object');
  }
  const s = schema as Record<string, unknown>;
  const queryName = (s.queryType && typeof s.queryType === 'object' && !Array.isArray(s.queryType))
    ? (s.queryType as Record<string, unknown>).name
    : 'Query';
  const mutationName = (s.mutationType && typeof s.mutationType === 'object' && !Array.isArray(s.mutationType))
    ? (s.mutationType as Record<string, unknown>).name
    : null;
  if (!Array.isArray(s.types) || s.types.length > 2000) throw new Error('Invalid GraphQL __schema.types collection');

  const ops: RawGraphqlOperation[] = [];
  for (const [tIdx, rawType] of s.types.entries()) {
    if (!rawType || typeof rawType !== 'object' || Array.isArray(rawType)) continue;
    const t = rawType as Record<string, unknown>;
    const rootKind = t.name === queryName ? 'query' : (mutationName && t.name === mutationName ? 'mutation' : null);
    if (!rootKind || !Array.isArray(t.fields)) continue;
    if (t.fields.length > 1000) throw new Error('GraphQL root type exceeds field limit');
    for (const [fIdx, rawField] of t.fields.entries()) {
      if (!rawField || typeof rawField !== 'object' || Array.isArray(rawField)) throw new Error('Invalid GraphQL field');
      const f = rawField as Record<string, unknown>;
      if (typeof f.name !== 'string' || !gqlIdent.test(f.name) || f.name.startsWith('__')) continue;
      const rawArgs = Array.isArray(f.args) ? f.args : [];
      if (rawArgs.length > 64) throw new Error('GraphQL field argument limit exceeded');
      const argNames: string[] = [];
      for (const a of rawArgs) {
        if (!a || typeof a !== 'object' || Array.isArray(a)) throw new Error('Invalid GraphQL argument');
        const argName = (a as Record<string, unknown>).name;
        if (typeof argName !== 'string' || !gqlIdent.test(argName)) throw new Error('Invalid GraphQL argument name');
        argNames.push(argName);
      }
      ops.push({
        rootKind,
        fieldName: f.name,
        argNames,
        locator: `/__schema/types/${tIdx}/fields/${fIdx}`,
      });
    }
  }
  return ops;
}

function stripGraphqlComments(sdl: string): string {
  // Conserva bloques """...""" fuera del análisis línea por línea y elimina comentarios #
  return sdl
    .replace(/"""[\s\S]*?"""/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/#[^\r\n]*/g, '');
}

function parseSdlText(sdl: string): RawGraphqlOperation[] {
  if (sdl.length > 1024 * 1024) throw new Error('GraphQL SDL exceeds 1 MiB');
  const cleaned = stripGraphqlComments(sdl);
  const ops: RawGraphqlOperation[] = [];
  const blockRegex = /\b(?:extend\s+)?type\s+(Query|Mutation)\b[^{]*\{([^}]*)\}/g;
  let blockMatch: RegExpExecArray | null;
  while ((blockMatch = blockRegex.exec(cleaned)) !== null) {
    const rootKind = blockMatch[1] === 'Query' ? 'query' : 'mutation';
    const body = blockMatch[2];
    let depth = 0;
    let current = '';
    const entries: string[] = [];
    for (let i = 0; i < body.length; i++) {
      const ch = body[i];
      if (ch === '(') { depth++; current += ch; }
      else if (ch === ')') { depth = Math.max(0, depth - 1); current += ch; }
      else if ((ch === '\n' || ch === '\r') && depth === 0) {
        if (current.trim()) entries.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    if (current.trim()) entries.push(current.trim());
    for (const line of entries) {
      const m = /^([A-Za-z_][A-Za-z0-9_]{0,63})\s*(?:\(([^)]*)\))?\s*:/.exec(line);
      if (!m) continue;
      const fieldName = m[1];
      if (fieldName.startsWith('__')) continue;
      const argNames: string[] = [];
      if (m[2]) {
        for (const piece of m[2].split(',')) {
          const argMatch = /^\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*:/.exec(piece);
          if (argMatch) argNames.push(argMatch[1]);
        }
      }
      ops.push({
        rootKind,
        fieldName,
        argNames,
        locator: `sdl:${blockMatch[1]}.${fieldName}`,
      });
      if (ops.length > 5000) throw new Error('GraphQL operation limit exceeded');
    }
  }
  if (!ops.length) throw new Error('No Query or Mutation fields found in GraphQL SDL');
  return ops;
}

export function extractGraphqlSurfaceInput(input: unknown): {
  origin: string | null;
  endpointPath: string;
  operations: RawGraphqlOperation[];
} {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      let parsed: unknown;
      try { parsed = JSON.parse(trimmed); } catch { throw new Error('Invalid GraphQL JSON'); }
      return extractGraphqlSurfaceInput(parsed);
    }
    return { origin: null, endpointPath: '/graphql', operations: parseSdlText(input) };
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Invalid GraphQL surface input');
  }
  const obj = input as Record<string, unknown>;
  const origin = typeof obj.origin === 'string' ? obj.origin : null;
  const endpointPath = typeof obj.endpointPath === 'string' ? obj.endpointPath : '/graphql';
  if (typeof obj.sdl === 'string') {
    return { origin, endpointPath, operations: parseSdlText(obj.sdl) };
  }
  return { origin, endpointPath, operations: parseIntrospectionObject(obj) };
}

