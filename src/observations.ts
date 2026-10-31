import { digest } from './contracts.ts';

export type Projection = { name: string; pointer: string };
export type Fact = { name: string; present: boolean; kind: 'unavailable' | 'missing' | 'null' | 'string' | 'number' | 'boolean' | 'object' | 'array'; sha256: string | null; meaningful: boolean };

export function validateProjections(value: unknown): asserts value is Projection[] {
  if (!Array.isArray(value) || !value.length || value.length > 20) throw new Error('Invalid projections');
  const names = new Set<string>();
  for (const p of value) {
    if (!p || typeof p !== 'object' || Object.keys(p).sort().join() !== 'name,pointer'
      || typeof p.name !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(p.name) || names.has(p.name)
      || typeof p.pointer !== 'string' || p.pointer.length > 512 || !/^(\/(?:[^~]|~[01])*)?$/.test(p.pointer)) throw new Error('Invalid projection');
    names.add(p.name);
  }
}

// RFC 6901 traversal uses own properties only; no target values are retained.
export function projectJson(body: Buffer, contentType: string, projections: Projection[]): Fact[] {
  validateProjections(projections);
  const absent = (name: string, kind: 'unavailable' | 'missing'): Fact => ({ name, present: false, kind, sha256: null, meaningful: false });
  let parsed: unknown;
  try {
    if (!/^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType)) throw new Error();
    parsed = JSON.parse(body.toString('utf8'));
  } catch { return projections.map(p => absent(p.name, 'unavailable')); }
  return projections.map(p => {
    let current: any = parsed;
    for (const segment of p.pointer === '' ? [] : p.pointer.slice(1).split('/').map(s => s.replaceAll('~1', '/').replaceAll('~0', '~'))) {
      if (!current || typeof current !== 'object') return absent(p.name, 'missing');
      if (Array.isArray(current)) {
        if (!/^(?:0|[1-9]\d*)$/.test(segment)) return absent(p.name, 'missing');
        const index = Number(segment);
        if (!Number.isSafeInteger(index) || index >= current.length) return absent(p.name, 'missing');
        current = current[index];
      } else {
        if (!Object.hasOwn(current, segment)) return absent(p.name, 'missing');
        current = current[segment];
      }
    }
    const kind = current === null ? 'null' : Array.isArray(current) ? 'array' : typeof current;
    const meaningful = kind === 'string' ? current.length > 0 : kind === 'object' || kind === 'array' ? Object.keys(current).length > 0 : kind === 'number' || kind === 'boolean';
    try { return { name: p.name, present: true, kind: kind as Fact['kind'], meaningful, sha256: digest(current) }; }
    catch { return absent(p.name, 'unavailable'); }
  });
}

export function validateFacts(value: unknown, projections: Projection[]): asserts value is Fact[] {
  if (!Array.isArray(value) || value.length !== projections.length) throw new Error('Invalid response facts');
  for (const [i, f] of value.entries()) {
    if (!f || typeof f !== 'object' || Object.keys(f).sort().join() !== 'kind,meaningful,name,present,sha256'
      || f.name !== projections[i].name || typeof f.present !== 'boolean' || typeof f.meaningful !== 'boolean'
      || !['unavailable', 'missing', 'null', 'string', 'number', 'boolean', 'object', 'array'].includes(f.kind)
      || f.present !== !['unavailable', 'missing'].includes(f.kind)
      || (f.present ? typeof f.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(f.sha256) : f.sha256 !== null || f.meaningful)
      || (f.kind === 'null' && f.meaningful)) throw new Error('Invalid response fact');
  }
}
