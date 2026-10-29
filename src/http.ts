import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { assertAuthorized, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';

export class RequestFailure extends Error {
  code: string;
  constructor(code: string) { super(code); this.code = code; }
}

export function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113));
  }
  // Accept only global-unicast space, conservatively excluding special-use
  // 2001::/23, documentation and deprecated 6to4. Mapped IPv4 is excluded.
  if (isIP(address) === 6) {
    const parts = address.toLowerCase().split(':');
    const first = parseInt(parts[0], 16), second = parseInt(parts[1] || '0', 16);
    return first >= 0x2000 && first <= 0x3fff && first !== 0x2002
      && !(first === 0x2001 && (second <= 0x1ff || second === 0xdb8))
      && !(first === 0x3fff && second <= 0xfff);
  }
  return false;
}

export async function destination(url: URL, scope: Scope, resolver = lookup): Promise<{ address: string; family: number }> {
  if (scope.mode === 'loopback-lab') {
    if (url.hostname !== '127.0.0.1') throw new RequestFailure('address-blocked');
    return { address: '127.0.0.1', family: 4 };
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const family = isIP(host);
  const addresses = family ? [{ address: host, family }] : await resolver(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address))) throw new RequestFailure('address-blocked');
  return addresses[0];
}

export type HttpResult = { status: number; body: Buffer; contentType: string };

export async function scopedRequest(scope: Scope, urlText: string, options: {
  token?: string; signal?: AbortSignal; remainingMs?: number;
} = {}): Promise<HttpResult> {
  validateScope(scope);
  const url = assertAuthorized(scope, urlText);
  if (options.token !== undefined && !/^[A-Za-z0-9._~+/-]{1,4096}={0,2}$/.test(options.token)) throw new RequestFailure('invalid-credential');
  const timeout = Math.min(scope.limits.timeoutMs, options.remainingMs ?? Infinity,
    Date.parse(scope.authorization.validUntil) - Date.now());
  if (timeout <= 0) throw new RequestFailure('deadline');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const aborted = () => new RequestFailure(options.signal?.aborted ? 'cancelled' : 'deadline');
  let rejectAbort: (() => void) | undefined;
  try {
    if (signal.aborted) throw aborted();
    const target = await Promise.race([
      destination(url, scope),
      new Promise<never>((_, reject) => { rejectAbort = () => reject(aborted()); signal.addEventListener('abort', rejectAbort, { once: true }); }),
    ]);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
    if (signal.aborted) throw aborted();
    assertAuthorized(scope, urlText); // Revalidate after DNS resolution.
    return await new Promise<HttpResult>((resolve, reject) => {
      const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
      const req = send(url, {
        method: 'GET', agent: false, signal,
        // Pin the validated resolution; the original hostname still controls
        // TLS certificate verification and SNI. Environment proxies are unused.
        lookup: (_host, _options, callback) => {
          if (_options.all) callback(null, [target]);
          else callback(null, target.address, target.family);
        },
        headers: options.token ? { Authorization: `Bearer ${options.token}` } : {},
      }, res => {
        const status = res.statusCode ?? 0;
        if ((status >= 300 && status < 400) || status === 429 || status >= 500) {
          resolve({ status, body: Buffer.alloc(0), contentType: '' }); res.destroy(); return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > scope.limits.maxResponseBytes) {
            reject(new RequestFailure('response-too-large')); res.destroy(); return;
          }
          chunks.push(chunk);
        });
        res.on('error', () => reject(signal.aborted ? aborted() : new RequestFailure('incomplete-response')));
        res.on('end', () => resolve({ status, body: Buffer.concat(chunks), contentType: res.headers['content-type'] ?? '' }));
      });
      req.on('error', () => reject(signal.aborted ? aborted() : new RequestFailure('network-error')));
      req.end();
    });
  } catch (error) {
    if (error instanceof RequestFailure) throw error;
    throw new RequestFailure('network-error');
  } finally {
    clearTimeout(timer);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
  }
}
