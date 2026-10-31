import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { connect as http2Connect } from 'node:http2';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect, isIP } from 'node:net';
import type { Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { assertAuthorized, validateScope } from './scope.ts';
import type { Scope } from './scope.ts';
import { identifyingHeaders } from './headers.ts';
import { resolveRequest } from './requests.ts';
import type { RequestSpec } from './scope.ts';

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

export async function destinationAddresses(url: URL, scope: Scope, resolver = lookup): Promise<{ address: string; family: number }[]> {
  if (scope.mode === 'loopback-lab') {
    if (url.hostname !== '127.0.0.1') throw new RequestFailure('address-blocked');
    return [{ address: '127.0.0.1', family: 4 }];
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const family = isIP(host);
  const addresses = family ? [{ address: host, family }] : await resolver(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address))) throw new RequestFailure('address-blocked');
  return addresses.map(({ address, family: addrFamily }) => ({ address, family: addrFamily }));
}

export async function destination(url: URL, scope: Scope, resolver = lookup): Promise<{ address: string; family: number }> {
  return (await destinationAddresses(url, scope, resolver))[0];
}

const cookieNamePattern = "[A-Za-z0-9!#$%&'*+.^_`|~:-]{1,128}";
const cookieValuePattern = '(?:[\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]{0,2048}|"[\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]{0,2046}")';
const cookieHeaderRegex = new RegExp(`^${cookieNamePattern}=${cookieValuePattern}(; ${cookieNamePattern}=${cookieValuePattern}){0,29}$`);
const bearerTokenRegex = /^[A-Za-z0-9._~+:|-]{1,4096}={0,2}$/;

// Operator-supplied secrets enter only through BBA_TOKEN_* (Bearer) or BBA_COOKIE_* (Cookie header).
export function credentialFor(envName: string, value: string): { token?: string; cookie?: string } {
  if (envName.startsWith('BBA_COOKIE_')) {
    if (!cookieHeaderRegex.test(value)) throw new Error('Invalid credential format');
    return { cookie: value };
  }
  if (!bearerTokenRegex.test(value)) throw new Error('Invalid credential format');
  return { token: value };
}

export type HttpResult = { status: number; body: Buffer; contentType: string; browserHeaders?: Record<string, string>; setCookies?: string[]; location?: string };
const browserResponseHeaders = ['content-security-policy', 'content-security-policy-report-only', 'x-content-type-options',
  'x-frame-options', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-methods',
  'access-control-allow-headers', 'access-control-expose-headers', 'vary'];

export async function scopedRequest(scope: Scope, urlText: string, options: {
  token?: string; cookie?: string; signal?: AbortSignal; remainingMs?: number; environment?: Record<string, string | undefined>;
  request?: RequestSpec;
  browserOrigin?: string;
  browserCredentials?: boolean;
} = {}): Promise<HttpResult> {
  validateScope(scope);
  const url = assertAuthorized(scope, urlText);
  let resolved: ReturnType<typeof resolveRequest>;
  try { resolved = resolveRequest(scope, urlText, options.request, options.environment); }
  catch { throw new RequestFailure('invalid-request-input'); }
  let headers: Record<string, string>;
  try { headers = identifyingHeaders(scope, url.origin, options.environment); }
  catch { throw new RequestFailure('invalid-identifying-header'); }
  if (options.browserOrigin !== undefined) {
    if (!scope.allowed.some(r => r.origin === options.browserOrigin)) throw new RequestFailure('invalid-request-input');
    headers.Origin = options.browserOrigin;
  }
  if (options.token !== undefined && options.cookie !== undefined && options.browserCredentials !== true) throw new RequestFailure('invalid-credential');
  if (options.token !== undefined && !bearerTokenRegex.test(options.token)) throw new RequestFailure('invalid-credential');
  if (options.cookie !== undefined) try { credentialFor('BBA_COOKIE_X', options.cookie); } catch { throw new RequestFailure('invalid-credential'); }
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
    const targets = await Promise.race([
      destinationAddresses(url, scope),
      new Promise<never>((_, reject) => { rejectAbort = () => reject(aborted()); signal.addEventListener('abort', rejectAbort, { once: true }); }),
    ]);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
    if (signal.aborted) throw aborted();
    assertAuthorized(scope, urlText); // Revalidate after DNS resolution.
    return await new Promise<HttpResult>((resolve, reject) => {
      let settled = false;
      const done = (result: HttpResult) => { if (!settled) { settled = true; resolve(result); } };
      const fail = (error: Error) => { if (!settled) { settled = true; reject(error); } };
      const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
      const requestOptions: import('node:https').RequestOptions & { autoSelectFamily?: boolean } = {
        method: resolved.method,
        agent: false,
        signal,
        autoSelectFamily: targets.length > 1,
        // Pin all validated public resolutions; the original hostname still controls
        // TLS certificate verification and SNI. Environment proxies are unused.
        lookup: (_host, lookupOptions, callback) => {
          if (lookupOptions.all) callback(null, targets);
          else callback(null, targets[0].address, targets[0].family);
        },
        headers: { ...headers, ...(resolved.body ? { 'Content-Type': resolved.contentType!, 'Content-Length': String(resolved.body.length) } : {}), ...(options.cookie ? { Cookie: options.cookie } : {}), ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}) },
      };
      const req = send(resolved.url, requestOptions, res => {
        const status = res.statusCode ?? 0;
        if ((status >= 300 && status < 400) || status === 429 || status >= 500) {
          done({ status, body: Buffer.alloc(0), contentType: '', location: res.headers.location, setCookies: res.headers['set-cookie'] });
          res.destroy();
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > scope.limits.maxResponseBytes) {
            fail(new RequestFailure('response-too-large'));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', () => fail(signal.aborted ? aborted() : new RequestFailure('incomplete-response')));
        res.on('end', () => {
          if (!res.complete) {
            fail(signal.aborted ? aborted() : new RequestFailure('incomplete-response'));
            return;
          }
          done({
            status,
            body: Buffer.concat(chunks),
            contentType: res.headers['content-type'] ?? '',
            setCookies: res.headers['set-cookie'],
            browserHeaders: Object.fromEntries(browserResponseHeaders.flatMap(name => typeof res.headers[name] === 'string' ? [[name, res.headers[name] as string]] : [])),
          });
        });
        res.on('close', () => {
          if (!settled) fail(signal.aborted ? aborted() : new RequestFailure('incomplete-response'));
        });
      });
      req.on('error', () => fail(signal.aborted ? aborted() : new RequestFailure('network-error')));
      req.end(resolved.body);
    });
  } catch (error) {
    if (error instanceof RequestFailure) throw error;
    throw new RequestFailure('network-error');
  } finally {
    clearTimeout(timer);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
  }
}

export type Http2PairItem = HttpResult & { startedAt: number; endedAt: number };

export async function scopedHttp2Pair(
  scope: Scope,
  urlText: string,
  specs: [RequestSpec, RequestSpec],
  options: {
    token?: string;
    cookie?: string;
    signal?: AbortSignal;
    remainingMs?: number;
    environment?: Record<string, string | undefined>;
  } = {},
): Promise<[Http2PairItem, Http2PairItem]> {
  validateScope(scope);
  const url = assertAuthorized(scope, urlText);
  let resolvedA: ReturnType<typeof resolveRequest>;
  let resolvedB: ReturnType<typeof resolveRequest>;
  try {
    resolvedA = resolveRequest(scope, urlText, specs[0], options.environment);
    resolvedB = resolveRequest(scope, urlText, specs[1], options.environment);
  } catch {
    throw new RequestFailure('invalid-request-input');
  }
  let baseHeaders: Record<string, string>;
  try { baseHeaders = identifyingHeaders(scope, url.origin, options.environment); }
  catch { throw new RequestFailure('invalid-identifying-header'); }
  if (options.token !== undefined && options.cookie !== undefined) throw new RequestFailure('invalid-credential');
  if (options.token !== undefined && !bearerTokenRegex.test(options.token)) throw new RequestFailure('invalid-credential');
  if (options.cookie !== undefined) {
    try { credentialFor('BBA_COOKIE_X', options.cookie); } catch { throw new RequestFailure('invalid-credential'); }
  }
  const timeout = Math.min(scope.limits.timeoutMs, options.remainingMs ?? Infinity, Date.parse(scope.authorization.validUntil) - Date.now());
  if (timeout <= 0) throw new RequestFailure('deadline');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const aborted = () => new RequestFailure(options.signal?.aborted ? 'cancelled' : 'deadline');
  let rejectAbort: (() => void) | undefined;
  try {
    if (signal.aborted) throw aborted();
    const targets = await Promise.race([
      destinationAddresses(url, scope),
      new Promise<never>((_, reject) => {
        rejectAbort = () => reject(aborted());
        signal.addEventListener('abort', rejectAbort, { once: true });
      }),
    ]);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
    if (signal.aborted) throw aborted();
    assertAuthorized(scope, urlText);

    return await new Promise<[Http2PairItem, Http2PairItem]>((resolve, reject) => {
      let settled = false;
      let rawSocket: Socket | undefined;
      const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
      const client = http2Connect(url.origin, {
        createConnection: () => {
          rawSocket = url.protocol === 'https:'
            ? tlsConnect({
                host: targets[0].address,
                port,
                servername: isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname,
                ALPNProtocols: ['h2'],
              })
            : netConnect({ host: targets[0].address, port });
          return rawSocket;
        },
      });
      const cleanup = () => {
        try { client.close(); } catch {}
        try { client.destroy(); } catch {}
      };
      const fail = (err: Error) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(err);
        }
      };
      const onAbort = () => fail(aborted());
      signal.addEventListener('abort', onAbort, { once: true });
      client.on('error', () => fail(signal.aborted ? aborted() : new RequestFailure('network-error')));

      client.once('connect', () => {
        if (signal.aborted) { fail(aborted()); return; }
        const makeHeaders = (r: ReturnType<typeof resolveRequest>): Record<string, string> => {
          const h: Record<string, string> = {
            ':method': r.method,
            ':path': r.url.pathname + r.url.search,
            ':scheme': r.url.protocol.slice(0, -1),
            ':authority': r.url.host,
          };
          for (const [k, v] of Object.entries(baseHeaders)) h[k.toLowerCase()] = v;
          if (r.body) {
            h['content-type'] = r.contentType!;
            h['content-length'] = String(r.body.length);
          }
          if (options.cookie) h.cookie = options.cookie;
          if (options.token) h.authorization = `Bearer ${options.token}`;
          return h;
        };

        const streamA = client.request(makeHeaders(resolvedA), { endStream: false });
        const streamB = client.request(makeHeaders(resolvedB), { endStream: false });

        const collect = (stream: ReturnType<typeof client.request>, getStarted: () => number): Promise<Http2PairItem> =>
          new Promise((resStream, rejStream) => {
            let status = 0;
            let contentType = '';
            let location: string | undefined;
            let setCookies: string[] | undefined;
            let size = 0;
            const chunks: Buffer[] = [];
            let streamDone = false;
            stream.on('response', hdrs => {
              status = Number(hdrs[':status'] ?? 0);
              contentType = typeof hdrs['content-type'] === 'string' ? hdrs['content-type'] : '';
              location = typeof hdrs.location === 'string' ? hdrs.location : undefined;
              const rawSc = hdrs['set-cookie'];
              setCookies = Array.isArray(rawSc) ? rawSc : typeof rawSc === 'string' ? [rawSc] : undefined;
            });
            stream.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > scope.limits.maxResponseBytes) {
                stream.close();
                rejStream(new RequestFailure('response-too-large'));
                return;
              }
              chunks.push(Buffer.from(chunk));
            });
            stream.on('end', () => {
              streamDone = true;
              resStream({
                status,
                body: Buffer.concat(chunks),
                contentType,
                location,
                setCookies,
                startedAt: getStarted(),
                endedAt: performance.timeOrigin + performance.now(),
              });
            });
            stream.on('error', () => rejStream(signal.aborted ? aborted() : new RequestFailure('network-error')));
            stream.on('close', () => {
              if (!streamDone) rejStream(signal.aborted ? aborted() : new RequestFailure('incomplete-response'));
            });
          });

        let startedAt = performance.timeOrigin + performance.now();
        const pA = collect(streamA, () => startedAt);
        const pB = collect(streamB, () => startedAt);

        const bodyA = resolvedA.body ?? Buffer.alloc(0);
        const bodyB = resolvedB.body ?? Buffer.alloc(0);
        if (bodyA.length > 1) streamA.write(bodyA.subarray(0, bodyA.length - 1));
        if (bodyB.length > 1) streamB.write(bodyB.subarray(0, bodyB.length - 1));

        // Sincroniza el envío del último byte de ambos streams en la misma escritura del socket.
        startedAt = performance.timeOrigin + performance.now();
        rawSocket?.cork();
        try {
          streamA.end(bodyA.length > 0 ? bodyA.subarray(bodyA.length - 1) : undefined);
          streamB.end(bodyB.length > 0 ? bodyB.subarray(bodyB.length - 1) : undefined);
        } finally {
          rawSocket?.uncork();
        }

        Promise.all([pA, pB]).then(
          pairResult => {
            signal.removeEventListener('abort', onAbort);
            if (!settled) {
              settled = true;
              cleanup();
              resolve(pairResult);
            }
          },
          err => {
            signal.removeEventListener('abort', onAbort);
            fail(err instanceof Error ? err : new RequestFailure('network-error'));
          },
        );
      });
    });
  } catch (error) {
    if (error instanceof RequestFailure) throw error;
    throw new RequestFailure('network-error');
  } finally {
    clearTimeout(timer);
    if (rejectAbort) signal.removeEventListener('abort', rejectAbort);
  }
}
