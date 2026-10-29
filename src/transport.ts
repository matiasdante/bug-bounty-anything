import { validateDocument } from './contracts.ts';
import type { Actor, Document, Observation } from './contracts.ts';
import { scopedRequest, RequestFailure } from './http.ts';
import { validateScope } from './scope.ts';
import type { Scope } from './scope.ts';

// Compatibility wrapper: the original lab uses the shared scoped HTTP core.
export function labTransport(origin: string, paths: string[], options: {
  budget?: number; timeoutMs?: number; maxBytes?: number;
} = {}) {
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin)) throw new Error('Only literal loopback lab origins are supported');
  if (paths.length !== 2 || new Set(paths).size !== 2 || paths.some(p => !/^\/documents\/[a-f0-9-]{36}$/.test(p))) throw new Error('Invalid allowed paths');
  const { budget = 5, timeoutMs = 2000, maxBytes = 4096 } = options;
  const scope: Scope = {
    schemaVersion: 1, mode: 'loopback-lab',
    authorization: { reference: 'BBA-owned disposable lab', validFrom: new Date().toISOString(), validUntil: new Date(Date.now() + 3600000).toISOString() },
    allowed: [{ origin, paths }], excluded: [],
    limits: { maxRequests: budget, timeoutMs, maxResponseBytes: maxBytes, minIntervalMs: 0, maxDurationMs: 3600000 },
  };
  validateScope(scope);
  let used = 0, stopped = false;
  return async (path: string, actor: Actor, credential?: string): Promise<Observation> => {
    if (!['anonymous', 'account-a', 'account-b'].includes(actor)) throw new Error('Invalid actor');
    if (actor === 'anonymous' ? credential !== undefined : !credential || !/^[a-f0-9]{64}$/.test(credential)) throw new Error('Invalid account credential');
    if (!paths.includes(path)) throw new Error('Request blocked: path outside scope');
    if (stopped) throw new Error('Transport stopped after unsafe or incomplete response');
    if (used >= budget) throw new Error('Request budget exhausted');
    used++;
    try {
      const timestamp = new Date().toISOString();
      const result = await scopedRequest(scope, origin + path, { token: credential });
      if ((result.status >= 300 && result.status < 400) || result.status === 429 || result.status >= 500) throw new Error(`Stopped on HTTP ${result.status}`);
      let document: Document | null = null;
      if (result.status === 200) {
        try {
          if (!result.contentType.startsWith('application/json')) throw new Error('Content type');
          const body: unknown = JSON.parse(result.body.toString('utf8'));
          validateDocument(body);
          if (path !== '/documents/' + body.id) throw new Error('Wrong document');
          document = body;
        } catch { throw new Error('Response does not match the synthetic lab contract'); }
      }
      return { timestamp, actor, path, status: result.status, document };
    } catch (error) {
      stopped = true;
      if (error instanceof RequestFailure && error.code === 'response-too-large') throw new Error('Incomplete or oversized response');
      if (error instanceof RequestFailure && error.code === 'deadline') throw new Error('Lab request exceeded its deadline');
      throw error;
    }
  };
}
