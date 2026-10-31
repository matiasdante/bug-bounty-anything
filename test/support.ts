import { createServer } from 'node:http';
import type { RequestListener } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import type { Scope } from '../src/scope.ts';

export async function fixture<T>(handler: RequestListener, action: (scope: Scope, folder: string) => Promise<T>): Promise<T> {
  const folder = await mkdtemp(join(tmpdir(), 'bba-extended-'));
  const server = createServer(handler);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
  try {
    return await action({ schemaVersion: 1, mode: 'loopback-lab',
      authorization: { reference: 'owned disposable fixture', validFrom: new Date(Date.now() - 1000).toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() },
      allowed: [{ origin, paths: ['/'] }], excluded: [],
      limits: { maxRequests: 100, minIntervalMs: 0, timeoutMs: 2000, maxResponseBytes: 65536, maxDurationMs: 600000 } }, folder);
  } finally {
    await new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); });
    assert.ok(folder.startsWith(join(tmpdir(), 'bba-extended-'))); await rm(folder, { recursive: true, force: true });
  }
}
