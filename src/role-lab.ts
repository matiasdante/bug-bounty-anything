import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { Variant } from './contracts.ts';

export type RoleLab = {
  origin: string; profileId: string;
  credentials: Record<'admin' | 'user', string>;
  close: () => Promise<void>;
};

// Two intentional flaws, one per variant switch: a missing function-level check
// on /admin/users (BFLA) and an unfiltered privileged property on /profiles/<id>.
export async function startRoleLab(variant: Variant): Promise<RoleLab> {
  if (variant !== 'vulnerable' && variant !== 'fixed') throw new Error('Unknown lab variant');
  const credentials = { admin: randomBytes(32).toString('hex'), user: randomBytes(32).toString('hex') };
  const profileId = randomUUID();
  const profile = { id: profileId, displayName: 'synthetic-' + randomBytes(8).toString('hex') };
  const privileged = { ...profile, internalScore: 'synthetic-' + randomBytes(8).toString('hex') };
  const users = [{ id: randomUUID(), role: 'admin' }, { id: randomUUID(), role: 'user' }];
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    const reply = (status: number, body: unknown) => { res.writeHead(status); res.end(JSON.stringify(body)); };
    if (req.method !== 'GET') { reply(405, { error: 'method-not-allowed' }); return; }
    const role = Object.entries(credentials).find(([, token]) => req.headers.authorization === `Bearer ${token}`)?.[0];
    if (!role) { reply(401, { error: 'unauthenticated' }); return; }
    if (req.url === '/admin/users') {
      if (variant === 'fixed' && role !== 'admin') { reply(403, { error: 'forbidden' }); return; }
      reply(200, users); return;
    }
    if (req.url === '/profiles/' + profileId) {
      reply(200, variant === 'fixed' && role !== 'admin' ? profile : privileged); return;
    }
    reply(404, { error: 'not-found' });
  });
  server.requestTimeout = 3000; server.headersTimeout = 3000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Lab failed to bind');
  return {
    origin: `http://127.0.0.1:${address.port}`, profileId, credentials,
    close: () => new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}
