import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { Actor, Document, Variant } from './contracts.ts';

export type Lab = {
  origin: string;
  documents: [Document, Document];
  credentials: Record<'account-a' | 'account-b', string>;
  close: () => Promise<void>;
};

export async function startLab(variant: Variant): Promise<Lab> {
  if (variant !== 'vulnerable' && variant !== 'fixed') throw new Error('Unknown lab variant');
  const credentials = {
    'account-a': randomBytes(32).toString('hex'),
    'account-b': randomBytes(32).toString('hex'),
  };
  const documents: [Document, Document] = ['account-a', 'account-b'].map(owner => ({
    id: randomUUID(), owner: owner as Actor, marker: 'synthetic-' + randomBytes(16).toString('hex'),
  })) as [Document, Document];
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    const reply = (status: number, body: unknown) => { res.writeHead(status); res.end(JSON.stringify(body)); };
    if (req.method !== 'GET') { reply(405, { error: 'method-not-allowed' }); return; }
    const identity = Object.entries(credentials).find(([, token]) => req.headers.authorization === `Bearer ${token}`)?.[0];
    if (!identity) { reply(401, { error: 'unauthenticated' }); return; }
    const doc = documents.find(d => req.url === '/documents/' + d.id);
    if (!doc) { reply(404, { error: 'not-found' }); return; }
    // The ONLY intentional vulnerability is the missing object-owner check.
    if (variant === 'fixed' && doc.owner !== identity) { reply(403, { error: 'forbidden' }); return; }
    reply(200, doc);
  });
  server.requestTimeout = 3000;
  server.headersTimeout = 3000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Lab failed to bind');
  return {
    origin: `http://127.0.0.1:${address.port}`, documents, credentials,
    close: () => new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}
