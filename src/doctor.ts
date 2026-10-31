import { createServer, connect } from 'node:net';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type DoctorCheck = { name: string; ok: boolean; detail: string };

const attempt = async (name: string, test: () => Promise<string>): Promise<DoctorCheck> => {
  try { return { name, ok: true, detail: await test() }; }
  catch (error) { return { name, ok: false, detail: error instanceof Error ? error.message.slice(0, 160) : 'failed' }; }
};

// Local checks only: nothing here contacts a remote host or prints a secret value.
export async function doctor(): Promise<{ ok: boolean; checks: DoctorCheck[] }> {
  const checks = [
    await attempt('node', async () => {
      const [major, minor] = process.versions.node.split('.').map(Number);
      if (major < 22 || (major === 22 && minor < 13)) {
        throw new Error(`Node ${process.versions.node} found; 22.13 or later is required`);
      }
      return process.versions.node;
    }),
    await attempt('sqlite', async () => {
      const { DatabaseSync } = await import('node:sqlite');
      const db = new DatabaseSync(':memory:'); db.exec('create table t (x)'); db.close();
      return 'node:sqlite works';
    }),
    await attempt('loopback', async () => {
      const server = createServer(socket => { socket.on('error', () => {}); socket.end('ok'); });
      await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
      try {
        const port = (server.address() as { port: number }).port;
        await new Promise<void>((resolve, reject) => { const c = connect(port, '127.0.0.1', () => { c.end(); resolve(); }); c.once('error', reject); c.on('error', () => {}); });
        return 'binds and connects on 127.0.0.1';
      } finally { server.close(); }
    }),
    await attempt('temp-directory', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'bba-doctor-'));
      try { await writeFile(join(dir, 'x'), 'x'); await readFile(join(dir, 'x')); return 'writable'; } finally { await rm(dir, { recursive: true, force: true }); }
    }),
    await attempt('browser', async () => {
      const { launchIsolated } = await import('./capture.ts');
      const isolated = await launchIsolated();
      try { return 'Chromium ' + isolated.browser.version() + ' launches with the isolation flags'; } finally { await isolated.close(); }
    }),
  ];
  const names = Object.keys(process.env).filter(k => /^BBA_(TOKEN|COOKIE|HEADER|INPUT|BODY)_[A-Z0-9_]+$/.test(k)).sort();
  checks.push({ name: 'credentials', ok: true, detail: names.length ? 'present (names only): ' + names.join(', ') : 'none set; only anonymous steps without required identifying headers can run' });
  return { ok: checks.every(c => c.ok), checks };
}
