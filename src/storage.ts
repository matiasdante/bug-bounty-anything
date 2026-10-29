import { mkdir, open, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { canonical, digest, validateBundle } from './contracts.ts';
import type { Bundle, Investigation } from './contracts.ts';
import { evaluate } from './investigation.ts';
import { renderReport } from './report.ts';

export function verify(bundle: unknown): asserts bundle is Bundle {
  validateBundle(bundle);
  if (canonical(bundle.investigation.findings) !== canonical(evaluate(bundle.investigation.evidence))) {
    throw new Error('Findings do not match their evidence');
  }
}

export async function requireNewDirectory(path: string): Promise<string> {
  const target = resolve(path);
  try { await stat(target); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return target;
    throw error;
  }
  throw new Error('Output already exists; choose a new directory');
}

export async function saveInvestigation(path: string, investigation: Investigation): Promise<void> {
  const target = await requireNewDirectory(path);
  const bundle: Bundle = { investigation, sha256: digest(investigation) };
  verify(bundle);
  await mkdir(dirname(target), { recursive: true });
  // Reserve the destination exclusively. A marker makes interrupted writes
  // distinguishable from complete investigations; never replace user files.
  await mkdir(target);
  const marker = join(target, '.incomplete');
  await writeFile(marker, 'BBA write in progress\n', { flag: 'wx' });
  await writeFile(join(target, 'investigation.json'), JSON.stringify(bundle, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await writeFile(join(target, 'report.md'), renderReport(investigation), { flag: 'wx', mode: 0o600 });
  await rm(marker);
}

export async function loadInvestigation(path: string): Promise<Investigation> {
  const folder = resolve(path);
  try {
    await stat(join(folder, '.incomplete'));
    throw new Error('Investigation write is incomplete');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const handle = await open(join(folder, 'investigation.json'), 'r');
  let raw: Buffer;
  try {
    // Bound memory even if the file changes after opening.
    const buffer = Buffer.alloc(1024 * 1024 + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > 1024 * 1024) throw new Error('Investigation exceeds 1 MiB');
    raw = buffer.subarray(0, offset);
  } finally { await handle.close(); }
  const bundle: unknown = JSON.parse(raw.toString('utf8'));
  verify(bundle);
  return bundle.investigation;
}

export async function exportReport(folder: string, output: string): Promise<void> {
  const investigation = await loadInvestigation(folder);
  await writeFile(resolve(output), renderReport(investigation), { flag: 'wx', mode: 0o600 });
}
