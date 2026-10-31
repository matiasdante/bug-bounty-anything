import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export type AppendJournal = {
  append: (event: Record<string, unknown>) => void;
  close: () => void;
};

// Journal append-only exclusivo con fsync en cada evento para conservar evidencia ante fallos abruptos.
export function openAppendJournal(folder: string, filename = 'requests.jsonl'): AppendJournal {
  const fd = openSync(join(folder, filename), 'wx', 0o600);
  let closed = false;
  return {
    append(event: Record<string, unknown>) {
      if (closed) throw new Error('Journal already closed');
      writeSync(fd, JSON.stringify(event) + '\n');
      fsyncSync(fd);
    },
    close() {
      if (!closed) {
        closed = true;
        closeSync(fd);
      }
    },
  };
}

// Aplica espaciado mínimo entre requests respetando deadline y señal de cancelación.
export async function waitIntervalOrDeadline(
  lastEnd: number,
  minIntervalMs: number,
  deadline: number,
  signal?: AbortSignal,
): Promise<void> {
  if (signal?.aborted) throw new Error('cancelled');
  const wait = Math.max(0, lastEnd + minIntervalMs - Date.now());
  if (Date.now() + wait >= deadline) throw new Error('deadline');
  if (wait > 0) {
    try {
      await delay(wait, undefined, { signal });
    } catch {
      throw new Error('cancelled');
    }
  }
  if (signal?.aborted) throw new Error('cancelled');
  if (Date.now() >= deadline) throw new Error('deadline');
}
