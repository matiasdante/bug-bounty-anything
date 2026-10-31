import { lstatSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SafeError } from './contracts.ts';

export function normalizePlatformPath(target: string): string {
  return process.platform === 'win32' ? target.toLowerCase() : target;
}

export function canonicalPath(target: string): string {
  return normalizePlatformPath(realpathSync(resolve(target)));
}

export function resolvedPlatformPath(target: string): string {
  try {
    return canonicalPath(target);
  } catch {
    return normalizePlatformPath(resolve(target));
  }
}

export function samePath(left: string, right: string): boolean {
  return resolvedPlatformPath(left) === resolvedPlatformPath(right);
}

export function isStrictSubpath(parentDir: string, candidate: string): boolean {
  const base = resolvedPlatformPath(parentDir);
  const full = resolvedPlatformPath(candidate);
  const rel = relative(base, full);
  return Boolean(rel) && !rel.startsWith('..') && !isAbsolute(rel);
}

export function includesPlatformPath(haystack: string, needlePath: string): boolean {
  if (process.platform === 'win32') {
    return haystack.toLowerCase().includes(needlePath.toLowerCase());
  }
  return haystack.includes(needlePath);
}

// Usa una transacción BEGIN IMMEDIATE en SQLite como lock administrado por el SO:
// si el proceso muere con SIGKILL, el descriptor se cierra y nunca queda un lockfile huérfano.
export function withSqliteLockSync<T>(lockFile: string, busyMessage: string, action: () => T): T {
  try {
    const stat = lstatSync(lockFile);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) {
      throw new SafeError('Invalid SQLite lock file');
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const lock = new DatabaseSync(lockFile, { timeout: 0 });
  try {
    try {
      lock.exec('PRAGMA trusted_schema=OFF; CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY) STRICT; BEGIN IMMEDIATE;');
    } catch {
      throw new SafeError(busyMessage);
    }
    return action();
  } finally {
    lock.close();
  }
}

