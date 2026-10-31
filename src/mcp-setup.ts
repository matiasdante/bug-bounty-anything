import { constants, copyFileSync, existsSync, lstatSync, mkdirSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { includesPlatformPath } from './paths.ts';

export type McpSetup = { status: 'ready' | 'replace-ready' | 'installed' | 'updated' | 'already-present'; command: string; args: string[];
  root: string; backup: string | null; restartRequired: true; networkTools: boolean };

function runCodex(args: string[]) {
  const result = spawnSync('codex', args, { encoding: 'utf8', timeout: 15000, windowsHide: true });
  if (result.error) throw new Error('Codex CLI unavailable or timed out');
  return result;
}

// Codex owns its TOML format; use its public CLI to register a stdio server.
// Registration never enables active tools by default and never stores credentials.
export function setupCodexMcp(root: string, apply = false, allowNetwork = false, replace = false): McpSetup {
  const workspace = realpathSync(resolve(root));
  if (!lstatSync(workspace).isDirectory()) throw new Error('MCP root must be a directory');
  const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const cli = realpathSync(join(packageRoot, 'dist', 'cli.js'));
  const command = process.execPath;
  const args = [cli, 'mcp', '--root', workspace, ...(allowNetwork ? ['--allow-network'] : [])];
  const existing = runCodex(['mcp', 'get', 'bba']);
  let replaceExisting = false;
  if (existing.status === 0) {
    const out = existing.stdout ?? '';
    if (includesPlatformPath(out, command) && includesPlatformPath(out, cli) && includesPlatformPath(out, workspace)
      && out.includes('--allow-network') === allowNetwork)
      return { status: 'already-present', command, args, root: workspace,
        backup: null, restartRequired: true, networkTools: allowNetwork };
    if (!replace) throw new Error('An existing bba MCP registration differs; use --replace after review');
    replaceExisting = true;
  }
  if (!replaceExisting && (existing.status !== 1 || !/No MCP server named 'bba' found\./.test(existing.stderr ?? '')))
    throw new Error('Could not inspect existing Codex MCP registration');
  if (!apply) return { status: replaceExisting ? 'replace-ready' : 'ready', command, args, root: workspace,
    backup: null, restartRequired: true, networkTools: allowNetwork };

  const codexHome = resolve(process.env.CODEX_HOME || join(homedir(), '.codex'));
  const config = join(codexHome, 'config.toml');
  if (lstatSync(codexHome).isSymbolicLink() || !lstatSync(codexHome).isDirectory()) throw new Error('Invalid Codex config directory');
  let backup: string | null = null;
  if (existsSync(config)) {
    if (lstatSync(config).isSymbolicLink() || !lstatSync(config).isFile()) throw new Error('Invalid Codex config file');
    const backupDir = join(codexHome, '.bba-backups');
    if (existsSync(backupDir) && (lstatSync(backupDir).isSymbolicLink() || !lstatSync(backupDir).isDirectory()))
      throw new Error('Invalid Codex backup directory');
    mkdirSync(backupDir, { recursive: true });
    backup = join(backupDir, 'config-' + Date.now() + '-' + randomUUID() + '.toml');
    copyFileSync(config, backup, constants.COPYFILE_EXCL);
  }
  if (replaceExisting && runCodex(['mcp', 'remove', 'bba']).status !== 0)
    throw new Error('Could not remove the previous bba registration; original config backup retained');
  const restore = () => { if (backup) copyFileSync(backup, config); };
  const added = runCodex(['mcp', 'add', 'bba', '--', command, ...args]);
  if (added.status !== 0) { restore(); throw new Error('Codex MCP registration failed; original config restored from backup'); }
  const verified = runCodex(['mcp', 'get', 'bba']);
  const verifiedOut = verified.stdout ?? '';
  if (verified.status !== 0 || !includesPlatformPath(verifiedOut, cli) || !includesPlatformPath(verifiedOut, workspace)
    || verifiedOut.includes('--allow-network') !== allowNetwork) {
    restore(); throw new Error('Codex MCP registration could not be verified; original config restored from backup');
  }
  return { status: replaceExisting ? 'updated' : 'installed', command, args, root: workspace,
    backup, restartRequired: true, networkTools: allowNetwork };
}
