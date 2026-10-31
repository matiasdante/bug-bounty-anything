import { constants, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { SafeError } from './contracts.ts';
import { includesPlatformPath, samePath } from './paths.ts';

export type McpClient = 'codex' | 'claude' | 'gemini';
export type McpSetup = {
  status: 'ready' | 'replace-ready' | 'installed' | 'updated' | 'already-present';
  client?: McpClient;
  configPath?: string;
  command: string;
  args: string[];
  root: string;
  backup: string | null;
  restartRequired: true;
  networkTools: boolean;
};

function runCodex(args: string[]) {
  const result = spawnSync('codex', args, { encoding: 'utf8', timeout: 15000, windowsHide: true });
  if (result.error) throw new Error('Codex CLI unavailable or timed out');
  return result;
}

function resolveServerCommand(root: string, allowNetwork: boolean) {
  const workspace = realpathSync(resolve(root));
  if (!lstatSync(workspace).isDirectory()) throw new SafeError('MCP root must be a directory');
  const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const cli = realpathSync(join(packageRoot, 'dist', 'cli.js'));
  const command = process.execPath;
  const args = [cli, 'mcp', '--root', workspace, ...(allowNetwork ? ['--allow-network'] : [])];
  return { workspace, cli, command, args };
}

// Codex usa su propia CLI TOML; Claude Code (.mcp.json) y Gemini (.gemini/settings.json) usan JSON local.
export function setupCodexMcp(root: string, apply = false, allowNetwork = false, replace = false): McpSetup {
  const { workspace, cli, command, args } = resolveServerCommand(root, allowNetwork);
  const existing = runCodex(['mcp', 'get', 'bba']);
  let replaceExisting = false;
  const codexHome = resolve(process.env.CODEX_HOME || join(homedir(), '.codex'));
  const config = join(codexHome, 'config.toml');
  if (existing.status === 0) {
    const out = existing.stdout ?? '';
    if (includesPlatformPath(out, command) && includesPlatformPath(out, cli) && includesPlatformPath(out, workspace)
      && out.includes('--allow-network') === allowNetwork)
      return { status: 'already-present', client: 'codex', configPath: config, command, args, root: workspace,
        backup: null, restartRequired: true, networkTools: allowNetwork };
    if (!replace) throw new SafeError('An existing bba MCP registration differs; use --replace after review');
    replaceExisting = true;
  }
  if (!replaceExisting && (existing.status !== 1 || !/No MCP server named 'bba' found\./.test(existing.stderr ?? '')))
    throw new SafeError('Could not inspect existing Codex MCP registration');
  if (!apply) return { status: replaceExisting ? 'replace-ready' : 'ready', client: 'codex', configPath: config, command, args, root: workspace,
    backup: null, restartRequired: true, networkTools: allowNetwork };

  if (lstatSync(codexHome).isSymbolicLink() || !lstatSync(codexHome).isDirectory()) throw new SafeError('Invalid Codex config directory');
  let backup: string | null = null;
  if (existsSync(config)) {
    if (lstatSync(config).isSymbolicLink() || !lstatSync(config).isFile()) throw new SafeError('Invalid Codex config file');
    const backupDir = join(codexHome, '.bba-backups');
    if (existsSync(backupDir) && (lstatSync(backupDir).isSymbolicLink() || !lstatSync(backupDir).isDirectory()))
      throw new SafeError('Invalid Codex backup directory');
    mkdirSync(backupDir, { recursive: true });
    backup = join(backupDir, 'config-' + Date.now() + '-' + randomUUID() + '.toml');
    copyFileSync(config, backup, constants.COPYFILE_EXCL);
  }
  if (replaceExisting && runCodex(['mcp', 'remove', 'bba']).status !== 0)
    throw new SafeError('Could not remove the previous bba registration; original config backup retained');
  const restore = () => { if (backup) copyFileSync(backup, config); };
  const added = runCodex(['mcp', 'add', 'bba', '--', command, ...args]);
  if (added.status !== 0) { restore(); throw new SafeError('Codex MCP registration failed; original config restored from backup'); }
  const verified = runCodex(['mcp', 'get', 'bba']);
  const verifiedOut = verified.stdout ?? '';
  if (verified.status !== 0 || !includesPlatformPath(verifiedOut, cli) || !includesPlatformPath(verifiedOut, workspace)
    || verifiedOut.includes('--allow-network') !== allowNetwork) {
    restore(); throw new SafeError('Codex MCP registration could not be verified; original config restored from backup');
  }
  return { status: replaceExisting ? 'updated' : 'installed', client: 'codex', configPath: config, command, args, root: workspace,
    backup, restartRequired: true, networkTools: allowNetwork };
}

function matchesJsonServer(entry: unknown, command: string, cli: string, workspace: string, allowNetwork: boolean): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const rec = entry as Record<string, unknown>;
  if (typeof rec.command !== 'string' || !Array.isArray(rec.args)) return false;
  if (!samePath(rec.command, command)) return false;
  const a = rec.args.map(String);
  const rootIdx = a.indexOf('--root');
  if (a.length < 4 || !samePath(a[0], cli) || a[1] !== 'mcp' || rootIdx !== 2 || !samePath(a[3], workspace)) return false;
  const hasNet = a.includes('--allow-network');
  const expectedLen = allowNetwork ? 5 : 4;
  return hasNet === allowNetwork && a.length === expectedLen;
}

export function setupMcp(
  root: string,
  options: { client?: McpClient; apply?: boolean; allowNetwork?: boolean; replace?: boolean; configPath?: string } = {},
): McpSetup {
  const client = options.client ?? 'codex';
  const apply = options.apply ?? false;
  const allowNetwork = options.allowNetwork ?? false;
  const replace = options.replace ?? false;
  if (client !== 'codex' && client !== 'claude' && client !== 'gemini') {
    throw new SafeError('Unsupported MCP client; expected codex, claude or gemini');
  }
  if (client === 'codex') return setupCodexMcp(root, apply, allowNetwork, replace);

  const { workspace, cli, command, args } = resolveServerCommand(root, allowNetwork);
  const configPath = resolve(
    options.configPath
      ?? (client === 'claude' ? join(workspace, '.mcp.json') : join(workspace, '.gemini', 'settings.json')),
  );
  const configDir = dirname(configPath);
  if (existsSync(configDir) && (lstatSync(configDir).isSymbolicLink() || !lstatSync(configDir).isDirectory())) {
    throw new SafeError('Invalid MCP config directory');
  }

  let parsed: Record<string, unknown> = {};
  let fileExisted = false;
  if (existsSync(configPath)) {
    const st = lstatSync(configPath);
    if (st.isSymbolicLink() || !st.isFile() || st.size > 1024 * 1024) throw new SafeError('Invalid MCP config file');
    fileExisted = true;
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(configPath, 'utf8')); } catch { throw new SafeError('Malformed JSON in MCP config file'); }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new SafeError('MCP config root must be a JSON object');
    parsed = raw as Record<string, unknown>;
  }

  const serversRaw = parsed.mcpServers;
  if (serversRaw !== undefined && (!serversRaw || typeof serversRaw !== 'object' || Array.isArray(serversRaw))) {
    throw new SafeError('mcpServers in config must be an object');
  }
  const servers = { ...(serversRaw as Record<string, unknown> | undefined) };
  let replaceExisting = false;
  if (Object.hasOwn(servers, 'bba')) {
    if (matchesJsonServer(servers.bba, command, cli, workspace, allowNetwork)) {
      return {
        status: 'already-present',
        client,
        configPath,
        command,
        args,
        root: workspace,
        backup: null,
        restartRequired: true,
        networkTools: allowNetwork,
      };
    }
    if (!replace) throw new SafeError('An existing bba MCP registration differs; use --replace after review');
    replaceExisting = true;
  }

  if (!apply) {
    return {
      status: replaceExisting ? 'replace-ready' : 'ready',
      client,
      configPath,
      command,
      args,
      root: workspace,
      backup: null,
      restartRequired: true,
      networkTools: allowNetwork,
    };
  }

  mkdirSync(configDir, { recursive: true });
  let backup: string | null = null;
  if (fileExisted) {
    const backupDir = join(configDir, '.bba-backups');
    if (existsSync(backupDir) && (lstatSync(backupDir).isSymbolicLink() || !lstatSync(backupDir).isDirectory())) {
      throw new SafeError('Invalid MCP backup directory');
    }
    mkdirSync(backupDir, { recursive: true });
    backup = join(backupDir, `config-${Date.now()}-${randomUUID()}.json`);
    copyFileSync(configPath, backup, constants.COPYFILE_EXCL);
  }

  servers.bba = client === 'claude' ? { type: 'stdio', command, args } : { command, args };
  const nextDoc = { ...parsed, mcpServers: servers };
  writeFileSync(configPath, JSON.stringify(nextDoc, null, 2) + '\n', { mode: 0o600 });
  return {
    status: replaceExisting ? 'updated' : 'installed',
    client,
    configPath,
    command,
    args,
    root: workspace,
    backup,
    restartRequired: true,
    networkTools: allowNetwork,
  };
}
