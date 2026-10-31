import { cpSync, existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync, lstatSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import pkg from '../package.json' with { type: 'json' };

// Install only this skill's resources; never touch MCP/client configuration,
// unrelated skills, dependencies or an existing destination.
export function installSkill(folder: string, update = false) {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const cli = join(root, 'dist', 'cli.js');
  if (!existsSync(cli)) throw new Error('Build the package before installing the skill');
  const out = resolve(folder);
  const names = ['SKILL.md', 'README.md', 'references', 'docs', 'agents', 'cases'];
  const tree = (path: string, relative = ''): string[] => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('Skill resources cannot be links');
    if (stat.isFile()) return [relative];
    if (!stat.isDirectory()) throw new Error('Invalid skill resource');
    return readdirSync(path).flatMap(name => tree(join(path, name), relative ? relative + '/' + name : name));
  };
  for (const name of names) tree(join(root, name));
  let backup: string | null = null;
  if (update) {
    if (!lstatSync(out).isDirectory() || lstatSync(out).isSymbolicLink()) throw new Error('Invalid skill installation directory');
    const runtime = JSON.parse(readFileSync(join(out, 'runtime.json'), 'utf8'));
    if (runtime.schemaVersion !== 1 || resolve(runtime.packageRoot) !== resolve(root)
      || !/^name: bug-bounty-anything\r?$/m.test(readFileSync(join(out, 'SKILL.md'), 'utf8'))) throw new Error('Skill is not bound to this package');
    for (const name of [...names, 'runtime.json', 'installation.json']) if (existsSync(join(out, name))) tree(join(out, name));
  } else { mkdirSync(dirname(out), { recursive: true }); mkdirSync(out); }
  const lockPath = join(out, '.bba-update.lock');
  const lock = openSync(lockPath, 'wx', 0o600);
  try {
    if (update) {
      const backups = join(out, '.bba-backups');
      if (existsSync(backups) && lstatSync(backups).isSymbolicLink()) throw new Error('Skill backup directory cannot be a link');
      backup = join(backups, Date.now() + '-' + randomUUID()); mkdirSync(backup, { recursive: true });
      for (const name of [...names, 'runtime.json', 'installation.json']) if (existsSync(join(out, name))) cpSync(join(out, name), join(backup, name === 'SKILL.md' ? 'SKILL.md.bak' : name), { recursive: true, errorOnExist: true, force: false });
    }
    for (const name of names.filter(n => n !== 'SKILL.md')) cpSync(join(root, name), join(out, name), { recursive: true, errorOnExist: !update, force: update });
    writeFileSync(join(out, 'runtime.json'), JSON.stringify({ schemaVersion: 1, packageVersion: pkg.version,
      command: process.execPath, args: [cli], packageRoot: root }, null, 2) + '\n', { flag: update ? 'w' : 'wx', mode: 0o600 });
    cpSync(join(root, 'SKILL.md'), join(out, 'SKILL.md'), { errorOnExist: !update, force: update });
    const files = [...names.flatMap(name => tree(join(root, name), name)), 'runtime.json'];
    writeFileSync(join(out, 'installation.json'), JSON.stringify({ schemaVersion: 1, packageVersion: pkg.version, packageRoot: root,
      managedFiles: files.map(path => ({ path, sha256: createHash('sha256').update(readFileSync(join(out, path))).digest('hex') })) }, null, 2), { flag: update ? 'w' : 'wx', mode: 0o600 });
  } finally { closeSync(lock); unlinkSync(lockPath); }
  return { skill: join(out, 'SKILL.md'), runtime: join(out, 'runtime.json'), packageRoot: root,
    backup, mcpConfigurationChanged: false, restartRequiredForDiscovery: true };
}
