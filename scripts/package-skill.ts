import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import { isStrictSubpath } from '../src/paths.ts';

// Tabla CRC-32 IEEE 802.3 para cabeceras PKZIP sin dependencias externas.
const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

type ZipEntryInput = { name: string; data: Buffer };

export function createZipBuffer(entries: ZipEntryInput[]): Buffer {
  const seen = new Set<string>();
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    if (!entry.name.startsWith('bug-bounty-anything/') || entry.name.includes('\\') || /(^|\/)\.\.(\/|$)/.test(entry.name)) {
      throw new Error(`Unsafe archive path: ${entry.name}`);
    }
    if (seen.has(entry.name)) throw new Error(`Duplicate archive entry: ${entry.name}`);
    seen.add(entry.name);

    const nameBytes = Buffer.from(entry.name, 'utf8');
    const uncompressed = entry.data;
    const compressed = deflateRawSync(uncompressed, { level: 9 });
    const useDeflate = compressed.length < uncompressed.length;
    const payload = useDeflate ? compressed : uncompressed;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(uncompressed);

    const localHeader = Buffer.alloc(30 + nameBytes.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4); // version needed 2.0
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8 flag
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0x5421, 12); // fixed mod date (2022-01-01)
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(payload.length, 18);
    localHeader.writeUInt32LE(uncompressed.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    localHeader.writeUInt16LE(0, 28);
    nameBytes.copy(localHeader, 30);

    const centralHeader = Buffer.alloc(46 + nameBytes.length);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x5421, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(payload.length, 20);
    centralHeader.writeUInt32LE(uncompressed.length, 24);
    centralHeader.writeUInt16LE(nameBytes.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    nameBytes.copy(centralHeader, 46);

    localParts.push(localHeader, payload);
    centralParts.push(centralHeader);
    offset += localHeader.length + payload.length;
  }

  const centralSize = centralParts.reduce((n, b) => n + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

function replaceSection(body: string, start: string, end: string, replacement: string): string {
  const first = body.indexOf(start);
  if (first < 0) throw new Error(`Missing skill section: ${start}`);
  const last = body.indexOf(end, first);
  if (last < 0) throw new Error(`Missing skill section boundary: ${end}`);
  return body.slice(0, first) + replacement + body.slice(last);
}

function collectFiles(projectRoot: string, targetPath: string): { rel: string; data: Buffer }[] {
  const stat = lstatSync(targetPath);
  if (stat.isSymbolicLink()) throw new Error(`Link in package: ${targetPath}`);
  if (!isStrictSubpath(projectRoot, targetPath)) throw new Error(`File outside project root: ${targetPath}`);
  if (stat.isFile()) {
    const rel = targetPath.slice(projectRoot.length + 1).replaceAll('\\', '/');
    return [{ rel, data: readFileSync(targetPath) }];
  }
  if (!stat.isDirectory()) return [];
  const entries = readdirSync(targetPath).sort();
  return entries.flatMap(name => collectFiles(projectRoot, join(targetPath, name)));
}

const claudeConnectionSection = `For Claude Code, this extracted folder contains the compiled BBA CLI and its
production dependency. Follow [Claude Code installation](INSTALL-CLAUDE-CODE.md)
to register its local stdio MCP server. Its default mode exposes offline tools.
Network tools require a deliberate \`--allow-network\` registration and a valid
per-target scope; do not infer that a connected MCP grants target permission.
Reconnect Claude Code and inspect \`/mcp\` after changing the registration.

`;

const claudeRuntimeSection = `Without MCP, use \`node dist/cli.js\` from this extracted skill folder. The
runtime and \`playwright-core\` are bundled here; Node.js 22.13 or later is required.
Store case outputs in the investigation workspace, outside the skill folder.

`;

const claudeInstallDoc = `# BBA for Claude Code & Gemini

Extract \`bug-bounty-anything\` under \`<project>/.claude/skills/\` or \`~/.claude/skills/\`.
Requires Node.js 22.13 or later.

Register the offline MCP server using BBA's multi-client installer:

\`\`\`text
node <skill-folder>/dist/cli.js setup-mcp --client claude --root <workspace> --apply
node <skill-folder>/dist/cli.js setup-mcp --client gemini --root <workspace> --apply
\`\`\`

Add \`--allow-network\` only when active testing is authorized by a valid per-target scope.
`;

export function packageSkill(options: { projectRoot?: string; outputPath?: string; includeNodeModules?: boolean } = {}): {
  archivePath: string;
  entries: number;
} {
  const projectRoot = resolve(options.projectRoot ?? join(dirname(fileURLToPath(import.meta.url)), '..'));
  const pkg = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
  const version = String(pkg.version);
  const outputPath = resolve(options.outputPath ?? join(projectRoot, `bug-bounty-anything-${version}-claude-code-manual.zip`));
  const partialPath = `${outputPath}.partial`;
  if (existsSync(outputPath)) throw new Error(`Archive already exists: ${outputPath}`);
  if (existsSync(partialPath)) throw new Error(`Partial archive already exists: ${partialPath}`);

  for (const required of ['SKILL.md', 'dist/cli.js', 'node_modules/playwright-core/package.json']) {
    const p = join(projectRoot, required);
    if (!existsSync(p) || !lstatSync(p).isFile()) throw new Error(`Missing required package file: ${required}`);
  }
  const dep = JSON.parse(readFileSync(join(projectRoot, 'node_modules/playwright-core/package.json'), 'utf8'));
  if (dep.version !== pkg.dependencies?.['playwright-core']) {
    throw new Error('The bundled playwright-core version differs from package.json');
  }

  let skill = readFileSync(join(projectRoot, 'SKILL.md'), 'utf8').replaceAll('\r\n', '\n');
  if (!skill.includes(`version: "${version}"`)) throw new Error('Skill and package versions differ');
  if (!/^metadata:[ \t]*$/m.test(skill)) throw new Error('Skill frontmatter metadata boundary missing');
  skill = skill.replace(/^metadata:[ \t]*$/m, 'disable-model-invocation: true\nmetadata:');
  const connAnchor = skill.includes('For a requested MCP connection,')
    ? 'For a requested MCP connection,'
    : 'For a requested Codex connection,';
  skill = replaceSection(skill, connAnchor, 'Use `capabilities` when coverage is uncertain;', claudeConnectionSection);
  skill = replaceSection(skill, 'Without MCP, use the local CLI.', 'If the runtime is missing', claudeRuntimeSection);

  const items = [
    'package.json',
    'package-lock.json',
    'dist',
    'docs',
    'references',
    'agents',
    'cases',
    ...(options.includeNodeModules !== false ? ['node_modules/playwright-core'] : []),
  ];

  const prefix = 'bug-bounty-anything/';
  const zipEntries: ZipEntryInput[] = [
    { name: `${prefix}SKILL.md`, data: Buffer.from(skill, 'utf8') },
    { name: `${prefix}INSTALL-CLAUDE-CODE.md`, data: Buffer.from(claudeInstallDoc, 'utf8') },
  ];

  for (const item of items) {
    const full = join(projectRoot, item);
    if (!existsSync(full)) throw new Error(`Missing package item: ${item}`);
    for (const file of collectFiles(projectRoot, full)) {
      zipEntries.push({ name: prefix + file.rel, data: file.data });
    }
  }

  if (options.includeNodeModules !== false && zipEntries.length < 150) {
    throw new Error('Invalid archive entry count');
  }

  mkdirSync(dirname(outputPath), { recursive: true });
  try {
    const zipBuffer = createZipBuffer(zipEntries);
    writeFileSync(partialPath, zipBuffer, { flag: 'wx', mode: 0o600 });
    renameSync(partialPath, outputPath);
  } catch (err) {
    if (existsSync(partialPath)) {
      try { unlinkSync(partialPath); } catch { /* ignore cleanup error */ }
    }
    throw err;
  }
  return { archivePath: outputPath, entries: zipEntries.length };
}

const isDirectEntry = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isDirectEntry) {
  const args = process.argv.slice(2);
  let outputPath: string | undefined;
  let includeNodeModules = true;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out' && args[i + 1]) {
      outputPath = args[++i];
    } else if (args[i] === '--minimal') {
      includeNodeModules = false;
    } else {
      throw new Error(`Unknown argument: ${args[i]}`);
    }
  }
  const res = packageSkill({ outputPath, includeNodeModules });
  console.log(`Entries: ${res.entries}\nArchive: ${res.archivePath}`);
}

