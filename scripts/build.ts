import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, lstatSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

// Node refuses to strip types inside node_modules, so an installed package must ship plain JS.
const thisFile = fileURLToPath(import.meta.url);
const project = dirname(dirname(thisFile));

export function collectTsFiles(rootDir: string, currentDir = rootDir): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
    const fullPath = join(currentDir, entry.name);
    if (lstatSync(fullPath).isSymbolicLink()) {
      throw new Error(`Symbolic link not allowed in src: ${fullPath}`);
    }
    if (entry.isDirectory()) {
      results.push(...collectTsFiles(rootDir, fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      results.push(relative(rootDir, fullPath));
    }
  }
  return results;
}

export function rewriteRelativeTsImports(code: string): string {
  return code
    .replace(/((?:\bfrom|\bimport)\s*\(\s*['"])(\.\.?\/[^'"]+?)\.ts(['"]\s*\))/g, '$1$2.js$3')
    .replace(/(\bfrom\s+['"])(\.\.?\/[^'"]+?)\.ts(['"])/g, '$1$2.js$3')
    .replace(/(^\s*import\s+['"])(\.\.?\/[^'"]+?)\.ts(['"])/gm, '$1$2.js$3');
}

export function buildProject(outArg?: string, workspaceRoot = project): number {
  const base = resolve(workspaceRoot);
  const out = resolve(outArg ?? join(base, 'dist'));
  if (![join(base, 'dist'), join(base, '.build-test')].includes(out)) {
    throw new Error('Build output must be dist or .build-test inside the workspace');
  }
  try {
    if (lstatSync(out).isSymbolicLink()) throw new Error('Build output cannot be a link');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const srcRoot = join(base, 'src');
  const files = collectTsFiles(srcRoot);
  for (const relFile of files) {
    const source = readFileSync(join(srcRoot, relFile), 'utf8');
    let code = stripTypeScriptTypes(source, { mode: 'strip' });
    code = rewriteRelativeTsImports(code);
    if (relFile === 'cli.ts') code = '#!/usr/bin/env node\n' + code;
    const destPath = join(out, relFile.replace(/\.ts$/, '.js'));
    mkdirSync(dirname(destPath), { recursive: true });
    writeFileSync(destPath, code);
  }
  console.log(`Built ${files.length} files into ${out}`);
  return files.length;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(thisFile)) {
  buildProject(process.argv[2]);
}
