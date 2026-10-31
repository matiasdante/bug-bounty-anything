import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, lstatSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Node refuses to strip types inside node_modules, so an installed package must ship plain JS.
const project = dirname(dirname(fileURLToPath(import.meta.url)));
const out = resolve(process.argv[2] ?? join(project, 'dist'));
if (![join(project, 'dist'), join(project, '.build-test')].includes(out)) throw new Error('Build output must be dist or .build-test inside the workspace');
try { if (lstatSync(out).isSymbolicLink()) throw new Error('Build output cannot be a link'); }
catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const file of readdirSync(join(project, 'src')).filter(f => f.endsWith('.ts'))) {
  let code = stripTypeScriptTypes(readFileSync(join(project, 'src', file), 'utf8'), { mode: 'strip' });
  code = code.replace(/(['"])(\.\/[\w-]+)\.ts\1/g, '$1$2.js$1');
  if (file === 'cli.ts') code = '#!/usr/bin/env node\n' + code;
  writeFileSync(join(out, file.replace(/\.ts$/, '.js')), code);
}
console.log(`Built ${readdirSync(out).length} files into ${out}`);
