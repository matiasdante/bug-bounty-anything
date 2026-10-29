import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join } from 'node:path';

// Node refuses to strip types inside node_modules, so an installed package must ship plain JS.
const out = process.argv[2] ?? 'dist';
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const file of readdirSync('src').filter(f => f.endsWith('.ts'))) {
  let code = stripTypeScriptTypes(readFileSync(join('src', file), 'utf8'), { mode: 'strip' });
  code = code.replace(/(['"])(\.\/[\w-]+)\.ts\1/g, '$1$2.js$1');
  if (file === 'cli.ts') code = '#!/usr/bin/env node\n' + code;
  writeFileSync(join(out, file.replace(/\.ts$/, '.js')), code);
}
console.log(`Built ${readdirSync(out).length} files into ${out}`);
