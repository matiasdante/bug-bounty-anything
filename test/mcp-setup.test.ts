import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setupCodexMcp } from '../src/mcp-setup.ts';

const available = spawnSync('codex', ['mcp', '--help'], { encoding: 'utf8', timeout: 10000 }).status === 0;

test('Codex MCP setup previews, backs up, registers offline tools and switches modes with explicit replacement',
  { skip: available ? false : 'Codex CLI is not installed' }, async () => {
    const runs = join(process.cwd(), 'runs');
    await mkdir(runs, { recursive: true });
    const home = await mkdtemp(join(runs, 'bba-codex-mcp-'));
    const prior = process.env.CODEX_HOME;
    process.env.CODEX_HOME = home;
    try {
      const original = 'model = "gpt-6.1-sol"\n';
      await writeFile(join(home, 'config.toml'), original);
      const preview = setupCodexMcp(home);
      assert.equal(preview.status, 'ready'); assert.equal(preview.networkTools, false);
      assert.equal(await readFile(join(home, 'config.toml'), 'utf8'), original);
      const installed = setupCodexMcp(home, true);
      assert.equal(installed.status, 'installed');
      assert.ok(installed.backup);
      assert.equal(await readFile(installed.backup!, 'utf8'), original);
      assert.match(await readFile(join(home, 'config.toml'), 'utf8'), /\[mcp_servers\.bba\]/);
      assert.equal(setupCodexMcp(home, true).status, 'already-present');
      assert.throws(() => setupCodexMcp(home, false, true), /differs/);
      assert.equal(setupCodexMcp(home, false, true, true).status, 'replace-ready');
      const active = setupCodexMcp(home, true, true, true);
      assert.equal(active.status, 'updated');
      assert.ok(active.backup);
      assert.match(await readFile(active.backup!, 'utf8'), /\[mcp_servers\.bba\]/);
      assert.equal(setupCodexMcp(home, false, true).status, 'already-present');
    } finally {
      if (prior === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = prior;
      await rm(home, { recursive: true, force: true });
    }
  });
