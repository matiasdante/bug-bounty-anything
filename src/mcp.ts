import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import pkg from '../package.json' with { type: 'json' };
import { confine, tools } from './tools.ts';

const versions = ['2024-11-05', '2025-03-26', '2025-06-18'];

// Same filter as the CLI: never echo hostile imported content or secrets.
const safe = (error: unknown) => {
  const known = error instanceof Error ? error.message : 'Unknown error';
  return /^[A-Za-z0-9 .;:'()/-]{1,160}$/.test(known) ? known : 'Operation failed; check arguments and local artifact integrity';
};

// Minimal MCP over newline-delimited JSON-RPC on stdio: only initialize, ping and tools.
// Network tools exist only with allowNetwork; credentials never travel as arguments.
export function serveMcp(options: { root: string; allowNetwork: boolean; input: Readable; output: Writable }): Promise<void> {
  const path = confine(options.root);
  const available = tools.filter(t => options.allowNetwork || !t.network);
  const send = (message: unknown): void => { options.output.write(JSON.stringify(message) + '\n'); };
  const fail = (id: unknown, code: number, message: string) => send({ jsonrpc: '2.0', id, error: { code, message } });

  async function handle(message: any) {
    if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') return fail(null, -32600, 'Invalid request');
    const { id, method, params } = message;
    if (id === undefined) return; // Notifications such as notifications/initialized need no answer.
    if (typeof id !== 'string' && typeof id !== 'number') return fail(null, -32600, 'Invalid request');
    if (method === 'initialize') {
      const requested = params?.protocolVersion;
      return send({ jsonrpc: '2.0', id, result: { protocolVersion: versions.includes(requested) ? requested : versions.at(-1),
        capabilities: { tools: {} }, serverInfo: { name: 'bba', version: pkg.version } } });
    }
    if (method === 'ping') return send({ jsonrpc: '2.0', id, result: {} });
    if (method === 'tools/list') {
      return send({ jsonrpc: '2.0', id, result: { tools: available.map(t => ({ name: t.name, description: t.description,
        inputSchema: { type: 'object', additionalProperties: false, required: Object.keys(t.args),
          properties: Object.fromEntries(Object.entries(t.args).map(([key, description]) => [key, { type: 'string', description, maxLength: 1024 }])) } })) } });
    }
    if (method === 'tools/call') {
      const tool = available.find(t => t.name === params?.name);
      const args = params?.arguments;
      if (!tool || !args || typeof args !== 'object' || Array.isArray(args)
        || Object.keys(args).sort().join() !== Object.keys(tool.args).sort().join()
        || Object.values(args).some(v => typeof v !== 'string' || v.length > 1024)) return fail(id, -32602, 'Unknown tool or invalid arguments');
      try {
        const result = await tool.run(args as Record<string, string>, path);
        return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }], isError: false } });
      } catch (error) {
        return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'BBA: ' + safe(error) }], isError: true } });
      }
    }
    return fail(id, -32601, 'Method not found');
  }

  return new Promise(resolve => {
    let queue = Promise.resolve(); // Requests are answered in order, one at a time.
    const lines = createInterface({ input: options.input });
    lines.on('line', line => {
      if (!line.trim()) return;
      let message: unknown;
      try { message = JSON.parse(line); } catch { fail(null, -32700, 'Parse error'); return; }
      queue = queue.then(() => handle(message)).catch(() => {});
    });
    lines.on('close', () => { queue.then(resolve); });
  });
}
