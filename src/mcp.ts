import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import pkg from '../package.json' with { type: 'json' };
import { safeErrorMessage } from './contracts.ts';
import { confine, tools } from './tools.ts';

const versions = ['2024-11-05', '2025-03-26', '2025-06-18'];

// Minimal MCP over newline-delimited JSON-RPC on stdio: only initialize, ping, notifications/cancelled and tools.
// Network tools exist only with allowNetwork; credentials never travel as arguments.
export function serveMcp(options: { root: string; allowNetwork: boolean; input: Readable; output: Writable }): Promise<void> {
  const path = confine(options.root);
  const available = tools.filter(t => options.allowNetwork || !t.network);
  const inFlight = new Map<string | number, AbortController>();
  const send = (message: unknown): void => { options.output.write(JSON.stringify(message) + '\n'); };
  const fail = (id: unknown, code: number, message: string) => send({ jsonrpc: '2.0', id, error: { code, message } });

  async function handle(message: any, controller?: AbortController) {
    if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') return fail(null, -32600, 'Invalid request');
    const { id, method, params } = message;
    if (id === undefined) return;
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
      const args = params?.arguments === undefined ? {} : params?.arguments;
      if (!tool || !args || typeof args !== 'object' || Array.isArray(args)
        || Object.keys(args).sort().join() !== Object.keys(tool.args).sort().join()
        || Object.values(args).some(v => typeof v !== 'string' || v.length > 1024)) return fail(id, -32602, 'Unknown tool or invalid arguments');
      if (controller?.signal.aborted) {
        return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'BBA: Operation cancelled' }], isError: true } });
      }
      try {
        const result = await tool.run(args as Record<string, string>, path, controller?.signal);
        return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }], isError: false } });
      } catch (error) {
        return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'BBA: ' + safeErrorMessage(error) }], isError: true } });
      }
    }
    return fail(id, -32601, 'Method not found');
  }

  return new Promise(resolve => {
    let queue = Promise.resolve();
    const lines = createInterface({ input: options.input });
    lines.on('line', line => {
      if (!line.trim()) return;
      let message: any;
      try { message = JSON.parse(line); } catch { fail(null, -32700, 'Parse error'); return; }
      if (message && typeof message === 'object' && !Array.isArray(message) && message.jsonrpc === '2.0') {
        if (message.id === undefined) {
          if (message.method === 'notifications/cancelled') {
            const requestId = message.params?.requestId;
            if (typeof requestId === 'string' || typeof requestId === 'number') inFlight.get(requestId)?.abort();
          }
          return;
        }
        if (message.method === 'ping' && (typeof message.id === 'string' || typeof message.id === 'number')) {
          send({ jsonrpc: '2.0', id: message.id, result: {} });
          return;
        }
        if (typeof message.id === 'string' || typeof message.id === 'number') {
          const id = message.id;
          const controller = new AbortController();
          inFlight.set(id, controller);
          queue = queue.then(() => handle(message, controller)).catch(() => {}).finally(() => { inFlight.delete(id); });
          return;
        }
      }
      queue = queue.then(() => handle(message)).catch(() => {});
    });
    lines.on('close', () => { queue.then(resolve); });
  });
}
