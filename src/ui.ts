import { createServer } from 'node:http';
import { existsSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { artifactView } from './artifacts.ts';
import { campaignStatus } from './campaign.ts';
import { inspectSession, readJson, sessionSummary } from './session.ts';
import type { Session } from './session.ts';
import type { Lang } from './i18n.ts';

export const INSPECTOR_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export function escapeHtml(raw: unknown): string {
  return String(raw ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderSessionTable(session: Session, lang: Lang): string {
  const sum = sessionSummary(session);
  const hdrs = lang === 'en'
    ? ['Step', 'Outcome', 'HTTP', 'Bytes', 'Response SHA-256', 'Facts / Redirect']
    : ['Paso', 'Resultado', 'HTTP', 'Bytes', 'SHA-256 respuesta', 'Hechos / Redirect'];
  const rows = session.attempts.map(a => {
    const facts = a.response?.facts?.map(f => `${f.name}:${f.kind}${f.sha256 ? '(' + f.sha256.slice(0, 10) + ')' : ''}`).join(', ') ?? '';
    const redir = a.response?.redirectClass ? `redirect:${a.response.redirectClass}(${a.response.redirectOrigin ?? '-'})` : '';
    const extra = [facts, redir].filter(Boolean).join(' · ') || '-';
    return `<tr>
      <td><code>${escapeHtml(a.stepId)}</code></td>
      <td>${escapeHtml(a.outcome)}${a.reason ? ` (<code>${escapeHtml(a.reason)}</code>)` : ''}</td>
      <td>${escapeHtml(a.response?.status ?? '-')}</td>
      <td>${escapeHtml(a.response?.bytes ?? '-')}</td>
      <td><code>${escapeHtml(a.response?.sha256 ? a.response.sha256.slice(0, 16) + '…' : '-')}</code></td>
      <td><code>${escapeHtml(extra)}</code></td>
    </tr>`;
  }).join('\n');

  const summaryTitle = lang === 'en' ? 'Session Checkpoints' : 'Checkpoints de sesión';
  const budgetLabel = lang === 'en' ? 'Budget consumed' : 'Presupuesto consumido';
  return `<section>
    <h2>${summaryTitle} — <code>${escapeHtml(session.id)}</code></h2>
    <p><strong>Status:</strong> <code>${escapeHtml(sum.status)}</code> · <strong>${budgetLabel}:</strong> ${sum.reservedRequests}/${sum.requestBudget} · <strong>Stop:</strong> <code>${escapeHtml(sum.stopReason ?? 'none')}</code></p>
    <table>
      <thead><tr>${hdrs.map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
      <tbody>${rows || `<tr><td colspan="6">-</td></tr>`}</tbody>
    </table>
  </section>`;
}

export function renderInspectorHtml(folder: string, lang: Lang = 'es'): string {
  const target = resolve(folder);
  if (!existsSync(target) || !statSync(target).isDirectory()) {
    throw new Error('Inspector target must be an existing directory');
  }
  const title = lang === 'en'
    ? `BBA Local Evidence Inspector — ${basename(target)}`
    : `BBA Inspector Local de Evidencia — ${basename(target)}`;
  const sections: string[] = [];

  if (existsSync(join(target, 'campaign.json'))) {
    const status = campaignStatus(target);
    sections.push(`<section>
      <h2>${lang === 'en' ? 'Campaign Ledger' : 'Expediente de campaña'}</h2>
      <pre>${escapeHtml(JSON.stringify(status, null, 2))}</pre>
    </section>`);
  }

  if (existsSync(join(target, 'session.sqlite'))) {
    sections.push(renderSessionTable(inspectSession(target), lang));
  } else if (existsSync(join(target, 'run', 'session.sqlite'))) {
    sections.push(renderSessionTable(inspectSession(join(target, 'run')), lang));
  }

  if (existsSync(join(target, 'artifact.json'))) {
    const summary = artifactView(target, { kind: 'summary', offset: 0, limit: 10 });
    const events = artifactView(target, { kind: 'events', offset: 0, limit: 50 });
    sections.push(`<section>
      <h2>${lang === 'en' ? 'Sealed Artifact' : 'Artefacto sellado'} — <code>${escapeHtml(summary.artifactKind)}</code></h2>
      <p><strong>ID:</strong> <code>${escapeHtml(summary.parentEvidenceId)}</code> · <strong>Revision:</strong> <code>${escapeHtml(String(summary.revisionDigest).slice(0, 16))}…</code> · <strong>Events:</strong> ${escapeHtml(summary.events)}</p>
      <pre>${escapeHtml(JSON.stringify(events.items, null, 2))}</pre>
    </section>`);
  }

  const jsonFiles = readdirSync(target)
    .filter(f => f.endsWith('.json') && !['scope.json', 'plan.json', 'artifact.json', 'campaign.json'].includes(f))
    .sort()
    .slice(0, 8);
  for (const name of jsonFiles) {
    try {
      const parsed = readJson(join(target, name));
      sections.push(`<section>
        <h2><code>${escapeHtml(name)}</code></h2>
        <pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
      </section>`);
    } catch {
      // Ignora archivos mayores a 1 MiB o no JSON
    }
  }

  const note = lang === 'en'
    ? 'Read-only local view bound to 127.0.0.1. Raw credentials, cookies and response bodies are never persisted by BBA.'
    : 'Vista local de solo lectura en 127.0.0.1. BBA nunca persiste credenciales, cookies ni cuerpos crudos.';

  return `<!doctype html>
<html lang="${escapeHtml(lang)}">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(INSPECTOR_CSP)}">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #16181d; background: #f8f9fb; line-height: 1.45; }
    header { border-bottom: 2px solid #d0d5dd; margin-bottom: 1.5rem; padding-bottom: 0.75rem; }
    h1 { font-size: 1.35rem; margin: 0 0 0.35rem 0; }
    h2 { font-size: 1.05rem; margin: 0 0 0.6rem 0; }
    section { background: #ffffff; border: 1px solid #d0d5dd; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th, td { border-bottom: 1px solid #eaecf0; text-align: left; padding: 0.45rem 0.5rem; vertical-align: top; }
    th { background: #f2f4f7; font-weight: 600; }
    pre { background: #f2f4f7; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.82rem; margin: 0; }
    code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.85em; }
    .note { color: #475467; font-size: 0.88rem; margin: 0; }
  </style>
</head>
<body>
  <header>
    <h1>${escapeHtml(title)}</h1>
    <p class="note">${escapeHtml(note)}</p>
  </header>
  ${sections.join('\n') || `<section><p>${escapeHtml(lang === 'en' ? 'No recognized artifacts in directory.' : 'Sin artefactos reconocidos en el directorio.')}</p></section>`}
</body>
</html>
`;
}

export function exportInspectorHtml(folder: string, outputPath: string, lang: Lang = 'es'): { output: string; bytes: number } {
  const html = renderInspectorHtml(folder, lang);
  const out = resolve(outputPath);
  writeFileSync(out, html, { flag: 'wx', mode: 0o600 });
  return { output: out, bytes: Buffer.byteLength(html, 'utf8') };
}

export async function startInspectorServer(
  folder: string,
  options: { port?: number; lang?: Lang; signal?: AbortSignal } = {},
): Promise<{ origin: string; port: number; close: () => Promise<void> }> {
  const target = resolve(folder);
  const lang = options.lang ?? 'es';
  // Valida que el directorio se pueda renderizar antes de abrir el puerto local.
  renderInspectorHtml(target, lang);

  const server = createServer((req, res) => {
    const commonHeaders = {
      'Content-Security-Policy': INSPECTOR_CSP,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...commonHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed\n');
      return;
    }
    const urlPath = (req.url ?? '/').split('?')[0];
    if (urlPath === '/healthz') {
      res.writeHead(200, { ...commonHeaders, 'Content-Type': 'application/json; charset=utf-8' });
      res.end(req.method === 'HEAD' ? undefined : JSON.stringify({ ok: true }));
      return;
    }
    if (urlPath !== '/') {
      res.writeHead(404, { ...commonHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found\n');
      return;
    }
    try {
      const body = renderInspectorHtml(target, lang);
      res.writeHead(200, { ...commonHeaders, 'Content-Type': 'text/html; charset=utf-8' });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      res.writeHead(500, { ...commonHeaders, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Inspector render failed\n');
    }
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(options.port ?? 0, '127.0.0.1', () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });

  const addr = server.address() as { port: number };
  const close = () => new Promise<void>(r => {
    server.closeAllConnections();
    server.close(() => r());
  });
  if (options.signal) {
    if (options.signal.aborted) {
      await close();
      throw new Error('cancelled');
    }
    options.signal.addEventListener('abort', () => { void close(); }, { once: true });
  }
  return { origin: `http://127.0.0.1:${addr.port}`, port: addr.port, close };
}
