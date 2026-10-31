import pkg from '../package.json' with { type: 'json' };
import { methods } from './scope.ts';
import { semanticClasses } from './semantic.ts';

export function capabilities() {
  return { version: pkg.version,
    transport: { methods, bodyFormats: ['json', 'form', 'text'], query: 'explicit-name-rules-and-environment-values', redirects: 'stop', retries: false,
      persistence: 'durable-reservations-and-resumable-static-plans', inputIntegrity: 'session-bound-digest' },
    confirmation: [...semanticClasses.map(name => ({ name, requires: 'declared policy, server identities and projected protected data; GET only' })),
      { name: 'xss', requires: 'baseline/probe URL inputs, opaque marker execution in Chromium and declared untrusted-input context' },
      { name: 'cors', requires: 'anonymous denial, protected baseline, actual cookie delivery and foreign-origin read in Chromium' },
      { name: 'jwt-signature-integrity', requires: 'signed JWT from one controlled account, anonymous denial, stable protected fact, altered payload with unchanged signature; four bounded requests' }],
    inputProofs: [
      { name: 'template-arithmetic', requires: 'one exact authorized query field, literal-input policy and two harmless independent arithmetic expressions; three GET requests' },
      { name: 'outbound-fetch', requires: 'one exact authorized URL-fetch field, operator-owned opaque callback and before/after receipt; at most four GET requests' },
      { name: 'cross-identity-cache', requires: 'two controlled identities, anonymous denial, declared semantically inert bust parameter and same private URL; seven GET requests' },
      { name: 'single-use-race', requires: 'two disposable owned resources, sequential denial control, exactly two concurrent JSON POST actions, final count and zero interval; at most seven requests' },
      { name: 'cross-origin-form', requires: 'owned reversible state, anonymous denial, actual Chromium form POST with test cookie, distinct attacker origin and before/after state; at most five requests' },
    ],
    discovery: ['offline HAR/Swagger 2.0/OpenAPI 3.x/REA projection', 'isolated browser capture with bounded DOM route/form/script facts', 'in-scope HTML href hunt', 'surface-to-policy hypothesis planning'],
    browserWorkflows: { actions: ['navigate', 'fill', 'click', 'wait'], requests: 'exact URL/method/body allowlist', redirects: 'explicit declared destinations, at most five', sessions: 'in-memory browser cookies/rotation; no browser-session resume' },
    evidence: ['stable session/step/field IDs', 'revision-bound pages', 'JSON pointer facts without raw values', 'cross-run metadata/field comparison'],
    integrations: { rea: 'offline capture import and agent handoff', zap: 'offline import', nuclei: 'offline import', subfinder: 'offline import' },
    mcpConnection: { client: 'Codex CLI registration via setup-mcp', default: 'offline tools only', active: 'requires explicit --allow-network at registration and a valid per-target scope' },
    publishedCases: { supported: ['faav-titan-jwt-2026'], workflow: 'offline case/policy/surface/historical/profile assembly and provenance graph; one exact JWT proof and five-question draft report' },
    limitations: ['No generic scanner or universal vulnerability coverage.', 'JWT integrity checks establish acceptance only for an owned test account and one declared mutation; they do not map privileged identities or prove access to other datasets.', 'Template arithmetic, owned callback, cache, single-use race and cross-origin form checks cover only their declared proof modes; SQL/NoSQL/command injection and internal SSRF remain unsupported.', 'CSRF classification additionally requires that the declared attacker origin is genuinely cross-site; loopback tests across ports prove only cross-origin behavior.', 'No generic login inference, dynamic unbound form inputs, arbitrary browser code or live third-party scanner execution.',
      'Published-case workflow currently supports one Titan-style JWT signature hypothesis and a single selected operation; historical hints are leads, not evidence of present behavior.',
      'scope.budgetId shares a durable budget near the canonical scope file across CLI/MCP phases. Legacy scopes remain per-run; external tools are not automatically charged.', 'Scopes and business rules are operator assertions, not cryptographically verified permissions.',
      'MCP tools/list is authoritative for the connected server; network tools require --allow-network.'] };
}
