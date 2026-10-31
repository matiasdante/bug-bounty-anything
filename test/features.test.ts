import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { createServer as createHttp2Server } from 'node:http2';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Scope } from '../src/scope.ts';
import { createSession } from '../src/session.ts';
import { executeSession } from '../src/execution.ts';
import { investigateSurface } from '../src/planner.ts';
import { importSurface } from '../src/surface.ts';
import { graphqlCheck } from '../src/graphql-check.ts';
import { jwtIntegrityCheck, mutateOwnedJwt } from '../src/jwt-integrity.ts';
import { oauthCheck } from '../src/oauth-check.ts';
import { redirectCheck } from '../src/redirect-check.ts';
import { bootstrapCredentials } from '../src/auth-bootstrap.ts';
import { importPolicyFile } from '../src/policy-import.ts';
import { importCandidatesFile } from '../src/candidates.ts';
import { planCandidatesFile } from '../src/candidate-planner.ts';
import { calculateCvss31, exportSubmission } from '../src/report-platform.ts';
import { raceCheck } from '../src/race-check.ts';
import { generateSigningKeypair, signEvidence, verifyEvidenceSignature } from '../src/signing.ts';
import { INSPECTOR_CSP, renderInspectorHtml, startInspectorServer } from '../src/ui.ts';

function makeWindow() {
  return {
    reference: 'BBA Block 3 feature test suite',
    validFrom: new Date(Date.now() - 10_000).toISOString(),
    validUntil: new Date(Date.now() + 600_000).toISOString(),
  };
}

function makeLimits(maxRequests = 20, minIntervalMs = 0) {
  return {
    maxRequests,
    minIntervalMs,
    timeoutMs: 4000,
    maxResponseBytes: 65536,
    maxDurationMs: 60000,
  };
}

function signTestJwt(payload: Record<string, unknown>, secret = 'lab-jwt-hmac-secret'): string {
  const hdr = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const pld = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(`${hdr}.${pld}`).digest('base64url');
  return `${hdr}.${pld}.${sig}`;
}

async function listAllFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await listAllFiles(full));
    else out.push(full);
  }
  return out;
}

test('Feature #1: semantic write/mass-assignment confirms unauthorized state mutation and rejects fixed handler', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat1-'));
  let vulnerable = true;
  let itemTier = 'standard';

  const srv = createServer((req, res) => {
    const auth = req.headers.authorization;
    if (req.method === 'GET' && req.url === '/api/me') {
      if (auth === 'Bearer tok-owner') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'u-owner', role: 'admin' }));
        return;
      }
      if (auth === 'Bearer tok-other') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'u-other', role: 'member' }));
        return;
      }
      res.writeHead(401).end();
      return;
    }
    if (req.url === '/api/account/plan') {
      if (!auth) { res.writeHead(401).end(); return; }
      if (req.method === 'GET') {
        if (auth !== 'Bearer tok-owner') { res.writeHead(403).end(); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ownerId: 'u-owner', tier: itemTier }));
        return;
      }
      if (req.method === 'PATCH') {
        let raw = '';
        req.on('data', c => { raw += c; });
        req.on('end', () => {
          if (!vulnerable && auth !== 'Bearer tok-owner') {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'denied' }));
            return;
          }
          const body = JSON.parse(raw);
          if (typeof body.tier === 'string') itemTier = body.tier;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        });
        return;
      }
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: makeWindow(),
      allowed: [{ origin, paths: ['/api/me', '/api/account/plan'] }],
      excluded: [],
      requestRules: [{ origin, path: '/api/account/plan', method: 'PATCH', queryNames: [], bodyFormats: ['json'] }],
      limits: makeLimits(10),
    };
    const surface = importSurface({
      openapi: '3.0.3',
      servers: [{ url: origin }],
      paths: { '/api/account/plan': { patch: { responses: { '200': { description: 'ok' } } } } },
    }, 'openapi');
    const surfaceBundle = { surface, sha256: (await import('../src/contracts.ts')).digest(surface) };
    const profile = {
      schemaVersion: 1,
      accounts: ['BBA_TOKEN_OWNER', 'BBA_TOKEN_OTHER'],
      identity: { url: `${origin}/api/me`, fact: 'uid', observe: [{ name: 'uid', pointer: '/id' }, { name: 'role', pointer: '/role' }] },
      rules: [{
        class: 'mass-assignment',
        method: 'PATCH',
        origin,
        pathPrefix: '/api/account',
        protectedPointer: '/tier',
        subjectPointer: '/ownerId',
        query: [],
        body: { format: 'json', valueEnv: 'BBA_BODY_PATCH_TIER' },
        policy: { reference: 'Account tier write boundary', boundary: 'owner-only', ownerFact: 'owner' },
      }],
    };
    const creds = {
      BBA_TOKEN_OWNER: 'tok-owner',
      BBA_TOKEN_OTHER: 'tok-other',
      BBA_BODY_PATCH_TIER: JSON.stringify({ tier: 'enterprise' }),
    };

    const vulnRes = await investigateSurface(join(dir, 'vuln'), scope, surfaceBundle, profile, { credentials: creds });
    assert.equal(vulnRes.findings.length, 1);
    assert.equal(vulnRes.findings[0].status, 'confirmed');

    // Reset state and verify fixed variant returns not-reproduced
    vulnerable = false;
    itemTier = 'standard';
    const fixedRes = await investigateSurface(join(dir, 'fixed'), scope, surfaceBundle, profile, { credentials: creds });
    assert.equal(fixedRes.findings.length, 1);
    assert.equal(fixedRes.findings[0].status, 'not-reproduced');
  } finally {
    srv.closeAllConnections();
    await new Promise<void>(r => srv.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #2 & #9: GraphQL SDL/introspection + JS/SourceMap surface import and active graphqlCheck', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat2-'));

  const sdlSurface = importSurface(`
    type Query {
      invoice(id: ID!): Invoice
      me: User
    }
    type Mutation {
      updateInvoice(id: ID!, total: Int!): Invoice
    }
  `, 'graphql');
  assert.equal(sdlSurface.entries.length, 3);
  assert.ok(sdlSurface.entries.some(e => e.parameters.some(p => p.name === 'op.query.invoice')));

  const jsSurface = importSurface({
    version: 3,
    sources: ['api.ts'],
    sourcesContent: [
      'export const loadOrder = (id) => fetch(`/api/v1/orders/${id}?expand=items`);\n'
      + 'export const pay = () => axios.post("/api/v1/orders/pay", {});',
    ],
  }, 'js-bundle');
  assert.equal(jsSurface.entries.length, 2);
  assert.ok(jsSurface.entries.some(e => e.path === '/api/v1/orders/{param}' && e.method === 'GET' && e.parameters.some(p => p.name === 'expand')));
  assert.ok(jsSurface.entries.some(e => e.path === '/api/v1/orders/pay' && e.method === 'POST'));

  let vulnerable = true;
  const srv = createServer((req, res) => {
    const auth = req.headers.authorization;
    if (req.method === 'GET' && req.url === '/me') {
      if (auth === 'Bearer tok-alice') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'alice' }));
        return;
      }
      if (auth === 'Bearer tok-bob') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'bob' }));
        return;
      }
      res.writeHead(401).end();
      return;
    }
    if (req.method === 'POST' && req.url === '/graphql') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (!auth) {
        res.end(JSON.stringify({ data: { invoice: null }, errors: [{ message: 'Unauthenticated' }] }));
        return;
      }
      if (!vulnerable && auth !== 'Bearer tok-alice') {
        res.end(JSON.stringify({ data: { invoice: null }, errors: [{ message: 'Forbidden' }] }));
        return;
      }
      res.end(JSON.stringify({ data: { invoice: { ownerId: 'alice', secretCode: 'INV-SECRET-991' } } }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: makeWindow(),
      allowed: [{ origin, paths: ['/me', '/graphql'] }],
      excluded: [],
      requestRules: [{ origin, path: '/graphql', method: 'POST', queryNames: [], bodyFormats: ['json'] }],
      limits: makeLimits(10),
    };
    const cfg = {
      schemaVersion: 1 as const,
      class: 'graphql-authorization' as const,
      policyReference: 'Invoice owner-only GraphQL resolver',
      accounts: ['BBA_TOKEN_ALICE', 'BBA_TOKEN_BOB'] as [string, string],
      identity: { url: `${origin}/me`, fact: 'uid', observe: [{ name: 'uid', pointer: '/id' }] },
      endpointUrl: `${origin}/graphql`,
      query: 'query GetInvoice($id: ID!) { invoice(id: $id) { ownerId secretCode } }',
      operationName: 'GetInvoice',
      variables: { id: 'inv-1' },
      protectedPointer: '/data/invoice/secretCode',
      subjectPointer: '/data/invoice/ownerId',
      policy: { reference: 'Invoice owner rule', boundary: 'owner-only' as const, ownerFact: 'owner' },
    };
    const creds = { BBA_TOKEN_ALICE: 'tok-alice', BBA_TOKEN_BOB: 'tok-bob' };

    const vuln = await graphqlCheck(join(dir, 'gql-vuln'), scope, cfg, { credentials: creds });
    assert.equal(vuln.status, 'confirmed');

    vulnerable = false;
    const fixed = await graphqlCheck(join(dir, 'gql-fixed'), scope, cfg, { credentials: creds });
    assert.equal(fixed.status, 'not-reproduced');
  } finally {
    srv.closeAllConnections();
    await new Promise<void>(r => srv.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #3 & #5: JWT alg-none/expired-token, OAuth redirect_uri conformance and open-redirect checks', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat35-'));
  const validJwt = signTestJwt({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) + 3600 });
  const freshNotExpired = signTestJwt({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) + 7200 });

  let acceptUnsigned = true;
  let oauthVulnerable = true;
  let redirectVulnerable = true;

  const srv = createServer((req, res) => {
    const parsed = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (parsed.pathname === '/jwt-protected') {
      const auth = req.headers.authorization;
      if (!auth?.startsWith('Bearer ')) { res.writeHead(401).end(); return; }
      const tok = auth.slice(7);
      if (tok === validJwt || (acceptUnsigned && tok.endsWith('.'))) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ secret: 'jwt-protected-fact-value' }));
        return;
      }
      res.writeHead(401).end();
      return;
    }
    if (parsed.pathname === '/oauth/authorize') {
      const redir = parsed.searchParams.get('redirect_uri') ?? '';
      if (redir === 'https://client.example/cb' || oauthVulnerable) {
        res.writeHead(302, { Location: `${redir}?code=SENSITIVE_AUTH_CODE_999&state=s` });
        res.end();
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'invalid_redirect_uri' }));
      return;
    }
    if (parsed.pathname === '/go') {
      const next = parsed.searchParams.get('next') ?? '/';
      if (next.startsWith('/') && !next.startsWith('//')) {
        res.writeHead(302, { Location: next }).end();
        return;
      }
      if (redirectVulnerable) {
        res.writeHead(302, { Location: `${next}?leaked=NEVER_PERSIST_QUERY` }).end();
        return;
      }
      res.writeHead(302, { Location: '/safe' }).end();
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: makeWindow(),
      allowed: [{ origin, paths: ['/jwt-protected', '/oauth/authorize', '/go'] }],
      excluded: [],
      requestRules: [
        { origin, path: '/oauth/authorize', method: 'GET', queryNames: ['client_id', 'redirect_uri', 'response_type', 'state'], bodyFormats: [] },
        { origin, path: '/go', method: 'GET', queryNames: ['next'], bodyFormats: [] },
      ],
      limits: makeLimits(10),
    };

    // Negative check: expired-token mode rejects a non-expired valueEnv JWT
    assert.throws(() => mutateOwnedJwt(validJwt, {
      schemaVersion: 1,
      policyReference: 'JWT exp check',
      boundary: 'jwt-signature-integrity',
      url: `${origin}/jwt-protected`,
      request: { method: 'GET' },
      credentialEnv: 'BBA_TOKEN_MAIN',
      proofPointer: '/secret',
      mutation: { mode: 'expired-token', valueEnv: 'BBA_TOKEN_OLD' },
    }, { BBA_TOKEN_MAIN: validJwt, BBA_TOKEN_OLD: freshNotExpired }), /not expired/);

    // alg-none positive & negative
    const jwtCfg = {
      schemaVersion: 1 as const,
      policyReference: 'JWT alg-none rejection policy',
      boundary: 'jwt-signature-integrity' as const,
      url: `${origin}/jwt-protected`,
      request: { method: 'GET' as const },
      credentialEnv: 'BBA_TOKEN_MAIN',
      proofPointer: '/secret',
      mutation: { mode: 'alg-none' as const },
    };
    const jwtVuln = await jwtIntegrityCheck(join(dir, 'jwt-vuln'), scope, jwtCfg, { environment: { BBA_TOKEN_MAIN: validJwt } });
    assert.equal(jwtVuln.status, 'confirmed');
    acceptUnsigned = false;
    const jwtFixed = await jwtIntegrityCheck(join(dir, 'jwt-fixed'), scope, jwtCfg, { environment: { BBA_TOKEN_MAIN: validJwt } });
    assert.equal(jwtFixed.status, 'not-reproduced');

    // OAuth redirect_uri conformance positive & negative + zero query/code persistence
    const oauthCfg = {
      schemaVersion: 1 as const,
      class: 'oauth-flow-conformance' as const,
      policyReference: 'RFC 9700 exact redirect_uri match',
      authorizeUrl: `${origin}/oauth/authorize`,
      clientId: 'owned-client-1',
      validRedirectUri: 'https://client.example/cb',
      unapprovedRedirectUri: 'https://attacker.example/steal',
      credentialEnv: null,
    };
    const oauthVuln = await oauthCheck(join(dir, 'oauth-vuln'), scope, oauthCfg);
    assert.equal(oauthVuln.status, 'confirmed');
    oauthVulnerable = false;
    const oauthFixed = await oauthCheck(join(dir, 'oauth-fixed'), scope, oauthCfg);
    assert.equal(oauthFixed.status, 'not-reproduced');

    // Open-redirect positive & negative
    const redirCfg = {
      schemaVersion: 1 as const,
      class: 'open-redirect' as const,
      policyReference: 'Login redirect allowlist',
      url: `${origin}/go`,
      parameter: 'next',
      relativeControlTarget: '/dashboard',
      externalProbeTarget: 'https://evil-redirect.example/landing',
      credentialEnv: null,
    };
    const redirVuln = await redirectCheck(join(dir, 'redir-vuln'), scope, redirCfg);
    assert.equal(redirVuln.status, 'confirmed');
    redirectVulnerable = false;
    const redirFixed = await redirectCheck(join(dir, 'redir-fixed'), scope, redirCfg);
    assert.equal(redirFixed.status, 'not-reproduced');

    // Ensure sensitive Location query values (SENSITIVE_AUTH_CODE_999, NEVER_PERSIST_QUERY) never hit disk
    for (const f of await listAllFiles(dir)) {
      const bytes = await readFile(f);
      assert.equal(bytes.includes(Buffer.from('SENSITIVE_AUTH_CODE_999')), false, f);
      assert.equal(bytes.includes(Buffer.from('NEVER_PERSIST_QUERY')), false, f);
    }
  } finally {
    srv.closeAllConnections();
    await new Promise<void>(r => srv.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #4: ephemeral authBootstrap acquires tokens and cookies in memory with zero disk persistence', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat4-'));
  const secretToken = 'ephemeral-boot-token-887766';
  const secretCookie = 'boot_sid=ephemeral-cookie-554433';

  const srv = createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/auth/token') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { accessToken: secretToken } }));
      return;
    }
    if (req.method === 'POST' && req.url === '/auth/cookie') {
      res.writeHead(200, { 'Set-Cookie': `${secretCookie}; HttpOnly; Path=/`, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method === 'GET' && req.url === '/api/protected') {
      if (req.headers.authorization === `Bearer ${secretToken}` || req.headers.cookie === secretCookie) {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(401).end();
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: makeWindow(),
      allowed: [{ origin, paths: ['/auth/token', '/auth/cookie', '/api/protected'] }],
      excluded: [],
      requestRules: [
        { origin, path: '/auth/token', method: 'POST', queryNames: [], bodyFormats: ['json'] },
        { origin, path: '/auth/cookie', method: 'POST', queryNames: [], bodyFormats: ['json'] },
      ],
      limits: makeLimits(10),
    };
    const bootRes = await bootstrapCredentials(scope, {
      schemaVersion: 1,
      accounts: [
        { targetEnv: 'BBA_TOKEN_BOOT', url: `${origin}/auth/token`, request: { method: 'POST', body: { format: 'json', valueEnv: 'BBA_BODY_LOGIN' } }, extract: { from: 'json-pointer', pointer: '/data/accessToken' } },
        { targetEnv: 'BBA_COOKIE_BOOT', url: `${origin}/auth/cookie`, request: { method: 'POST', body: { format: 'json', valueEnv: 'BBA_BODY_LOGIN' } }, extract: { from: 'set-cookie', cookieNames: ['boot_sid'] } },
      ],
    }, { environment: { BBA_BODY_LOGIN: JSON.stringify({ user: 'owned' }) } });

    assert.equal(bootRes.requestsSent, 2);
    createSession(join(dir, 'run'), scope, {
      schemaVersion: 1,
      steps: [
        { id: 's1', method: 'GET', url: `${origin}/api/protected`, credentialEnv: 'BBA_TOKEN_BOOT' },
        { id: 's2', method: 'GET', url: `${origin}/api/protected`, credentialEnv: 'BBA_COOKIE_BOOT' },
      ],
    });
    const session = await executeSession(join(dir, 'run'), scope, { credentials: bootRes.credentials });
    assert.equal(session.status, 'completed');

    for (const f of await listAllFiles(dir)) {
      const raw = await readFile(f);
      assert.equal(raw.includes(Buffer.from(secretToken)), false, f);
      assert.equal(raw.includes(Buffer.from('ephemeral-cookie-554433')), false, f);
    }
  } finally {
    srv.closeAllConnections();
    await new Promise<void>(r => srv.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #6 & #7: policy-import quarantines wildcards and candidate-planner compiles bounded checks', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat67-'));
  try {
    const h1Policy = {
      relationships: {
        structured_scopes: {
          data: [
            { attributes: { asset_identifier: 'https://api.acme.example/v1/*', asset_type: 'URL', eligible_for_submission: true } },
            { attributes: { asset_identifier: '*.acme.example', asset_type: 'WILDCARD', eligible_for_submission: true } },
            { attributes: { asset_identifier: 'https://status.acme.example/', asset_type: 'URL', eligible_for_submission: false } },
          ],
        },
      },
    };
    const policyPath = join(dir, 'h1.json');
    await writeFile(policyPath, JSON.stringify(h1Policy));
    const polSummary = importPolicyFile(policyPath, 'hackerone', join(dir, 'policy-out'));
    assert.equal(polSummary.draftGenerated, true);
    assert.equal(polSummary.allowedOrigins, 1);
    assert.equal(polSummary.excludedOrigins, 1);
    assert.deepEqual(polSummary.manualReviewWildcards, ['*.acme.example']);

    const draftScope = JSON.parse(await readFile(join(dir, 'policy-out', 'scope.draft.json'), 'utf8')) as Scope;
    assert.deepEqual(draftScope.allowed[0].pathPrefixes, ['/v1']);
    assert.equal(JSON.stringify(draftScope.allowed).includes('*'), false);

    // Import Nuclei + Subfinder leads and compile into bounded plan.json + checks.draft.json
    const nucleiPath = join(dir, 'nuclei.jsonl');
    await writeFile(nucleiPath, [
      JSON.stringify({ 'template-id': 'api-lead', info: { name: 'Invoice endpoint', severity: 'medium' }, 'matched-at': 'https://api.acme.example/v1/invoices' }),
      JSON.stringify({ 'template-id': 'oos-lead', info: { name: 'Status page', severity: 'low' }, 'matched-at': 'https://status.acme.example/' }),
    ].join('\n') + '\n');
    const candsPath = join(dir, 'candidates.json');
    importCandidatesFile(nucleiPath, 'nuclei', draftScope, candsPath);

    const planSum = planCandidatesFile(join(dir, 'policy-out', 'scope.draft.json'), candsPath, join(dir, 'compiled'));
    assert.equal(planSum.plannedChecks, 1);
    assert.equal(planSum.plannedRequests, 3);
    assert.equal(planSum.skipped.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #10: raceCheck with HTTP/2 single-connection multiplexing confirms race over a single session', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat10-'));
  let sessionsOpened = 0;
  let vulnerable = true;
  const counts: Record<string, number> = { 'ctrl-res-01': 0, 'race-res-02': 0 };

  const h2 = createHttp2Server();
  h2.on('session', () => { sessionsOpened++; });
  h2.on('stream', (stream, headers) => {
    const method = headers[':method'];
    const path = headers[':path'];
    if (method === 'GET' && path === '/state/ctrl') {
      stream.respond({ ':status': 200, 'content-type': 'application/json' });
      stream.end(JSON.stringify({ redeemed: counts['ctrl-res-01'] }));
      return;
    }
    if (method === 'GET' && path === '/state/race') {
      stream.respond({ ':status': 200, 'content-type': 'application/json' });
      stream.end(JSON.stringify({ redeemed: counts['race-res-02'] }));
      return;
    }
    if (method === 'POST' && path === '/redeem') {
      let raw = '';
      stream.on('data', chunk => { raw += chunk; });
      stream.on('end', async () => {
        const { coupon } = JSON.parse(raw) as { coupon: string };
        const current = counts[coupon] ?? 0;
        if (!vulnerable) {
          if (current >= 1) {
            stream.respond({ ':status': 409, 'content-type': 'application/json' });
            stream.end(JSON.stringify({ error: 'already_used' }));
            return;
          }
          counts[coupon] = current + 1;
          await new Promise(r => setTimeout(r, 15));
          stream.respond({ ':status': 200, 'content-type': 'application/json' });
          stream.end(JSON.stringify({ ok: true }));
          return;
        }
        // Vulnerable TOCTOU window: reads 0 before awaiting, then increments
        if (current >= 1) {
          stream.respond({ ':status': 409, 'content-type': 'application/json' });
          stream.end(JSON.stringify({ error: 'already_used' }));
          return;
        }
        await new Promise(r => setTimeout(r, 25));
        counts[coupon] = (counts[coupon] ?? 0) + 1;
        stream.respond({ ':status': 200, 'content-type': 'application/json' });
        stream.end(JSON.stringify({ ok: true }));
      });
      return;
    }
    stream.respond({ ':status': 404 });
    stream.end();
  });

  // Note: sequential GET/POST control steps in raceCheck use HTTP/1.1 or HTTP/2?
  // Wait: Node's cleartext http2 server only speaks HTTP/2 prior knowledge unless allowHTTP1 is enabled, OR TLS ALPN!
  // Let's also verify what happens if the server is HTTP/1.1+HTTP/2: let's check!
  await new Promise<void>(r => h2.listen(0, '127.0.0.1', r));
  const h2Port = (h2.address() as { port: number }).port;

  // Create a dual-port or single-origin HTTP/1.1 + HTTP/2 front? Wait: scopedRequest uses http.request (HTTP/1.1), while scopedHttp2Pair uses http2.connect (h2c)!
  // Let's create a tiny TCP multiplexer on 127.0.0.1 that routes HTTP/2 connection preface ("PRI * HTTP/2.0") to `h2` and HTTP/1.1 to an `http.Server` sharing the exact `counts` state!
  const h1 = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/state/ctrl') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ redeemed: counts['ctrl-res-01'] }));
      return;
    }
    if (req.method === 'GET' && req.url === '/state/race') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ redeemed: counts['race-res-02'] }));
      return;
    }
    if (req.method === 'POST' && req.url === '/redeem') {
      let raw = '';
      req.on('data', c => { raw += c; });
      req.on('end', () => {
        const { coupon } = JSON.parse(raw) as { coupon: string };
        if ((counts[coupon] ?? 0) >= 1) {
          res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'already_used' }));
          return;
        }
        counts[coupon] = (counts[coupon] ?? 0) + 1;
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(r => h1.listen(0, '127.0.0.1', r));
  const h1Port = (h1.address() as { port: number }).port;

  const { createServer: createNetServer, connect: netConnect } = await import('node:net');
  const mux = createNetServer(sock => {
    sock.once('readable', () => {
      const head: Buffer | null = sock.read(14);
      if (!head) { sock.destroy(); return; }
      const isH2 = head.toString('latin1').startsWith('PRI * HTTP/2.0');
      const upstream = netConnect(isH2 ? h2Port : h1Port, '127.0.0.1', () => {
        upstream.write(head);
        sock.pipe(upstream).pipe(sock);
      });
      upstream.on('error', () => sock.destroy());
      sock.on('error', () => upstream.destroy());
    });
  });
  await new Promise<void>(r => mux.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(mux.address() as { port: number }).port}`;

  try {
    const scope: Scope = {
      schemaVersion: 1,
      mode: 'loopback-lab',
      authorization: makeWindow(),
      allowed: [{ origin, paths: ['/redeem', '/state/ctrl', '/state/race'] }],
      excluded: [],
      requestRules: [{ origin, path: '/redeem', method: 'POST', queryNames: [], bodyFormats: ['json'] }],
      limits: makeLimits(10, 0),
    };
    const cfg = {
      schemaVersion: 1 as const,
      class: 'single-use-race' as const,
      policyReference: 'Single-use coupon redemption',
      credentialEnv: 'BBA_TOKEN_RACER',
      actionUrl: `${origin}/redeem`,
      actionField: 'coupon',
      controlResourceId: 'ctrl-res-01',
      raceResourceId: 'race-res-02',
      controlStateUrl: `${origin}/state/ctrl`,
      raceStateUrl: `${origin}/state/race`,
      countPointer: '/redeemed',
      transport: 'http2' as const,
    };

    const vulnRes = await raceCheck(join(dir, 'race-vuln'), scope, cfg, { credentials: { BBA_TOKEN_RACER: 'tok-racer' } });
    assert.equal(vulnRes.status, 'confirmed');
    assert.equal(sessionsOpened, 1, 'both race streams must multiplex over a single HTTP/2 session');

    vulnerable = false;
    counts['ctrl-res-01'] = 0;
    counts['race-res-02'] = 0;
    const fixedRes = await raceCheck(join(dir, 'race-fixed'), scope, cfg, { credentials: { BBA_TOKEN_RACER: 'tok-racer' } });
    assert.equal(fixedRes.status, 'not-reproduced');
    assert.equal(sessionsOpened, 2);
  } finally {
    mux.close();
    h1.closeAllConnections();
    h2.close();
    await new Promise<void>(r => h1.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

test('Feature #8, #11 & #12: platform submission export + CVSS, Ed25519 signing/tamper detection and CSP-locked local UI', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bba-feat81112-'));
  try {
    // CVSS v3.1 formula sanity check (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N -> 6.5 Medium)
    const cvss = calculateCvss31({ AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' });
    assert.equal(cvss.score, 6.5);
    assert.equal(cvss.severity, 'Medium');

    // Create a completed run and fake a verified confirmed result + unconfirmed result
    const srv = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ secret: 'top' }));
    });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;
    const superSecretToken = 'super-secret-submission-token-999';

    try {
      const scope: Scope = {
        schemaVersion: 1,
        mode: 'loopback-lab',
        authorization: makeWindow(),
        allowed: [{ origin, paths: ['/item'] }],
        excluded: [],
        limits: makeLimits(5),
      };
      const artDir = join(dir, 'case-xss-escape');
      createSession(join(artDir, 'run'), scope, {
        schemaVersion: 1,
        steps: [{ id: 'probe', method: 'GET', url: `${origin}/item`, credentialEnv: 'BBA_TOKEN_SUB' }],
      });
      await executeSession(join(artDir, 'run'), scope, { credentials: { BBA_TOKEN_SUB: superSecretToken } });
      await writeFile(join(artDir, 'note.json'), JSON.stringify({ label: '<script>alert(1)</script>' }));

      const { digest } = await import('../src/contracts.ts');
      const confirmedPayload = {
        schemaVersion: 1,
        class: 'bola',
        status: 'confirmed',
        reason: 'Cross-account read confirmed.',
        evidence: ['run:probe'],
        limitations: ['Scoped to controlled resource.'],
      };
      await writeFile(join(artDir, 'result.json'), JSON.stringify({ result: confirmedPayload, sha256: digest(confirmedPayload) }, null, 2));

      // Export HackerOne & GHSA submissions
      const h1 = exportSubmission(artDir, 'hackerone', join(dir, 'h1.md'), { lang: 'es' });
      assert.equal(h1.status, 'confirmed');
      assert.ok(h1.cvss !== null && h1.cvss.v31Score === 6.5);
      const h1Md = await readFile(join(dir, 'h1.md'), 'utf8');
      assert.match(h1Md, /\$BBA_TOKEN_SUB/);
      assert.doesNotMatch(h1Md, new RegExp(superSecretToken));

      // Unconfirmed result must NOT receive a CVSS score
      const unconfDir = join(dir, 'unconf');
      await (await import('node:fs/promises')).mkdir(unconfDir);
      const unconfPayload = { ...confirmedPayload, status: 'not-reproduced' };
      await writeFile(join(unconfDir, 'result.json'), JSON.stringify({ result: unconfPayload, sha256: digest(unconfPayload) }, null, 2));
      const ghsa = exportSubmission(unconfDir, 'ghsa', join(dir, 'ghsa.md'), { lang: 'en' });
      assert.equal(ghsa.cvss, null);

      // Feature #12: Inspector HTML escapes XSS in directory/artifact names and serves CSP on 127.0.0.1
      const html = renderInspectorHtml(artDir, 'es');
      assert.equal(html.includes('<script>alert(1)</script>'), false);
      assert.equal(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), true);

      const uiSrv = await startInspectorServer(artDir, { lang: 'en' });
      try {
        const resGet = await fetch(uiSrv.origin + '/');
        assert.equal(resGet.status, 200);
        assert.equal(resGet.headers.get('content-security-policy'), INSPECTOR_CSP);
        assert.equal(resGet.headers.get('x-frame-options'), 'DENY');
        const bodyText = await resGet.text();
        assert.doesNotMatch(bodyText, new RegExp(superSecretToken));

        const resPost = await fetch(uiSrv.origin + '/', { method: 'POST' });
        assert.equal(resPost.status, 405);
      } finally {
        await uiSrv.close();
      }

      // Feature #11: Ed25519 keygen, signEvidence, verifyEvidenceSignature & tamper rejection
      const keysA = generateSigningKeypair(join(dir, 'keys-a'));
      const keysB = generateSigningKeypair(join(dir, 'keys-b'));
      const signed = signEvidence(artDir, keysA.privateKeyPath);
      assert.ok(signed.filesSigned >= 2);

      const verified = verifyEvidenceSignature(artDir, keysA.publicKeyPath);
      assert.equal(verified.verified, true);

      // Wrong public key must fail
      assert.throws(() => verifyEvidenceSignature(artDir, keysB.publicKeyPath), /fingerprint/);

      // Tampering a signed file must fail
      await writeFile(join(artDir, 'result.json'), (await readFile(join(artDir, 'result.json'), 'utf8')) + '\n');
      assert.throws(() => verifyEvidenceSignature(artDir, keysA.publicKeyPath), /modified/);
    } finally {
      srv.closeAllConnections();
      await new Promise<void>(r => srv.close(() => r()));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
