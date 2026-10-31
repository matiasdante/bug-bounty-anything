import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { fixture } from './support.ts';
import { openCampaign, linkCampaign, campaignStatus, campaignExecute, campaignCapture, campaignResume, preparePolicyReview } from '../src/campaign.ts';
import { importSurface } from '../src/surface.ts';
import { digest } from '../src/contracts.ts';
import type { Profile } from '../src/planner.ts';

test('campaign ledger guides a scoped synthetic investigation and rejects changed evidence', async () => {
  let hits = 0;
  await fixture((req, res) => {
    hits++;
    const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a'
      : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
    const response = req.url === '/me' ? { id: actor } : { owner: 'a', private: 'synthetic-private-fact' };
    res.writeHead(actor ? 200 : 401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(actor ? response : {}));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin, campaign = join(folder, 'campaign');
    scope.allowed[0].paths = ['/', '/me', '/resources/one'];
    scope.budgetId = 'campaign-fixture'; scope.limits.maxRequests = 6;
    openCampaign(campaign, origin + '/');
    assert.match(campaignStatus(campaign).next, /scope/);
    const scopePath = join(campaign, 'scope.json'); await writeFile(scopePath, JSON.stringify(scope));
    linkCampaign(campaign, 'scope', scopePath);
    assert.match(campaignStatus(campaign).next, /policy review/);
    const review = { schemaVersion: 1, sourceUrl: 'https://program.example.test/policy', reviewedAt: new Date().toISOString(),
      scopeDigest: digest(scope), authorizationReference: scope.authorization.reference,
      sourceKind: 'owner-written-authorization', operatorDecision: 'authorized' };
    const policyPath = join(campaign, 'policy.json'); await writeFile(policyPath, JSON.stringify(review));
    linkCampaign(campaign, 'policy', policyPath);
    assert.match(campaignStatus(campaign).next, /Inspect the exact authorized page/);
    const surface = importSurface({ openapi: '3.0.3', info: {}, servers: [{ url: origin }],
      paths: { '/resources/one': { get: {} } } }, 'openapi');
    const surfacePath = join(campaign, 'surface.json'); await writeFile(surfacePath, JSON.stringify({ surface, sha256: digest(surface) }));
    linkCampaign(campaign, 'surface', surfacePath);
    assert.match(campaignStatus(campaign).next, /business rules/);
    const profile: Profile = { schemaVersion: 1, accounts: ['BBA_TOKEN_CAMPAIGN_A', 'BBA_TOKEN_CAMPAIGN_B'],
      identity: { url: origin + '/me', fact: 'identity', observe: [{ name: 'identity', pointer: '/id' }] },
      rules: [{ class: 'bola', origin, pathPrefix: '/resources', protectedPointer: '/private', subjectPointer: '/owner', query: [],
        policy: { reference: 'owned fixture private data', boundary: 'owner-only', ownerFact: 'owner' } }] };
    const profilePath = join(campaign, 'profile.json'); await writeFile(profilePath, JSON.stringify(profile));
    linkCampaign(campaign, 'profile', profilePath);
    assert.match(campaignStatus(campaign).next, /execute the bounded semantic investigation/);
    assert.equal(hits, 0, 'campaign planning remains offline');
    process.env.BBA_TOKEN_CAMPAIGN_A = 'synthetic-a'; process.env.BBA_TOKEN_CAMPAIGN_B = 'synthetic-b';
    try {
      const result = await campaignExecute(campaign);
      assert.equal(result.stopped, 'proof-complete'); assert.equal(hits, 5);
      await assert.rejects(() => campaignExecute(campaign), /already linked/);
      assert.equal(hits, 5, 'rerun does not send requests');
    } finally { delete process.env.BBA_TOKEN_CAMPAIGN_A; delete process.env.BBA_TOKEN_CAMPAIGN_B; }
    const status = campaignStatus(campaign);
    assert.equal(status.linked.length, 6);
    assert.equal(status.budget?.reservedRequests, 5);
    assert.equal(status.budget?.uncertainRequests, 0);
    assert.match(status.next, /Review the draft/);
    assert.equal(status.claims.ownerPermissionVerifiedByTool, false);
    assert.equal(status.claims.vulnerabilityConfirmedByCampaign, false);
    const changed = JSON.parse(await readFile(profilePath, 'utf8'));
    changed.rules[0].protectedPointer = '/other';
    await writeFile(profilePath, JSON.stringify(changed));
    assert.throws(() => campaignStatus(campaign), /changed/);
  });
});

test('campaign capture uses an authorized target once and links page facts', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<a href="/next?secret=discard">next</a><form action="/search"><input name="q"></form>');
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin, campaign = join(folder, 'capture-campaign');
    scope.budgetId = 'capture-fixture'; scope.limits.maxRequests = 4;
    openCampaign(campaign, origin + '/');
    const scopePath = join(campaign, 'scope.json'); await writeFile(scopePath, JSON.stringify(scope)); linkCampaign(campaign, 'scope', scopePath);
    await assert.rejects(() => campaignCapture(campaign), /authorized policy review/);
    assert.equal(hits, 0);
    const review = { schemaVersion: 1, sourceUrl: 'https://program.example.test/policy', reviewedAt: new Date().toISOString(),
      scopeDigest: digest(scope), authorizationReference: scope.authorization.reference,
      sourceKind: 'owner-written-authorization', operatorDecision: 'authorized' };
    const policy = join(campaign, 'policy.json'); await writeFile(policy, JSON.stringify(review)); linkCampaign(campaign, 'policy', policy);
    const result = await campaignCapture(campaign);
    assert.ok(result.requests >= 1); assert.ok(hits >= 1);
    assert.ok(campaignStatus(campaign).linked.some(item => item.kind === 'page'));
    const before = hits; await assert.rejects(() => campaignCapture(campaign), /already linked/);
    assert.equal(hits, before);
  });
});

test('campaign resumes only checkpointed steps under the same profile and budget', async () => {
  let hits = 0;
  await fixture((req, res) => { hits++;
    const actor = req.headers.authorization === 'Bearer synthetic-a' ? 'a' : req.headers.authorization === 'Bearer synthetic-b' ? 'b' : null;
    res.writeHead(actor ? 200 : 401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(actor ? req.url === '/me' ? { id: actor } : { owner: 'a', private: 'fixture-value' } : {}));
  }, async (scope, folder) => {
    const origin = scope.allowed[0].origin, campaign = join(folder, 'resumed-campaign');
    scope.allowed[0].paths = ['/', '/me', '/resources/one']; scope.budgetId = 'resume-fixture'; scope.limits.maxRequests = 6;
    openCampaign(campaign, origin + '/');
    const scopePath = join(campaign, 'scope.json'); await writeFile(scopePath, JSON.stringify(scope)); linkCampaign(campaign, 'scope', scopePath);
    const review = { schemaVersion: 1, sourceUrl: 'https://program.example.test/policy', reviewedAt: new Date().toISOString(),
      scopeDigest: digest(scope), authorizationReference: scope.authorization.reference,
      sourceKind: 'owner-written-authorization', operatorDecision: 'authorized' };
    const policyPath = join(campaign, 'policy.json'); await writeFile(policyPath, JSON.stringify(review)); linkCampaign(campaign, 'policy', policyPath);
    const surface = importSurface({ openapi: '3.0.3', info: {}, servers: [{ url: origin }], paths: { '/resources/one': { get: {} } } }, 'openapi');
    const surfacePath = join(campaign, 'surface.json'); await writeFile(surfacePath, JSON.stringify({ surface, sha256: digest(surface) }));
    linkCampaign(campaign, 'surface', surfacePath);
    const profile: Profile = { schemaVersion: 1, accounts: ['BBA_TOKEN_CAMPAIGN_A', 'BBA_TOKEN_CAMPAIGN_B'],
      identity: { url: origin + '/me', fact: 'identity', observe: [{ name: 'identity', pointer: '/id' }] },
      rules: [{ class: 'bola', origin, pathPrefix: '/resources', protectedPointer: '/private', subjectPointer: '/owner', query: [],
        policy: { reference: 'fixture owner data', boundary: 'owner-only', ownerFact: 'owner' } }] };
    const profilePath = join(campaign, 'profile.json'); await writeFile(profilePath, JSON.stringify(profile)); linkCampaign(campaign, 'profile', profilePath);
    process.env.BBA_TOKEN_CAMPAIGN_A = 'synthetic-a'; process.env.BBA_TOKEN_CAMPAIGN_B = 'synthetic-b';
    try {
      const abort = new AbortController(); abort.abort();
      const paused = await campaignExecute(campaign, abort.signal);
      assert.equal(paused.runStatus, 'paused'); assert.equal(hits, 0);
      assert.deepEqual(campaignStatus(campaign).blockers, ['interrupted-action']);
      const resumed = await campaignResume(campaign);
      assert.equal(resumed.newRequests, 5); assert.equal(resumed.stopped, 'proof-complete');
      assert.equal(hits, 5); assert.equal(campaignStatus(campaign).budget?.reservedRequests, 5);
      await assert.rejects(() => campaignResume(campaign), /No current interrupted investigation/);
      assert.equal(hits, 5);
    } finally { delete process.env.BBA_TOKEN_CAMPAIGN_A; delete process.env.BBA_TOKEN_CAMPAIGN_B; }
  });
});

test('campaign keeps uncertain policy offline and confines linked artifacts', async () => {
  await fixture((_req, res) => res.end(), async (scope, folder) => {
    const campaign = join(folder, 'campaign'), origin = scope.allowed[0].origin;
    scope.budgetId = 'uncertain-policy';
    openCampaign(campaign, origin + '/');
    const outside = join(folder, 'scope.json'); await writeFile(outside, JSON.stringify(scope));
    assert.throws(() => linkCampaign(campaign, 'scope', outside), /inside its folder/);
    const inside = join(campaign, 'scope.json'); await writeFile(inside, JSON.stringify(scope));
    linkCampaign(campaign, 'scope', inside);
    const review = { schemaVersion: 1, sourceUrl: 'https://program.example.test/policy', reviewedAt: new Date().toISOString(),
      scopeDigest: digest(scope), authorizationReference: scope.authorization.reference,
      sourceKind: 'official-program-policy', operatorDecision: 'uncertain' };
    const policy = join(campaign, 'policy.json'); await writeFile(policy, JSON.stringify(review));
    linkCampaign(campaign, 'policy', policy);
    const status = campaignStatus(campaign);
    assert.deepEqual(status.blockers, ['policy-uncertain']);
    assert.match(status.next, /Resolve program authorization/);
    await writeFile(join(campaign, 'events.json'), '{"events":[],"sha256":"wrong"}');
    assert.throws(() => campaignStatus(campaign), /integrity mismatch/);
  });
});

test('campaign binds a local policy source without claiming owner permission', async () => {
  let hits = 0;
  await fixture((_req, res) => { hits++; res.end(); }, async (scope, folder) => {
    const campaign = join(folder, 'source-campaign'), origin = scope.allowed[0].origin;
    scope.budgetId = 'policy-source-fixture';
    openCampaign(campaign, origin + '/');
    const scopePath = join(campaign, 'scope.json'); await writeFile(scopePath, JSON.stringify(scope));
    linkCampaign(campaign, 'scope', scopePath);
    await writeFile(join(campaign, 'policy-source.txt'), 'Authorized fixture: exact loopback origin and GET / only.');
    const prepared = preparePolicyReview(campaign, 'https://program.example.test/policy', 'owner-written-authorization', 'authorized');
    assert.equal(prepared.permissionVerifiedByTool, false);
    linkCampaign(campaign, 'policy', prepared.policy);
    assert.equal(campaignStatus(campaign).policySourceBound, true);
    assert.equal(hits, 0);
    await writeFile(join(campaign, 'policy-source.txt'), 'changed policy source');
    assert.throws(() => campaignStatus(campaign), /Policy source changed/);
  });
});
