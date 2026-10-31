import { closeSync, fstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { digest } from './contracts.ts';
import { strictUrl, validateScope } from './scope.ts';
import type { Scope, ScopeRule } from './scope.ts';

export type PolicyFormat = 'hackerone' | 'bugcrowd' | 'intigriti' | 'security-txt';

export type PolicyImportSummary = {
  schemaVersion: 1;
  format: PolicyFormat;
  sourceDigest: string;
  draftGenerated: boolean;
  allowedOrigins: number;
  excludedOrigins: number;
  manualReviewWildcards: string[];
  skippedAssets: number;
  limitations: string[];
};

const MAX_POLICY_BYTES = 2 * 1024 * 1024;

type RawAsset = { target: string; eligible: boolean };

function cleanAssetText(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return trimmed && trimmed.length <= 2048 ? trimmed : null;
}

function extractRawAssets(content: string, format: PolicyFormat): RawAsset[] {
  if (format === 'security-txt') {
    const assets: RawAsset[] = [];
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const m = /^Canonical\s*:\s*(.+)$/i.exec(line);
      if (m) {
        const clean = cleanAssetText(m[1]);
        if (clean) assets.push({ target: clean, eligible: true });
      }
    }
    if (!assets.length) throw new Error('No Canonical URLs found in security.txt');
    return assets;
  }

  let doc: any;
  try { doc = JSON.parse(content); } catch { throw new Error('Invalid JSON policy input'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Invalid JSON policy object');

  const assets: RawAsset[] = [];
  if (format === 'hackerone') {
    // Soporta tanto relationships.structured_scopes.data como arreglos planos structured_scopes / in_scope.
    const scopes = Array.isArray(doc?.relationships?.structured_scopes?.data)
      ? doc.relationships.structured_scopes.data.map((item: any) => item?.attributes ?? item)
      : Array.isArray(doc?.structured_scopes)
        ? doc.structured_scopes
        : Array.isArray(doc?.targets?.in_scope) || Array.isArray(doc?.targets?.out_of_scope)
          ? [
              ...(Array.isArray(doc.targets?.in_scope) ? doc.targets.in_scope.map((x: any) => ({ ...x, eligible_for_submission: true })) : []),
              ...(Array.isArray(doc.targets?.out_of_scope) ? doc.targets.out_of_scope.map((x: any) => ({ ...x, eligible_for_submission: false })) : []),
            ]
          : null;
    if (!scopes || scopes.length > 2000) throw new Error('Invalid HackerOne structured scopes');
    for (const s of scopes) {
      const id = cleanAssetText(s?.asset_identifier ?? s?.target ?? s?.endpoint);
      if (!id) continue;
      const assetType = typeof s?.asset_type === 'string' ? s.asset_type.toUpperCase() : 'URL';
      if (!['URL', 'WILDCARD', 'API', 'DOMAIN', 'OTHER'].includes(assetType)) continue;
      assets.push({ target: id, eligible: s?.eligible_for_submission !== false });
    }
  } else if (format === 'bugcrowd') {
    const groups = Array.isArray(doc?.target_groups) ? doc.target_groups : null;
    if (groups) {
      for (const g of groups) {
        const inScope = g?.in_scope !== false;
        const targets = Array.isArray(g?.targets) ? g.targets : [];
        for (const t of targets) {
          const uri = cleanAssetText(t?.uri ?? t?.name ?? t?.target);
          if (uri) assets.push({ target: uri, eligible: inScope });
        }
      }
    } else {
      for (const t of Array.isArray(doc?.in_scope) ? doc.in_scope : []) {
        const uri = cleanAssetText(t?.target ?? t?.uri ?? t);
        if (uri) assets.push({ target: uri, eligible: true });
      }
      for (const t of Array.isArray(doc?.out_of_scope) ? doc.out_of_scope : []) {
        const uri = cleanAssetText(t?.target ?? t?.uri ?? t);
        if (uri) assets.push({ target: uri, eligible: false });
      }
    }
    if (!assets.length) throw new Error('No targets found in Bugcrowd policy JSON');
  } else if (format === 'intigriti') {
    const domains = Array.isArray(doc?.domains) ? doc.domains : Array.isArray(doc?.content) ? doc.content : null;
    if (!domains || domains.length > 2000) throw new Error('Invalid Intigriti domains list');
    for (const d of domains) {
      const endpoint = cleanAssetText(d?.endpoint ?? d?.target);
      if (!endpoint) continue;
      const tier = typeof d?.tier === 'string' ? d.tier.toLowerCase() : '';
      const outOfScope = d?.outOfScope === true || tier === 'out_of_scope' || tier === 'out-of-scope';
      assets.push({ target: endpoint, eligible: !outOfScope });
    }
  } else {
    throw new Error('Unsupported policy format');
  }
  return assets;
}

function mergeRule(map: Map<string, { paths: Set<string>; prefixes: Set<string> }>, origin: string, pathname: string, asPrefix: boolean): void {
  let entry = map.get(origin);
  if (!entry) {
    entry = { paths: new Set(), prefixes: new Set() };
    map.set(origin, entry);
  }
  if (asPrefix) entry.prefixes.add(pathname);
  else entry.paths.add(pathname);
}

function buildRules(map: Map<string, { paths: Set<string>; prefixes: Set<string> }>): ScopeRule[] {
  const rules: ScopeRule[] = [];
  for (const [origin, sets] of [...map.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(0, 20)) {
    const paths = [...sets.paths].sort().slice(0, 100);
    const prefixes = [...sets.prefixes].sort().slice(0, 50);
    rules.push({
      origin,
      paths,
      ...(prefixes.length ? { pathPrefixes: prefixes } : {}),
    });
  }
  return rules;
}

export function importPolicy(content: string, format: PolicyFormat, options: {
  reference?: string;
  validFrom?: string;
  validUntil?: string;
} = {}): { summary: PolicyImportSummary; scopeDraft: Scope | null } {
  if (Buffer.byteLength(content, 'utf8') > MAX_POLICY_BYTES) throw new Error('Policy source exceeds 2 MiB');
  const rawAssets = extractRawAssets(content, format);
  const allowedMap = new Map<string, { paths: Set<string>; prefixes: Set<string> }>();
  const excludedMap = new Map<string, { paths: Set<string>; prefixes: Set<string> }>();
  const wildcards = new Set<string>();
  let skippedAssets = 0;

  for (const item of rawAssets) {
    if (item.target.includes('*')) {
      // Si el comodín está solo al final de la ruta (https://api.example.com/v1/*), el origen es exacto y podemos usar pathPrefix.
      const suffixWildcard = /^(https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?)(\/[^*?#]*)\*$/.exec(item.target);
      if (suffixWildcard && !suffixWildcard[1].includes('*')) {
        try {
          const parsed = strictUrl(suffixWildcard[1] + suffixWildcard[2]);
          const cleanPrefix = parsed.pathname.length > 1 && parsed.pathname.endsWith('/')
            ? parsed.pathname.slice(0, -1)
            : parsed.pathname;
          mergeRule(item.eligible ? allowedMap : excludedMap, parsed.origin, cleanPrefix, true);
          continue;
        } catch {
          wildcards.add(item.target);
          continue;
        }
      }
      wildcards.add(item.target);
      continue;
    }

    const candidateUrl = /^https?:\/\//i.test(item.target)
      ? item.target
      : /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\/.*)?$/.test(item.target)
        ? `https://${item.target}`
        : null;
    if (!candidateUrl) {
      skippedAssets++;
      continue;
    }
    try {
      const parsed = strictUrl(candidateUrl);
      if (parsed.protocol !== 'https:') {
        skippedAssets++;
        continue;
      }
      if (format === 'security-txt' && parsed.pathname.endsWith('/security.txt')) {
        mergeRule(allowedMap, parsed.origin, '/', false);
      } else {
        const asPrefix = parsed.pathname !== '/';
        mergeRule(item.eligible ? allowedMap : excludedMap, parsed.origin, parsed.pathname, asPrefix);
      }
    } catch {
      skippedAssets++;
    }
  }

  const allowed = buildRules(allowedMap);
  const excluded = buildRules(excludedMap);
  const now = Date.now();
  const validFrom = options.validFrom ?? new Date(now - 60_000).toISOString();
  const validUntil = options.validUntil ?? new Date(now + 7 * 24 * 3600_000).toISOString();
  const reference = options.reference ?? `Imported ${format} policy draft - operator review required`;

  let scopeDraft: Scope | null = null;
  if (allowed.length > 0) {
    const candidateScope: Scope = {
      schemaVersion: 1,
      mode: 'public-https',
      authorization: { reference, validFrom, validUntil },
      allowed,
      excluded,
      limits: {
        maxRequests: 10,
        minIntervalMs: 1000,
        timeoutMs: 5000,
        maxResponseBytes: 65536,
        maxDurationMs: 60000,
      },
    };
    validateScope(candidateScope);
    scopeDraft = candidateScope;
  }

  const manualReviewWildcards = [...wildcards].sort();
  const limitations = [
    'Draft scope only: operator review and explicit campaign_policy_review confirmation are mandatory before any active request.',
    'Wildcard hostnames (such as *.example.com) are quarantined in manualReviewWildcards and never expanded automatically.',
    'Program rate limits, required identifying headers and test-account rules in prose must be added manually to scope.json.',
  ];
  const summary: PolicyImportSummary = {
    schemaVersion: 1,
    format,
    sourceDigest: digest(content),
    draftGenerated: scopeDraft !== null,
    allowedOrigins: allowed.length,
    excludedOrigins: excluded.length,
    manualReviewWildcards,
    skippedAssets,
    limitations,
  };
  return { summary, scopeDraft };
}

export function importPolicyFile(inputPath: string, format: PolicyFormat, outDir: string): PolicyImportSummary {
  const fd = openSync(inputPath, 'r');
  let content: string;
  try {
    if (fstatSync(fd).size > MAX_POLICY_BYTES) throw new Error('Policy source exceeds 2 MiB');
    content = readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
  const { summary, scopeDraft } = importPolicy(content, format);
  mkdirSync(dirname(outDir), { recursive: true });
  mkdirSync(outDir);
  writeFileSync(join(outDir, 'policy-source.txt'), content, { flag: 'wx', mode: 0o600 });
  if (scopeDraft) {
    writeFileSync(join(outDir, 'scope.draft.json'), JSON.stringify(scopeDraft, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  writeFileSync(join(outDir, 'policy-import.json'), JSON.stringify({ summary, sha256: digest(summary) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return summary;
}
