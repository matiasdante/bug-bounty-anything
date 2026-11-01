# CLI guide

**English** · [Español](es/cli.md) · [Português (Brasil)](pt-BR/cli.md) · [简体中文](zh/cli.md)

Command reference for the local engine: scoped execution, imports, capture, evaluation, signatures, program headers, lab files, limits, and verification. Install first with the [installation guide](installation.md).

## Scoped execution and recovery

The [execution guide](EXECUTION.md) defines contracts, limits, checkpoints, and recovery. With scope and plan prepared for authorized resources:

```powershell
npm run bba -- scope-check --scope scope.json --plan plan.json
npm run bba -- run --scope scope.json --plan plan.json --out runs/investigation
npm run bba -- resume runs/investigation --scope scope.json
npm run bba -- inspect-run runs/investigation
npm run bba -- export-run runs/investigation --out runs/investigation-export.json
npm run bba -- report-run runs/investigation --out runs/investigation-report.md
```

`scope-check` validates format, window, and destination matching; **it does not verify the asset owner's permission**. Establish that permission and current rules before writing the scope. `run` and `resume` send requests; the other commands above are offline. Ctrl+C records what is known. `resume` retains budget and evidence, requires the same current scope, and runs only unstarted steps. An in-flight request whose outcome was lost remains inconclusive and is never retried automatically. Stops caused by errors or limits require review and, where appropriate, a new investigation.

## Import surface and policy

```powershell
npm run bba -- import-surface --format har|openapi|rea|graphql|js-bundle --input source.json --out runs/surface.json [--quarantine]
npm run bba -- import-policy --format hackerone|bugcrowd|intigriti|security-txt --input policy.json --out runs/policy-draft
```

The offline importer projects endpoints from HAR 1.2, Swagger 2.0/OpenAPI 3.0/3.1 JSON, REA evidence, GraphQL introspection/SDL, and JS bundles/SourceMap v3. It does not contact URLs or grant authorization. `--quarantine` counts and skips unrepresentable entries instead of rejecting the entire batch. Entries distinguish observed HAR/REA data from declared schema or JS data and retain source locators. Headers, bodies, query values, examples, and descriptions are discarded. Numeric, UUID, and long segments become `{opaque}`. RFC 3986 path characters and bracketed query names are supported while ambiguous escapes remain blocked. Policy import extracts exact HTTPS assets into `scope.draft.json`; wildcard domains are held in `manualReviewWildcards`, never silently expanded.

## Capture with Chromium

```powershell
npm run bba -- capture --scope scope.json --plan plan.json --out runs/capture
```

Headless Chromium visits each plan step and writes `surface.json`, `capture.json`, and `pages.json` (observed paths, actions, and field names without values or query strings). Scope modes are `loopback-lab` and `public-https`. Local servers and bounded public navigation on `www.dcs.ar` were tested; that pilot did not test login, permissions, or payloads.

Every browser request passes through BBA's transport: exact scoped GET, pinned DNS, public IP validation, no redirects, timeout, size, interval, and budget limits. Other requests are blocked; after a stop, later steps are marked `not-sent`. Chromium's own traffic is directed to a rejecting loopback sink and counted as `leak-attempts`; DNS resolution and direct WebRTC UDP are disabled. Tests exercise these boundaries. `preconnect` and `dns-prefetch` did not open connections in the pinned Chromium build, so they are not claimed as proven vectors.

`credentialEnv` accepts either `BBA_TOKEN_*` as Bearer or `BBA_COOKIE_*` as a Cookie header; both are never sent together and values are never persisted. The operator obtains the session cookie. BBA does not log in or apply `Set-Cookie`, so rotating sessions may become unauthenticated. Each step uses an ephemeral context with service workers blocked. In `surface.json`, `status: null` means no request was sent. Capture has no checkpoints: a crash can lose the record of sent requests. Form login, POST, and crawling are outside this path. Exit codes: `0` complete, `1` stopped, `130` cancelled.

## Evaluate authorization hypotheses

```powershell
npm run bba -- evaluate-run runs/investigation --checks checks.json --out runs/evaluation.md
```

This offline comparator reads a verified run and declared `checks.json` hypotheses for `bola`, `bfla`, and `property-exposure`. Each check uses an anonymous control and a baseline and probe with different credentials against the same URL. A denied control and two identical 200 responses yield only `needs-validation`; a denied probe with a valid baseline yields `not-reproduced`; open controls, failed baselines, missing responses, 5xx, or differing 200 responses are `unresolved`. A different 200 for property exposure may be a partial leak. It compares response hashes, does not retain content or measure impact, and cannot verify declared roles or owners. `not-reproduced` does not mean the system is safe. The vulnerable and fixed local labs exercise these cases over real HTTP.

## Import scanner candidates

```powershell
npm run bba -- import-candidates --format zap|nuclei|subfinder --input zap-report.json --scope scope.json --out runs/candidates.json
```

BBA does **not** run ZAP, Nuclei, or Subfinder. Their activity would bypass BBA's scope and budget transport. It normalizes operator supplied ZAP JSON, Nuclei JSONL, or Subfinder JSONL offline, up to 2 MiB and 5,000 records. Every candidate remains `unvalidated`. Scope status is `in-scope`, `excluded`, `out-of-scope`, or `unparseable`; Subfinder hostnames are compared without DNS. Descriptions, raw evidence, attacks, requests, responses, and query values are dropped. Scanner severity is a source label, not a BBA assessment. Duplicates are counted and collapsed. Formats were modeled from tool documentation and synthetic tests, not a real scanner run. Advisory and version delta lookup remains manual.

## Frozen evaluation

```powershell
npm run bba -- eval --out runs/evaluation.md
```

This runs 18 mandatory loopback cases: six response comparisons, three inconclusive budget cases, six scope boundaries, two secret checks, and one recovery case. `FROZEN_DIGEST` guards the case IDs and expected outcomes. The hash comparator reports candidates, not confirmed findings; the autonomous BOLA path has separate tests. Synthetic lab metrics do not estimate real-world detection or false-positive rates and do not prove a target safe. Chromium isolation has separate capture tests.


## Signatures, submission drafts, and local inspector

```powershell
bba keygen --out keys/operator
bba sign-evidence runs/investigation --key keys/operator/bba-ed25519.key.pem
bba verify-signature runs/investigation --pub keys/operator/bba-ed25519.pub.pem
bba export-submission runs/investigation --platform hackerone|bugcrowd|ghsa --out runs/submission.md
bba ui runs/investigation --out runs/inspector.html
```

Ed25519 signing verifies complete files or directories, including later additions and deletions. `export-submission` writes Markdown drafts with redacted `curl` commands and conservative CVSS v3.1/v4.0 baselines only for `confirmed` findings. `ui` serves a read-only inspector on `127.0.0.1` with a strict CSP or exports standalone HTML without JavaScript or external resources. Campaign commands open and link a case to its policy, check integrity and budget, capture an exact URL, execute a semantic profile, and resume paused work without repeating recorded steps; see [campaigns](CAMPAIGNS.md).

## Program identification headers

`scope.requestHeaders` supports per-origin markers in `run`, `resume`, `capture`, and `hunt`:

```json
"requestHeaders": [
  { "origin": "https://authorized-service", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://authorized-service", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

The operator sets values in the environment. Only lowercase `user-agent` or `x-*` names are allowed, not auth, cookie, host, or transport headers. Values must be 1–512 printable ASCII characters without newlines. The scope stores references and names, never values. Missing values fail before sending or reserving requests. Each marker goes only to its declared origin. Existing scopes without this field still work.


## Files and contracts

`lab` writes `investigation.json`, a versioned bundle with scope, five evidence records, two hypotheses, and SHA-256 checksum, plus `report.md` with result, reproduction, evidence references, impact, and limitations. [src/contracts.ts](../src/contracts.ts) validates the input. Evidence stores UTC time, actor, route, HTTP status, and only allowed synthetic fields, not complete HTTP captures, auth headers, cookies, error bodies, or unexpected fields. On read, BBA validates structure, version, IDs, references, checksum, and conclusion consistency. Hashes detect accidental changes; **they are not signatures or proof of third party authenticity**. JSON is data, never executable code.

An interrupted lab write remains `.incomplete`. `run/resume` use separate checkpoint contracts. Outputs under `runs/` are Git ignored.

## Executor limits

The fixed `lab` path allows only GET to two exact lab routes, with no queries, redirects, or arbitrary domains. It has five requests, a two-second per-request timeout, and a 4,096-byte response limit. It stops on redirects, 429, 5xx, timeouts, oversized bodies, or out-of-contract content. General `run/resume` limits come from the scope and preserve partial state. HTTP metadata and hashes alone are not interpreted as vulnerabilities.

## Verification

`npm test` uses `node:test` and real local HTTP servers for vulnerable/fixed variants, inconclusive controls, isolation, limits, secrets, scope, checkpoints, integrity, and CLI. It includes cancellation and process death recovery without duplicate requests. Public DNS selection uses a controlled resolver; tests do not contact production services. `npm run check` performs strict TypeScript checks without emitting JS; `npm run verify` runs check, build, and tests. CI runs on Ubuntu and Windows with Node 22.13 and 24.

Exit codes: `0` completed (including a lab that found vulnerabilities), `1` error or stopped, `2` invalid arguments, `3` partial with inconclusive results, `130` cancelled. A zero exit code is not evidence of no vulnerabilities.


