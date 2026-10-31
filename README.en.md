# BBA — Bug Bounty Anything

[Español](README.md) · **English**

BBA is a local agent skill and engine for discovering, checking, and documenting vulnerabilities with verifiable evidence. For an authorized service, the agent establishes scope and policy, prepares a case, projects an attack surface, runs bounded comparisons, and drafts a report. Version `2.0.0` unifies CLI and MCP commands, supports Node.js `>=22.13.0` and `--lang es|en`, and adds the checks and evidence tools described below. The [roadmap](docs/ROADMAP.en.md) records coverage and limits.

`investigate` builds hypotheses from imported surface data and declared rules. It can confirm BOLA, BFLA, property exposure, tenant isolation, and mutations or mass assignment on disposable resources by checking server supplied identities and before/after state. `graphql-check` checks authorization per GraphQL operation. `oauth-check` and `redirect-check` classify 3xx `Location` headers without following redirects or retaining authorization codes or query values. `browser-check` checks XSS through marker execution and CORS through actual Chromium reads with WebRTC isolation. `hunt` discovers HTML resources and checks BOLA. The historical `evaluate-run` hash comparator only returns candidates marked `needs-validation`. Scanner and policy importers run offline.

`jwt-check` tests whether a token from an account you control is still accepted after a claim changes without a new signature (`add-canary`, `replace`), after removing the signature (`alg-none`), or after expiry (`expired-token`). It preserves native JSON types. See the [JWT contract](docs/JWT-INTEGRITY.en.md). It neither infers privileged identities nor estimates access to third party data. `study-bundle` → `study-plan` → `study-run` combines a published case, current policy, imported API surface, and historical clues with that JWT check; see [published case studies](docs/PUBLISHED-CASE-STUDIES.en.md).

Input and state checks are covered in [input proofs](docs/INPUT-PROOFS.en.md), [cache](docs/CACHE-CHECK.en.md), [race conditions](docs/RACE-CHECK.en.md), and [CSRF](docs/CSRF-CHECK.en.md). Each requires authorized paths and methods, resources you control, and negative controls.

```powershell
node dist/cli.js capabilities
node dist/cli.js investigate --scope scope.json --surface surface.json --profile profile.json --out runs/investigation
node dist/cli.js check graphql --scope scope.json --config graphql.json --out runs/graphql-proof
node dist/cli.js export-submission runs/graphql-proof --platform hackerone --out runs/h1-draft.md
```

For contracts and confirmation rules, see [investigation and evidence](docs/INVESTIGATION.en.md), [browser checks](docs/BROWSER-CHECKS.en.md), [browser sessions](docs/SCENARIOS.en.md), and the [persistent data model](docs/database.en.md). The agent prepares profiles; field names alone do not establish privacy, ownership, or roles. `hunt` needs a current scope, two controlled accounts, and the service's identity/ownership rules; see [HUNT](docs/HUNT.en.md). BBA never sends reports automatically.

## Invoke the skill

With project dependencies available:

```powershell
npm run build
node dist/cli.js install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
```

The output directory must be new. Installation copies instructions, references, and UI metadata; `runtime.json` points to this package's Node runtime and compiled CLI. Keep the project at that location. The command does not install dependencies or change MCP or other skills. Start a new chat if the skill catalog has not refreshed. `update-skill --out <existing-directory>` updates managed files, keeps a backup in `.bba-backups/`, checks that the installation belongs to this package, rejects resource links, and preserves unrelated files. `installation.json` stores managed file hashes; an interrupted update is never reported as complete.

For Claude Code, Codex, or Gemini CLI, `npm run package:skill -- --out dist-skill.zip` builds a portable ZIP with the compiled CLI, `SKILL.md`, and references. The older Windows PowerShell packager remains available. Unpack `bug-bounty-anything` into `.claude/skills/` or `~/.claude/skills/`. Initial MCP registration exposes offline tools only; install Chromium separately when browser checks are needed.

Ask the agent, for example, **`$bug-bounty-anything investigate https://authorized-service/ and prepare findings`**. The agent looks up current policy and creates the required files. It asks only for facts it cannot establish, such as test accounts or an access rule. Without authorization it stops active checks on that asset; public research may continue. The skill works through the CLI without requiring MCP and delegates client artifact analysis to REA where appropriate.

If policy or an authorization window is missing, `start-case --target <url> --out <directory>` records a pending case without creating a scope or making requests. Once permission is established, use `prepare`:

```powershell
node dist/cli.js prepare --scope scope.json --target https://authorized-service/ --out runs/investigation
```

This creates a scope copy, anonymous GET seed plan, checksummed case record, and investigation notes. It does not contact the target or prove permission. It rejects excluded or out of scope URLs, expired windows, and existing outputs. MCP also exposes `prepare` without enabling network access. A `budgetId` shares a persistent request count, interval, and duration across phases next to the canonical scope file; older scopes keep per-run limits.

## Requirements and local run

- Node.js **22.13.0 or newer**, with npm. Node provides TypeScript type stripping during development and native SQLite. The only production dependency is `playwright-core` 1.64.1 (Apache-2.0).
- For development or tests on Node 22.13, enable native TypeScript stripping with `$env:NODE_OPTIONS = '--experimental-strip-types'` in PowerShell. The published package runs compiled JavaScript and does not need this option.
- Run `npm install` and `npx playwright-core install --only-shell chromium` for capture and browser checks. Chromium downloads outside the repository. Other commands do not require it.
- Local labs and the inspector need connections to `127.0.0.1`. If a sandbox blocks loopback, run from a local terminal where it is allowed.

```powershell
npm run bba -- lab --variant vulnerable --out runs/vulnerable
npm run bba -- lab --variant fixed --out runs/fixed
npm run bba -- inspect runs/vulnerable
npm run bba -- report runs/vulnerable --out runs/vulnerable-export.md
npm run demo:core -- --out runs/core-demo
npm test
```

On PowerShell installations that block `npm.ps1`, use `npm.cmd`. Output files and directories must be new; BBA does not overwrite an investigation. `lab` starts a disposable server on `127.0.0.1`, creates two synthetic accounts and documents, sends five sequential requests, and shuts down even on error. Credentials stay in memory. `inspect` and `report` read verified local evidence without network access; `report` rebuilds the report from JSON. `demo:core` runs a second lab and writes SQLite checkpoints, a scope and plan without credentials, JSON export, and a report. Do not reuse its ephemeral credentials or port.

## Scoped execution and recovery

The [execution guide](docs/EXECUTION.en.md) defines contracts, limits, checkpoints, and recovery. With scope and plan prepared for authorized resources:

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

## Installation, diagnosis, and MCP

For a one-off CLI run directly from npm, without a global installation:

```powershell
npx --yes bug-bounty-anything@latest capabilities
npx --yes bug-bounty-anything@latest --help
```

`npx` downloads the published package and runs its `bba` command. For a persistent skill or MCP registration, install the package globally: registrations store the CLI path, and a temporary `npx` cache entry may later disappear.

```powershell
npm install --global bug-bounty-anything@latest
bba install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
bba doctor
```

For browser checks, install Chromium separately with `npx playwright-core install --only-shell chromium`. In the source repository, `npm install`, `npm run build`, and `npm test` remain the development commands. The public package and code use the [MIT license](LICENSE).

The package exposes `bba`, including grouped `campaign`, `check`, and `study` subcommands, per-command help, and `--lang es|en`. `doctor` checks only local Node, SQLite, loopback, temporary storage, Chromium, and names (never values) of present `BBA_TOKEN_*`, `BBA_COOKIE_*`, `BBA_HEADER_*`, `BBA_INPUT_*`, and `BBA_BODY_*` variables.

```powershell
bba mcp --root C:/path/to/workspace
bba mcp --root C:/path/to/workspace --allow-network
```

MCP runs over stdio JSON-RPC with `initialize`, out-of-band `ping`, real cancellation through `notifications/cancelled`, and `tools`. `tools/list` is authoritative; active tools only appear with `--allow-network`. Paths are confined to `--root` on Windows and POSIX, including symlink and junction escapes; internal errors are sanitized. `setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` previews or applies registration with local backups.

## Signatures, submission drafts, and local inspector

```powershell
bba keygen --out keys/operator
bba sign-evidence runs/investigation --key keys/operator/bba-ed25519.key.pem
bba verify-signature runs/investigation --pub keys/operator/bba-ed25519.pub.pem
bba export-submission runs/investigation --platform hackerone|bugcrowd|ghsa --out runs/submission.md
bba ui runs/investigation --out runs/inspector.html
```

Ed25519 signing verifies complete files or directories, including later additions and deletions. `export-submission` writes Markdown drafts with redacted `curl` commands and conservative CVSS v3.1/v4.0 baselines only for `confirmed` findings. `ui` serves a read-only inspector on `127.0.0.1` with a strict CSP or exports standalone HTML without JavaScript or external resources. Campaign commands open and link a case to its policy, check integrity and budget, capture an exact URL, execute a semantic profile, and resume paused work without repeating recorded steps; see [campaigns](docs/CAMPAIGNS.en.md).

## Program identification headers

`scope.requestHeaders` supports per-origin markers in `run`, `resume`, `capture`, and `hunt`:

```json
"requestHeaders": [
  { "origin": "https://authorized-service", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://authorized-service", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

The operator sets values in the environment. Only lowercase `user-agent` or `x-*` names are allowed, not auth, cookie, host, or transport headers. Values must be 1–512 printable ASCII characters without newlines. The scope stores references and names, never values. Missing values fail before sending or reserving requests. Each marker goes only to its declared origin. Existing scopes without this field still work.

## What the lab demonstrates

| Request | Vulnerable | Fixed |
|---|---|---|
| Anonymous reads document B | 401 | 401 |
| A reads document A | 200 | 200 |
| B reads document B | 200 | 200 |
| A reads document B | 200 and B's content | 403 |
| B reads document A | 200 and A's content | 403 |

The evaluator checks controls and compares the complete document to its owner's response. It does not use the variant name to decide. Different content, invalid sessions, or failed controls remain `unresolved`; a valid denial is `not-reproduced` for that comparison, not a safety claim. The vulnerable variant demonstrates two directions of one root cause, not two independent vulnerabilities. No production severity or CVSS is inferred.

## Files and contracts

`lab` writes `investigation.json`, a versioned bundle with scope, five evidence records, two hypotheses, and SHA-256 checksum, plus `report.md` with result, reproduction, evidence references, impact, and limitations. [src/contracts.ts](src/contracts.ts) validates the input. Evidence stores UTC time, actor, route, HTTP status, and only allowed synthetic fields, not complete HTTP captures, auth headers, cookies, error bodies, or unexpected fields. On read, BBA validates structure, version, IDs, references, checksum, and conclusion consistency. Hashes detect accidental changes; **they are not signatures or proof of third party authenticity**. JSON is data, never executable code.

An interrupted lab write remains `.incomplete`. `run/resume` use separate checkpoint contracts. Outputs under `runs/` are Git ignored.

## Executor limits

The fixed `lab` path allows only GET to two exact lab routes, with no queries, redirects, or arbitrary domains. It has five requests, a two-second per-request timeout, and a 4,096-byte response limit. It stops on redirects, 429, 5xx, timeouts, oversized bodies, or out-of-contract content. General `run/resume` limits come from the scope and preserve partial state. HTTP metadata and hashes alone are not interpreted as vulnerabilities.

## Verification

`npm test` uses `node:test` and real local HTTP servers for vulnerable/fixed variants, inconclusive controls, isolation, limits, secrets, scope, checkpoints, integrity, and CLI. It includes cancellation and process death recovery without duplicate requests. Public DNS selection uses a controlled resolver; tests do not contact production services. `npm run check` performs strict TypeScript checks without emitting JS; `npm run verify` runs check, build, and tests. CI runs on Ubuntu and Windows with Node 22.13 and 24.

Exit codes: `0` completed (including a lab that found vulnerabilities), `1` error or stopped, `2` invalid arguments, `3` partial with inconclusive results, `130` cancelled. A zero exit code is not evidence of no vulnerabilities.

## Next work

The engine still needs login/SSO and dynamic token inference, confirmation of more classes, and confined scanner execution. Declared form/action scenarios and in-memory cookie rotation run now but cannot resume after a crash. Semantic generation and XSS/CORS checks have bounded GET coverage. The skill supports broader agent assisted research with controllable tools without promising universal detection.
