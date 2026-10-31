# Reproducible studies of published cases

[Español](PUBLISHED-CASE-STUDIES.md) · **English**

The first study uses [Faav's Titan article](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records) as a method reference. `cases/faav-titan-jwt-2026.json` identifies the publication and bug class but contains no token, service data, or authorized target. A historical investigation and a current reproduction are distinct.

## Agent workflow

1. Read current program policy and record source, window, assets, exclusions, allowed techniques, request limit, and owned test account. Without these, stop at offline analysis; a publication grants no permission.
2. Import Swagger 2.0/OpenAPI JSON using `import-surface --format openapi`. It omits bodies, examples, and secrets while retaining routes, methods, declared auth, and provenance. Record structured public historical clues in `historical.json` without assuming validity today.
3. Create `policy.json` and `profile.json` from verified facts. The agent writes them; the user need not write JSON. Profile refers to environment variables, a harmless query on owned data, and one protected JSON fact. No secrets in files.
4. Run `study-bundle` and `study-plan`. Planning selects one optionally authenticated operation and one protected operation on the same origin within allowed prefixes; a historical clue may break a tie. With no unique candidate, return `unresolved` and send no requests. Review `analysis.json`, `scope.json`, and `jwt-config.json` before active work.
5. With signed token and body in the environment, run `study-run`: anonymous, original JWT, changed-claim JWT retaining the old signature, and original JWT again. Confirm only when anonymous is denied and the same owned protected fact appears with both tokens. `resume-study` validates bundle and original artifacts without repeating uncertain attempts.

```powershell
node dist/cli.js import-surface --format openapi --input api.json --out runs/surface.json
node dist/cli.js study-bundle --case cases/faav-titan-jwt-2026.json --policy policy.json --surface runs/surface.json --historical historical.json --profile profile.json --out runs/study-input.json
node dist/cli.js study-plan --input runs/study-input.json --out runs/study-plan
node dist/cli.js study-run --input runs/study-input.json --out runs/study-active
node dist/cli.js resume-study runs/study-active --input runs/study-input.json
```

Bundle and plan are offline; run and resume may send requests. MCP names are `study_bundle`, `study_plan`, `study_run`, and `resume_study`; the last two require `--allow-network`. Outputs must be new. Preserve the canonical path of `study-input.json`, since `.bba-budgets/<budgetId>` is stored alongside it.

## Minimum contracts

- `policy.json`: `schemaVersion: 1`, `mode`, `sourceUrl`, `reviewedAt`, `authorization` (`reference`, `validFrom`, `validUntil`), `assets` and `excluded` as `{origin,pathPrefixes}`, `techniques: ["jwt-signature-integrity"]`, `budgetId`, and scope `limits`. Exclusions win. Format and time are validated; the investigator verifies policy legitimacy.
- `historical.json`: `schemaVersion: 1`, `sourceUrl`, `capturedAt`, and `routes: [{path,clue}]`, where `clue` is `routing-definition` or `endpoint-reference`. Historical sources suggest where to look.
- `profile.json`: `schemaVersion: 1`, `credentialEnv` (`BBA_TOKEN_*`), `proofPointer`, `request`, and `mutation` per the [JWT contract](JWT-INTEGRITY.en.md). POST bodies use `BBA_BODY_*`; choose owned data and a stable private fact.
- `study-input.json`: validated portable bundle of five inputs. `study-plan/analysis.json` contains candidates and a provenance graph; scope and JWT config require one unique candidate. `study-active/report.md` is a five-question draft.

## Report claims

The draft covers the issue, discovery, exploit proof, reproduction, and remediation, with evidence IDs and limits. `confirmed` shows acceptance of the altered JWT for the declared account/fact. It does not show other identities' privileges, bulk reads, severity, or that the article's target remains vulnerable. `not-reproduced` excludes only the tested mutation. Reports remain local for review before submission. This MVP handles one hypothesis class and one candidate per run; it does not automate broad reconnaissance or identity/claim inference.
