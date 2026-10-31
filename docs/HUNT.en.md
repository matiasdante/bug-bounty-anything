# BBA autonomous goal and workflow

[Español](HUNT.md) · **English**

The goal is to start from an authorized website, discover its surface, generate and run hypotheses, confirm a vulnerability with controls, document proof, and leave a draft ready for bug bounty review. Accounts, rules, and scope are set once; the framework proposes checks within those limits without a manual list of expected bugs.

## Current implementation

`hunt --scope scope.json --config hunt.json --out runs/hunt` implements this for improper reading of private fields across two accounts (BOLA), through CLI or network-enabled MCP. The skill prepares files from the service and current policy; `prepare` starts a case offline. This is a specialized route, not a requirement when accounts or an owner-only rule are unavailable.

```json
{
  "schemaVersion": 1,
  "seed": "https://service.example/",
  "identityUrl": "https://service.example/api/me",
  "identityField": "id",
  "ownerField": "ownerId",
  "privateField": "privateNotes",
  "accounts": ["BBA_TOKEN_A", "BBA_TOKEN_B"],
  "boundary": "owner-only"
}
```

Example URLs are structural, not targets. Secrets come from referenced environment variables; `BBA_COOKIE_*` also supports cookies. Use two distinct accounts you control, without shared permissions on the checked resources. The operator establishes that the field is owner-only; a field named `ownerId` does not establish the business rule. Scope contains exact origins and paths, possibly unvisited permitted paths. Discovery does not expand it: external, excluded, query-bearing, or unrepresentable links are not visited. No wildcards or enumeration of others' objects.

## Confirmation

1. Query the identity endpoint with each credential and require distinct server-returned IDs.
2. Follow HTML links from the seed as both accounts within common scope, budget, interval, timeout, size, and deadline limits.
3. For a JSON document owned by one of those identities with the configured private field, generate a hypothesis.
4. Read the same resource anonymously and with the other account. Confirm only when anonymous access is denied and the second identity receives the same owner and protected value.
5. Write result, evidence references, and report. Invalid sessions, public data, or incomplete controls never confirm.

Stop at the first confirmation to avoid reading more resources from one cause. Unvisited discovered links remain coverage gaps; one positive proof does not settle other classes. `scope.requestHeaders` adds per-origin environment-bound identification markers without persisting values. HTTP 200 or equal body hashes alone are insufficient. The report links response, identity evidence, and protected-field digests. Ownership and confidentiality still depend on the operator's declared preconditions.

## Artifacts

- `requests.jsonl` synchronizes intent before each send, then stores response metadata and redacted identity/field comparisons. Numeric IDs link report and requests.
- `hunt.json` stores discovered surface, source response, hypotheses, states, spent budget, stops, limits, and checksum.
- `report.md` contains access rule, preconditions, numbered reproduction, actor/resource, evidence, observed effect, remediation, and triage gaps.

No credentials, cookies, or original private values are stored. Authorized URLs and field names are retained; do not put secrets in them. Redacted evidence can be reproduced with test accounts but is not a full traffic capture. Hashes do not authenticate the author. Attempts without a result remain in the journal. Ctrl+C records partial facts and exits 130. Cancellation, deadline, and authorization are rechecked after interval waits. `hunt` cannot auto-resume or retry uncertain attempts. A new run needs a new folder and review of consumed budget; static `run/resume` uses its own checkpoint mechanism.

## Coverage gaps

`hunt` does not execute JavaScript or infer roles/tenants; its HTML-link generator covers BOLA only. Other routes provide [semantic investigation](INVESTIGATION.en.md), [Chromium XSS/CORS](BROWSER-CHECKS.en.md), and [browser sessions](SCENARIOS.en.md). There is no generic injection/SSRF confirmation or universal business-rule inference. No suitable discovered resource may yield no hypothesis, not a safety finding. There is no automatic submission, reward guarantee, live-program deduplication, or production validation here.

## Historical review before 1.2

Earlier Claude work on scope/transport, capture, imports, evaluation, persistence, CLI/MCP, packaging, and frozen evaluation was reviewed. Budget/checkpoints, destination isolation, provenance-aware importers, per-identity browser isolation, restricted MCP, and JS packaging were retained. BBA added autonomous hypothesis generation; `evaluate-run` now leaves hash matches as `needs-validation`, with differing property responses `unresolved`. Frozen evaluation revision 2 records zero confirmations and three misses rather than inflating detection metrics. Capture no longer forwards page credentials to another origin and rechecks cancellation/deadline after waiting. Build rejects deletion targets other than workspace `dist` or `.build-test` and rejects links. The internally authorized DCS pilot never authorized new tests or fulfilled a third-party bounty pilot. Six browser tests were initially skipped without Chromium; 1.2 ran the full suite and a bounded public DCS pilot. Neither proves broad web coverage.
