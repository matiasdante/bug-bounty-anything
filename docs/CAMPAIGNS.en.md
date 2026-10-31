# Campaign case (1.9.0)

[Español](CAMPAIGNS.md) · **English**

A campaign coordinates one-target research: scope source, policy review, surface, owned-account profile, execution, and draft. Links are recorded in a hash-chained journal. `campaign_status` revalidates files and shows budget and next step. It detects accidental changes or inconsistency; it neither authenticates the policy owner nor turns an observation into a finding.

## Open and authorize

1. `campaign_open` / `campaign-open --target <url> --out <new-directory>` creates a case without requests. The target must be a canonical URL.
2. Write `scope.json` in the case with stable `budgetId`, current authorization window, exact assets/routes/methods, limits, and authorization reference. `campaign_link --kind scope` checks target coverage and freezes this scope for the case.
3. Read the current official program policy or written owner permission. Save a text copy as `policy-source.txt`. `campaign-policy-review` / `campaign_policy_review` generates `policy.json`, binding the source SHA-256 to scope and explicit operator decision. Review and link it with `campaign-link --kind policy`. The historical form without a local copy is still accepted:

```json
{
  "schemaVersion": 1,
  "sourceUrl": "https://program.example/policy",
  "reviewedAt": "2026-10-30T12:00:00.000Z",
  "scopeDigest": "<canonical scope SHA-256>",
  "authorizationReference": "<same as scope.authorization.reference>",
  "sourceKind": "official-program-policy",
  "operatorDecision": "authorized"
}
```

Choose `uncertain` if permission cannot be established. This records a human decision; the tool does not fetch or validate policy. A policy URL, `security.txt`, or user interest alone does not authorize active tests. `campaign_status` reports `policySourceBound` and detects changes to the local copy. Its hash shows copy integrity, not source authenticity or owner permission; retain the link and consultation date.

## MCP and CLI flow

With MCP `--allow-network`, `campaign_capture` captures the **exact target URL once** using bounded GETs. It writes `pages.json`, `capture.json`, and `surface.json` under `actions/capture/output` and links observed page and surface facts. DOM paths are clues, never automatically visited or added to scope. CLI: `bba campaign-capture <case>`.

An OpenAPI, Swagger, HAR, or REA surface bundle may instead be linked via `campaign_link --kind surface`. Link an investigation profile with two controlled identities and explicit business rules using `--kind profile`. `campaign_status` shows the number of compiled semantic checks and uncovered classes/entries. New profiles may follow new surfaces; old revisions stay in history.

`campaign_execute` / `bba campaign-execute <case>` runs anonymous, owner, and other-account controls **once per current profile** under the shared scope budget. It stops at the first confirmed semantic proof. The run and `report.md` are saved under `actions/investigation-<sequence>/output` and linked when complete or stopped at `proof-complete`. Credentials come from `BBA_TOKEN_*` or `BBA_COOKIE_*` in the MCP environment, never arguments or case files. Review impact, reproduction, and disclosure rules before submitting the draft.

## Stops and resume

An action directory is reserved before requests. On interrupted capture/investigation, `campaign_status` shows `interrupted-action` and will not rerun it. Inspect `started.json`, output, and `inspect_budget`. Uncertain reservations or expired windows block new actions. `campaign_resume` / `bba campaign-resume <case>` checks current scope, surface, and profile against a paused checkpoint, resumes only unstarted steps, writes `report-resumed.md`, and links completed artifacts. A terminal run with an existing report is linked without more requests. Browser capture has no automatic resume.

The semantic draft separately explains the issue, discovery, proof, reproduction, and fix. Proof retains each check's exact state and evidence IDs; `unresolved` never becomes claimed impact. Journal limit is 100 events with paths confined to the case directory. Automatic checks currently cover BOLA, BFLA, property exposure, and tenant isolation for JSON GET under declared identity and business rules. Other vectors require their own tools or remain gaps. A case does not claim a critical vulnerability or complete surface coverage.
