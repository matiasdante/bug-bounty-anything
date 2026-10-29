---
name: bug-bounty-anything
description: Investigate and prepare evidence-backed vulnerability reports for web apps and APIs under an explicit program policy or written authorization (BBA). Use for authorized bug bounty and VDP investigations, including known vulnerabilities and version deltas. Exclude ordinary source-code review.
metadata:
  version: "1.0.0"
---

# BBA (Bug Bounty Anything)

## Local implementation status

The bundled CLI is version 1.0.0: the original disposable authorization lab,
scoped GET plans with durable budgets and resumable checkpoints, offline import of
HAR/OpenAPI/REA surfaces and ZAP/Nuclei/Subfinder candidates, browser capture,
control/baseline/probe checks for BOLA, BFLA and property exposure, a frozen
evaluation, an MCP server and `doctor`. It was piloted once, on the operator's own
authorized site, not on a third-party bounty program. It cannot yet send a
program-required identifying header.
Imported candidates are always unvalidated; only the three check classes can be
confirmed, and only against a scope the operator wrote from the program policy.
See [README.md](README.md) for commands
and [docs/ROADMAP.md](docs/ROADMAP.md) for remaining 1.0.0 capabilities.
`npm run bba -- lab --variant vulnerable --out runs/example` runs only its
own synthetic lab; use `fixed` for the corrected variant and a new output
directory. That lab command does not accept external targets. General
`run/resume` commands require an explicit scope and plan; read
[docs/EXECUTION.md](docs/EXECUTION.md) before using them. `scope-check` checks
structure and scope matching, not the asset owner's real permission. Resolve
the authorization gate below before network execution. The methodology is
broader than the implemented tool coverage; never present planned adapters
or tests as available capabilities.

Use BBA when the user wants to find and report a vulnerability in a system
that has a confirmed bug bounty program (HackerOne, Bugcrowd, Intigriti,
YesWeHack, or the vendor's own VDP page) or explicit written authorization
for that exact asset. BBA is for externally-facing testing toward an
official report, not for reviewing code the user already owns and controls
— use the available coding and security-review workflow for that instead.

This skill never overrides the session's safety rules on prohibited and
permission-required actions. It adds a stricter gate on top: no active
technique below runs until scope is confirmed, and every finding stops at
a minimal proof of concept. Use controlled test data, stop once the
security boundary failure is demonstrated, and avoid service disruption.

## Gate: scope and authorization (before anything active)

Read [references/scope-and-authorization.md](references/scope-and-authorization.md)
and work through its checklist before the first active request against the
target. In short:

1. Read the current program policy or explicit written authorization from
   the asset owner. Record its source and verification date.
2. Confirm the specific asset — domain, subdomain, mobile package ID, API,
   IP range — is listed as in-scope, not excluded.
3. Confirm which test classes and techniques the program allows and which
   it bans (common bans: automated scanners without throttling, DoS/load
   testing, social engineering, physical access, testing other users'
   accounts/data, third-party vendor infrastructure).
4. Note rate limits, required test-account provisioning, safe-harbor
   language, and any required identifying header or user-agent string the
   program asks participants to send.
5. If asset authorization or the proposed technique remains ambiguous,
   stop active testing on that asset. Passive, read-only reconnaissance of
   already-public information is still fine; say explicitly to the user
   what authorization is missing before going further.

Re-check scope when the target surface spans multiple domains/programs —
scope is per-asset, not per-organization.

## Route the target first

- Web application, REST/GraphQL/gRPC API, or server-side system with a
  confirmed authorization: continue with recon and vulnerability-class testing
  below.
- Mobile app (APK/IPA), native binary, Electron/desktop client, firmware,
  or smart-contract bytecode: BBA does not reimplement static or binary
  analysis. Use `reverse-engineer-anything`, when available, for the client-side artifact
  (decompilation, traffic capture setup, client-side logic). Bring any
  server-side endpoints, API contracts, or secrets that analysis surfaces
  back here for the application-logic and API side. Re-check authorization
  before contacting discovered endpoints or using any credential; an
  artifact's scope does not authorize its backend. If REA is unavailable,
  state that limitation rather than claiming artifact coverage.
- Cloud infrastructure misconfiguration (exposed buckets, metadata
  endpoints, IAM) found incidentally during recon: treat as its own
  finding class — see
  [references/vulnerability-classes.md](references/vulnerability-classes.md).

## Work the investigation in stages

1. **Passive recon only.** Program policy, public docs/changelogs, DNS and
   certificate-transparency logs, public code repositories (leaked keys,
   old endpoints), job postings or engineering blog posts naming the
   stack, Wayback Machine snapshots, and publicly indexed data (Shodan/
   Censys-style). Distinguish third-party public records from direct
   target requests: endpoint probing, introspection, and active DNS
   enumeration require the authorization gate even when read-only.
2. **Enumerate the in-scope surface.** Subdomains, exposed endpoints, any
   published API spec (OpenAPI/Swagger, GraphQL introspection if not
   disabled), authentication flows, roles/tenants, third-party
   integrations. Build this into a written surface map before testing
   anything — by the time the investigation ends, every item on this map
   should be accounted for as confirmed, not reproduced, or
   explicitly unresolved (see "Evidence discipline" below).
3. **Fingerprint stack and versions.** Response headers, error pages,
   JS bundle source maps/comments, changelog or `/version` endpoints.
   Before inventing a novel attack, check
   [references/known-vulns-and-deltas.md](references/known-vulns-and-deltas.md)
   for a matching CVE/advisory against the identified stack and version —
   a version match is a lead; applicability and impact still need evidence.
4. **Select vulnerability classes from the surface map**, not the other
   way around: match each input, auth boundary, and trust boundary (client
   vs. server, user vs. admin, tenant vs. tenant, same-origin vs.
   cross-origin) to the classes in
   [references/vulnerability-classes.md](references/vulnerability-classes.md)
   that actually apply to it. Do not run every class against every
   endpoint.
5. **Probe with the smallest safe request.** Prefer read-only/idempotent
   requests before anything that mutates state. Stop at the point that
   confirms the vulnerability exists; do not escalate into full
   exploitation, lateral movement, mass data access, or anything the
   program's scope excludes. One clean reproduction beats ten noisy ones.
6. **Record every hypothesis tested**, confirmed or not, with its
   evidence: exact request/response (redacted of any other user's real
   data), the observed vs. expected behavior, and which class it maps to.
   This is the finding ledger the report in stage 7 draws from — keep it
   as you go, not reconstructed from memory at the end.
7. **Write the report** with
   [references/reporting.md](references/reporting.md): impact, exact
   reproduction steps, minimal PoC, and suggested remediation. Prepare a
   draft; send it only when the user explicitly authorizes submission,
   through the program's portal or agreed contact. Never disclose
   publicly before the program's disclosure policy allows it.

## Evidence discipline

Separate **observation** (what the request/response actually showed),
**inference** (what that implies, e.g. "likely IDOR" before a second
account confirms it), and **unknown** (what you could not test because
scope, access, or program rules didn't allow it). State severity using
CVSS when the program's platform expects it, and always include enough
detail for the triager to reproduce the issue from the report alone.

The finding ledger that stage 6 keeps and stage 7 reports from is one
entry per hypothesis, each with: stable ID; surface-map item and class;
authorization reference; timestamp; test roles/accounts and preconditions;
expected boundary; baseline/control and probe evidence; observation,
inference and unknowns; status (confirmed / not-reproduced / unresolved);
and severity with rationale for confirmed findings. Redact credentials,
session tokens and personal data at collection time, including your own.
Retain reproducibility with named placeholders and setup instructions.

"Not-reproduced" applies only to that test under its recorded conditions;
it does not mean the endpoint is clean. Untested or blocked hypotheses
stay unresolved with a reason. Summarize coverage per surface item from
its hypotheses; one confirmed bug or negative probe never closes all
other applicable classes on that item.

Never claim a finding is confirmed from passive/inferred evidence only.
Never claim the full attack surface was covered — name what was in scope
but not tested (time, access, or rules of engagement) as explicitly
unresolved, the same way an incomplete static analysis would be reported
as incomplete rather than exhaustive.

## Read only the relevant guide

- Authorization checklist, program types, and when to stop:
  [references/scope-and-authorization.md](references/scope-and-authorization.md)
- Vulnerability classes, what each needs as a minimal non-destructive
  probe, and what counts as confirmation:
  [references/vulnerability-classes.md](references/vulnerability-classes.md)
- Fingerprinting a stack/version and checking it against known
  CVEs/advisories before testing novel attacks:
  [references/known-vulns-and-deltas.md](references/known-vulns-and-deltas.md)
- Report structure per platform and responsible-disclosure timing:
  [references/reporting.md](references/reporting.md)

## Finish the task

Summarize findings in plain language, each tied to its ledger entry and
evidence. If nothing confirmed is found, say so plainly rather than
reporting a speculative or unconfirmed issue — a bad report costs the
program's triage time and the reporter's reputation. When the user wants
to fix a vulnerability in their own system (not report one on someone
else's), hand off to the available coding and security-review workflow.
