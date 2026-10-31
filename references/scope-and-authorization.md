# Scope and authorization

[Español](scope-and-authorization.es.md) · **English**

This is the gate every other part of BBA sits behind. Work through it
before active testing, including read-only probes and introspection.
Reading public policy/contact pages is allowed to establish authorization;
whether a request looks like normal browsing does not establish permission.

## 1. Identify the program and read its current policy

- Ask the user which program/platform, or find it yourself: search
  `site:hackerone.com`, `site:bugcrowd.com`, `site:yeswehack.com`,
  `site:intigriti.com`, or the vendor's own `/security`, `/.well-known/
  security.txt`, or `/vulnerability-disclosure` page.
- `security.txt` (RFC 9116) at `/.well-known/security.txt` is itself public
  recon and often the fastest way to find the real contact/policy URL when
  no third-party platform is involved.
- Its presence or a disclosure contact alone does not authorize testing;
  follow the linked policy ([RFC 9116, section 5.5](https://www.rfc-editor.org/rfc/rfc9116.html#section-5.5)).
- Alternatively, use explicit written authorization from the asset owner:
  record who authorized which assets, techniques, test window and reporting
  channel. A public program is not required for this route.
- Read the policy page itself, now — not a cached memory of it, a
  write-up, or a script's hardcoded assumption. Programs change scope,
  add exclusions, or pause/close without notice.

## 2. Confirm the exact asset is in scope

- Match the literal domain/subdomain, mobile package ID, API base URL, or
  IP range against the policy or written authorization. A sibling subdomain or a
  look-alike domain is not automatically in scope just because it's owned
  by the same company.
- Check the exclusion list explicitly — it is as binding as the inclusion
  list. Common exclusions: staging/demo environments, third-party SaaS the
  company merely uses (support desk, status page, marketing site on a
  different platform), acquired products not yet migrated, and anything
  explicitly marked "out of scope" even if technically reachable from an
  in-scope asset.
- If the user names a target and you cannot find it on any current scope
  list, authorizing VDP policy or written permission, say so and stop — do not assume authorization because
  the company "probably has a program somewhere."

## 3. Confirm allowed techniques and classes

Almost every program bans some subset of:

- Automated scanners run without rate limiting, or any volume that could
  degrade service.
- Social engineering, phishing, or physical-access attempts against
  employees or offices.
- Testing against other users' real accounts or data; the program expects
  you to create and test only your own test account(s).
- Spam, mass account creation, or anything that degrades the product for
  real users.
- Attacking third-party vendor infrastructure the target merely uses
  (cloud provider, CDN, email provider) — report *misconfiguration by the
  target* on third-party infra, never attack the vendor itself.
- Reporting findings from automated scanner output alone without manual
  validation (many programs require this and will close such reports as
  invalid).

Read the specific program's list — it varies. When unstated, assume the
most conservative reading.

### Operational limits of this workflow

These are BBA's conservative workflow limits, not a quotation of a model's
policy. The session's actual tool and safety rules still apply.

- Exclude DoS/load testing, social engineering and evasion of CAPTCHA or
  bot-detection controls. Stop or use the program's documented test access.
- Use accounts and synthetic data you control, created through the
  program's permitted signup flow or supplied by it. Test accounts do not
  authorize access to real users' data.
- Exercise financial logic only with the program's designated sandbox
  and test funds; do not place real orders, transfer money or use real cards.
- Scope does not expand through redirects, CNAMEs, callbacks or backend
  discovery. Check each new destination before following it; do not forward
  cookies, authorization headers or identifying markers to unrelated hosts.
- For outbound callbacks, use an approved endpoint you control and opaque
  correlation markers. Do not send target data or secrets to public services.
- Stop on unexpected personal data, service degradation, rate-limit
  responses or effects outside test resources. Record minimal redacted
  evidence, avoid retries that worsen the effect, and report the limitation.

## 4. Note operational constraints

- Rate limits or a maximum request volume per day/hour.
- A required test-account signup flow, or test data/sandbox the program
  provides instead of touching production data.
- A required identifying marker (specific header, user-agent substring,
  or a note in a specific field) so the target's security team can
  distinguish authorized testing from an attack in their logs. Add it to
  every active request once known.
- Record any safe-harbor conditions as written; do not describe them as
  an unconditional legal guarantee. Unstated operational limits are not
  unlimited permission: keep probes manual and minimal, and resolve any
  uncertainty material to the intended test before running it.

## 5. When something cannot be confirmed

- No current policy or written authorization covers the test, or the asset is
  ambiguous between in-scope and excluded: stop active testing on that
  asset specifically. Continue only passive, already-public reconnaissance
  (steps that a normal browser/search engine visit would also do), and
  tell the user plainly what is missing.
- With neither an authorizing policy nor explicit written permission,
  do not perform active testing. Record the missing authorization without
  making a legal determination about the target or the user.
- A multi-asset target (one company, several domains/apps) can have
  different scope per asset, or different programs entirely (e.g. web app
  on HackerOne, mobile app self-managed). Re-run this checklist per asset,
  not once for the whole company.

## Re-verification

Scope changes. Re-check the policy or written authorization's validity at the start of a new session on
the same target, and whenever an unexpected asset or subdomain turns up
during recon that was not already confirmed in scope.
