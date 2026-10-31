# Reporting and responsible disclosure

[Español](reporting.es.md) · **English**

A finding is only worth something once it's reported through the right
channel, in a form the triager can act on without extra back-and-forth.
Build the report from the finding ledger kept during testing — don't
reconstruct steps from memory at the end.

Prepare the draft and evidence first. Submit or contact anyone only with
the user's explicit authorization for that action; testing permission
does not by itself authorize sending a report. Record submission ID/status
only after the portal or recipient channel confirms delivery.

## Report structure (platform-agnostic core)

Every platform's form varies, but a strong report always has:

1. **Title** — one line, specific: vulnerability class + affected
   endpoint/feature, not "security issue found."
   e.g. "IDOR on `GET /api/orders/{id}` allows reading other users' orders."
2. **Summary / impact** — one paragraph: what an attacker can do, to
   whom, and the realistic worst case. Avoid both understating (missing
   why it matters) and overstating (claiming "full account takeover" for
   something narrower).
3. **Severity** — follow the current program's rubric. When using CVSS,
   specify its version, full vector, score and rationale. Separate proven
   impact from plausible consequences requiring additional conditions.
4. **Affected asset(s)** — exact URL(s), parameter(s), endpoint(s), app
   version — matched to the confirmed policy or written authorization.
5. **Steps to reproduce** — numbered, exact: literal requests (method,
   URL, headers, body) or literal UI actions, in order, starting from a
   state the triager can also reach (e.g. "create two free-tier
   accounts A and B"). A triager who can't reproduce it will mark it
   "unable to reproduce" regardless of how real the bug is.
6. **Proof of concept** — the minimal evidence: redacted
   request/response pairs, a short screen recording, or a `curl` command.
   Redact any other real user's actual data, your own session tokens
   (unless the token's structure itself is the finding, in which case
   show its structure, not a currently-valid one), and any credential/key
   found in information-disclosure findings — state that it was found and
   where, not the live value.
7. **Suggested remediation** — a concrete, specific fix (e.g. "enforce
   server-side ownership check on `order_id` before returning the
   resource"), not a generic "add input validation."
8. **CWE/CVE reference** — when the finding maps to a known category
   (CWE) or a specific known advisory already confirmed in
   known-vulns-and-deltas.md.

## Platform notes

- **HackerOne / Bugcrowd / Intigriti / YesWeHack:** use the platform's own
  structured submission form — it already encodes most of the sections
  above as fields. Fill every field the form asks for; don't paste a
  freeform report into the summary box and leave the rest blank.
- **Vendor's own VDP (no third-party platform):** follow the exact
  contact method stated on their `/security` or
  `/.well-known/security.txt` page (often a specific email with a PGP
  key). Use the structure above as the email body. If they ask for
  encrypted submission, do not send it in plaintext.
- **No bounty, VDP only:** report the same way — a VDP without a paid
  bounty is still a legitimate authorized-disclosure channel and the
  correct destination; it is not a reason to skip the report or to
  disclose elsewhere instead.

## Responsible disclosure timing

- Submit through the program's channel first, always. Never post details
  publicly (blog, social media, a public issue tracker) before the
  program's own disclosure policy allows it.
- If the program states a disclosure timeline (e.g. "90 days after fix or
  triage"), that clock is the program's to run, not something to assume
  satisfied just because time has passed without a reply — if the
  program is unresponsive well past its own stated SLA, that is a
  question for the user to decide on (whether to follow up, escalate
  through the platform, or wait longer), not something to act on
  unilaterally.
- Keep the finding ledger and any PoC material private; share it only
  with the program and, if requested, the platform's mediation team.

## Before submitting, check

- Scope: is this exact asset still covered by the policy or written
  authorization (re-check validity if time has passed since recon)?
- Duplication: search the program's public disclosed-reports (if any are
  published) for the same class on the same endpoint — a near-duplicate
  still ages the triager's patience even if not an exact match.
- Severity honesty: does the PoC actually demonstrate the claimed impact,
  or does the report describe a worse scenario than what was proven?
- Completeness: could a triager who has never seen the target reproduce
  this from the report alone?
