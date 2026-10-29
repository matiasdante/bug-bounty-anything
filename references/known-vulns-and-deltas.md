# Known vulnerabilities and version deltas

Check this before inventing a novel attack. A target running an
identifiable, outdated component often already has a public advisory —
confirming that is faster and more reliable than discovering a new issue,
and it's still a legitimate, reportable finding when the program accepts
outdated-dependency reports.

## Fingerprint before searching

Pull the concrete signal first; searching a vague "looks like it might be
X" wastes time and produces false matches.

- **HTTP headers:** `Server`, `X-Powered-By`, cookie names (`JSESSIONID`,
  `laravel_session`, `_wordpress_session`), cache/CDN headers.
- **Error pages:** default framework error pages often name the exact
  framework and sometimes the version.
- **Static assets:** explicit versions in source maps, bundle comments or
  parameters may identify a component. A hash like `app.3f2a91.js` identifies
  a build, not a product version; attribute even `?v=6.4.2` to its component.
- **Well-known paths:** `/CHANGELOG`, `/README`, `/release-notes`,
  `/version`, `/.well-known/`, CMS-specific paths
  (`/wp-json`, `/wp-content`, `/sites/default/files` for Drupal,
  `/administrator/manifests` for Joomla).
- **Package manifests exposed by accident:** `package.json`,
  `composer.lock`, `requirements.txt`, `go.sum` reachable directly — useful
  fingerprints. Assess protected data and impact before claiming disclosure.
- **Client-side framework signatures:** React/Vue/Angular devtools
  hooks, build-tool banners left in bundled JS.

## Match the fingerprint to a known issue

- Search the exact product + version against: the vendor's own security
  advisories page, the National Vulnerability Database (NVD), GitHub
  Security Advisories for the project's repo, and the project's own
  CHANGELOG for entries that mention "security," "CVE," or "fix" near the
  identified version.
- Read vendor affected ranges, prerequisites, configuration and fixed
  releases; record the URL and lookup date. Account for backported fixes,
  disabled features and reachable code. A fix diff is supporting evidence,
  and may cover only part of the issue or one release branch.
- If the project is open source, diff the identified version against the
  next release that patched a relevant CVE. The actual code change (the
  "delta") tells you precisely what was vulnerable and exactly how to
  construct a non-destructive proof that the *unpatched* behavior is
  present — far more precise than guessing from the advisory's prose
  alone.

## Confirm safely — don't assume a version banner is accurate

- A version string in a header or changelog can be stale, spoofed, or
  simply wrong (some admins intentionally mask or fake it). Before
  reporting "vulnerable because version X," run the specific
  confirmation probe the advisory describes — the smallest non-
  destructive request that would only succeed if the unpatched code path
  is actually present — and only report it as confirmed if that probe
  succeeds against the live target.
- A banner match with no successful confirmation probe is a hypothesis in
  the finding ledger, not a confirmed finding: state it in the investigation summary as "fingerprint
  suggests version X (known advisory CVE-YYYY-NNNNN); could not confirm
  without an action outside program scope" rather than asserting the
  vulnerability as proven.

## Deltas across the target's own versions

When a target itself exposes multiple versions you can compare (a staging
environment one release behind prod and explicitly in scope, a mobile
app's current vs. previous release available for download, a public
changelog with enough detail), diffing them can surface:

- A security fix that was shipped silently (no CVE, no announcement) —
  confirm the pre-fix behavior is still reachable on the in-scope target
  before reporting it as live.
- A regression: a previously-fixed issue reintroduced by a later change.
- A feature flag or endpoint only present in one version, worth adding to
  the surface map.

For the *client-side* half of this (comparing app binaries/bundles across
versions, decompiling to see what changed), route to
`reverse-engineer-anything`'s version-comparison tools and bring the
resulting server-side/API implications back here.
