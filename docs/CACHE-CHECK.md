# Cache-correlated cross-identity exposure (1.9.0)

**English** · [Español](es/CACHE-CHECK.md) · [Português (Brasil)](pt-BR/CACHE-CHECK.md) · [简体中文](zh/CACHE-CHECK.md)

`cache-check` / `cache_check` sends seven exact GET requests to a resource you own with two controlled accounts. Configuration requires `schemaVersion: 1`, `class: "cross-identity-cache"`, `policyReference`, `identityUrl`, `identityPointer`, `resourceUrl`, `protectedPointer`, `accountA`, `accountB`, `bustQueryName`, and two distinct opaque `bustTokens`. Account values come from `BBA_TOKEN_*` or `BBA_COOKIE_*` environment variables, never the config. Scope must allow both routes, the query name, and at least seven requests.

The check establishes distinct identities and anonymous denial. It verifies that A can read the protected field with a cache-busting parameter and B cannot, warms the shared URL without that parameter as A, then reads it as B. `confirmed` requires B to receive A's protected field at the shared URL; `not-reproduced` requires B to be denied. Incomplete controls or B also reading the field with cache busting are `unresolved`, since general authorization failure may explain the result. `resume-cache-check` / `resume_cache_check` retains scope, accounts, config, and budget without repeating uncertain reservations.

The operator must verify that busting tokens have no semantic effect, the accounts do not share permission, and the resource belongs to them. This shows exposure **correlated** with caching; it does not identify the cache layer or key algorithm or establish other affected routes. Only projected facts and digests are retained, never the protected value. The five-section draft limits impact to the checked field.
