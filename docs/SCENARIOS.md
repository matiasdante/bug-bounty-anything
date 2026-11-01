# Controlled scenarios with a real browser session

**English** · [Español](es/SCENARIOS.md) · [Português (Brasil)](pt-BR/SCENARIOS.md) · [简体中文](zh/SCENARIOS.md)

```powershell
node dist/cli.js browser-scenario --scope scope.json --config scenario.json --out runs/scenario
```

MCP: `browser_scenario`, only with network enabled. It runs a declared workflow in an ephemeral Chromium context: navigation, filling fields, clicking, and waiting for a visible selector. Login cookies and rotation are applied in memory from real Set-Cookie attributes. Output records observations, not an automatic vulnerability claim.

## Contract

`scenario.json` has exactly `schemaVersion: 1`, `policyReference`, `boundary: "controlled-workflow"`, `sessionOrigin`, `plan`, `actions`, `maxRedirects`, and `observe`.

- `sessionOrigin` is the allowed origin to which browser-generated cookies/Bearer may return.
- `plan` is the `run` contract with up to 100 known requests, all with `credentialEnv: null`. Session credentials come from the browser; login data comes from actions and environment-bound bodies. Outside `sessionOrigin`, only GET is allowed and credentials are withheld.
- `actions` contains 1–30 items, starting with navigate. Forms include `{ "kind": "navigate", "stepId": "home" }`, `{ "kind": "fill", "selector": "#username", "valueEnv": "BBA_INPUT_USER" }`, `{ "kind": "click", "selector": "#submit" }`, and `{ "kind": "wait", "selector": "#dashboard" }`.
- `maxRedirects` is 0–5. Every destination must match a declared request, including method and body when Chromium supplies them.
- `observe` has up to 20 `{ "name": "identity", "selector": "#identity", "attribute": null }` entries. Null reads textContent; an attribute may be selected instead. Presence, digest, and truncation at 4,096 characters are retained.

Complete URL, method, and body bytes are matched before sending. A known form may use `body: { "format": "form", "valueEnv": "BBA_BODY_LOGIN" }` and fill actions with `BBA_INPUT_USER` / `BBA_INPUT_PASSWORD`. Expected body must match form serialization exactly, including order, encoding, and hidden fields. Missing inputs or different/dynamic unbound bodies are blocked. POST/PUT/PATCH/DELETE need explicit scope rules, owned resources, and cleanup for state changes.

## Isolation and fidelity

CDP Fetch intercepts every redirect hop; Playwright routes alone cover only the first URL. Browser network policy remains active and direct redirect following is disallowed. Rejecting proxy and WebRTC policy remain active; service workers, WebSockets, and downloads are blocked. The relay sends selected Set-Cookie and CSP/CORS headers back to Chromium. It forwards browser-produced cookies/Bearer only to `sessionOrigin`, never uses a personal browser profile, persists a session, or sends those headers to another origin. Login forms, dynamic tokens, and SSO domains are not inferred; extra windows/providers need explicit definitions.

Queries, expected bodies, and fill values come from the environment. Never place credentials in selectors, IDs, base URLs, or references. Steps can project JSON response facts like `run`. There is no resumable browser session checkpoint: after a crash, budget/reservations remain but the session is lost.

## Artifacts

`scope.json` and `config.json` retain references, not values. `requests.jsonl` synchronizes reservations before sending and stores metadata/facts, completed actions, and sanitized network errors. `scenario.json` stores outcomes, counts, DOM facts, and checksum. `artifact.json` seals journal, result, and sources for paginated `artifact-view`. Bodies, passwords, cookies, and tokens are never saved. A completed action or DOM change shows observed behavior, not security. A report needs an expected rule, controls, identity/state, and impact evidence. Local tests cover form login, redirects, two cookies, rotation, authenticated read, redaction, and undeclared-request blocking.
