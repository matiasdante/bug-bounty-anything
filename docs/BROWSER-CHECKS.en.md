# XSS and CORS checks in Chromium

[Español](BROWSER-CHECKS.md) · **English**

`browser-check --scope scope.json --config browser.json --out <new-directory>` and MCP `browser_check` run finite comparisons against controlled data and origins. Chromium, authorized scope, and allowed techniques are required. Headers or reflected text alone are insufficient evidence.

All requests use BBA's transport. Only GETs whose complete URL, method, and environment-bound inputs match declared steps are sent. CSP, CORS, origin isolation, and `nosniff` headers are preserved; redirects are not followed. Service workers, WebSockets, downloads, and off-plan access are blocked. The rejecting loopback proxy and WebRTC policy remain active. `budgetId` activates the shared budget.

## Common fields

Use `schemaVersion: 1`, `class`, `policyReference`, `observationMs` (50–5000), `baseline`, `probe`, and `resources`. Steps use the `run` contract: unique ID, GET, base URL, `credentialEnv`, and optional query input from `BBA_INPUT_*`. `resources` lists assets the pages actually require; discovered hosts are not added automatically. These checks do not accept request bodies or projections.

## XSS

Set `class: "xss"`, `boundary: "untrusted-input-script"`, and `markerEnv: "BBA_INPUT_MARKER"`. Baseline and probe navigate the same base URL with the same credentials but different concrete inputs. The unique opaque marker is 12–128 alphanumeric, hyphen, or underscore characters. The agent prepares benign input and a minimal context-specific payload that attempts `window.__bbaProof(marker)`. The payload stays in an environment variable, not the plan or report. Chromium exposes the function solely to observe the expected marker called from the application origin. It never reads cookies, files, tokens, or other users' data.

The check confirms only when the probe executes the marker and baseline does not. Escaped text or CSP blocking does not confirm. Execution in both controls, blocked required assets, exhausted budget, and failures remain inconclusive. A negative result covers only the observed input, context, and window. The operator must show attacker control and an unintended executable context; self-XSS or intended HTML is not automatically reportable. There is no universal payload generator or stored XSS test that might reach real users.

## CORS

Set `class: "cors"`, `boundary: "private-cross-origin-read"`, `protectedPointer`, and `target` (GET of private data). Baseline opens a page at the target origin; probe opens a page at a different, controlled, allowed origin. Configure the cookie:

```json
"cookie": {
  "origin": "https://service.example",
  "valueEnv": "BBA_COOKIE_A",
  "sameSite": "Lax"
}
```

The target's `credentialEnv` must match this cookie. Only target-origin steps may use it; the foreign page never receives it from the relay. The value is a `name=value; name2=value2` cookie string. Chromium receives test cookies with declared URL and SameSite; Secure derives from HTTPS. This must model the actual session. BBA neither infers cookie attributes nor automates login/rotation.

An anonymous control, same-origin read, and foreign-origin `fetch` with `credentials: "include"` are performed. The relay preserves `Origin`, CORS headers, and actual browser cookie delivery; it never adds a cookie omitted by Chromium. Confirmation requires anonymous denial and successful foreign-origin browser read of the same private field. Chromium rejects `Access-Control-Allow-Origin: *` with credentials. Probe 401, public data, different values, and insufficient evidence remain inconclusive. If the relay received data but the browser could not read it, that particular read was not reproduced; this says nothing about every CORS policy. The attacker origin and cookie attributes are material report preconditions.

## Evidence and recovery

Scope/config copies exclude environment values. `requests.jsonl` synchronizes reservations before sending and stores minimal responses and redacted comparisons. `browser-check.json` stores observations, outcome, and checksum; `artifact.json` links journal, result, and sources for paginated `artifact-view`. `report.md` is a draft. Bodies, cookies, payloads, and the original marker are not saved; reconstruct safe inputs and exact preconditions before reporting.

Browser checks cannot resume. After a crash, review journal and shared-budget uncertain reservations before a new output directory. Duration, interval, byte, 3xx/429/5xx, and cancellation stops still apply. Synthetic vulnerable/fixed apps, CSP, wildcard CORS, absent credentials, filtered data, and expired sessions were tested.
