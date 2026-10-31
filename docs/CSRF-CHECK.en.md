# Cross-origin form against owned state (1.9.0)

[Español](CSRF-CHECK.md) · **English**

`csrf-check` / `csrf_check` uses Chromium to send **one** POST form from a declared attacker origin to an action on an account you control. Config fields are `schemaVersion: 1`, `class: "cross-origin-form"`, `policyReference`, `attackerPageUrl`, `stateUrl`, `actionUrl`, `cookieEnv`, `sameSite`, `formField`, `formValue`, `statePointer`, `beforeValue`, and `afterValue`. Scope must allow both origins, GET for attacker page and state, form POST to the exact action, and at least five requests. The `BBA_COOKIE_*` value comes from the environment and is never persisted.

The engine checks initial state and anonymous denial. It then opens the attacker page in an isolated browser context, constructs the declared simple form, verifies that Chromium sends the expected cookie and `Origin`, and compares final state. `confirmed` requires the declared transition and a successful response. If state does not change and the browser omits the cookie or the server denies the action, the result is `not-reproduced`; incomplete controls are `unresolved`. It does not infer or force other SameSite settings, dynamic tokens, or undeclared actions.

The operator creates and restores test state. Calling the result **CSRF** requires a genuinely cross-site attacker and an action that requires authenticated intent under the policy. Two `127.0.0.1` lab ports are separate origins but may be the same site; that lab only validates the engine's form/cookie/state workflow. `artifact-view` reads the sealed journal. A crash requires inspection; the action is not retried.
