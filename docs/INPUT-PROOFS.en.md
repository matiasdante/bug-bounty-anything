# Bounded input checks (1.9.0)

[Español](INPUT-PROOFS.md) · **English**

Both tools reuse exact scope, `requestRules`, shared budget, and SQLite checkpoints. Inputs are generated or bound to config; credentials come from the environment. An incomplete run retains reservations and can resume only unstarted steps with the same scope/config.

## Template expression

`template-check` / `template_check` takes `schemaVersion: 1`, `class: "template-arithmetic"`, `policyReference`, `url`, `parameter`, `pointer`, `operands: [a,b,c]`, and `credentialEnv` (`null` or a `BBA_TOKEN_*` / `BBA_COOKIE_*` reference). Operands are distinct integers from 2 through 997. Scope must authorize the exact GET and query name. The engine sends literal `a*b`, `{{a*b}}`, and `{{b*c}}` to one resource, projects one JSON field, and stores digests only. It confirms **evaluation of this syntax** when the control remains literal and both expressions return their products. If both remain literal, the result is `not-reproduced`; other outcomes are `unresolved`. The operator must establish that the field should have treated input as literal text. SQL, NoSQL, command execution, files, and third party data are not tested. `resume-template-check` / `resume_template_check` uses the same scope/config.

## URL callback

`ssrf-callback-check` / `ssrf_callback_check` takes `schemaVersion: 1`, `class: "outbound-fetch"`, `policyReference`, `triggerUrl`, `queryName`, `credentialEnv`, `callbackUrl`, `receiptUrl`, and `receiptPointer`. Trigger, callback, and receipt must be exact scoped paths. The callback uses a separate origin you own and ends in an opaque token of at least 12 characters. Its receiver exposes a JSON boolean at `receiptPointer` that changes from `false` to `true` only after this callback.

The engine reads the receipt, sends the callback URL as a query value to the trigger, then polls the receipt at most twice. A `false` → `true` transition with trigger 200 demonstrates an outbound request to **that owned receiver**, assuming it is configured correctly and the declared policy forbids the destination. It does not prove internal network access, metadata access, or response disclosure. It never generates internal URLs, follows redirects, or sweeps destinations. `resume-ssrf-callback` / `resume_ssrf_callback` retains the limits.

The service's callback to the receiver is an additional request outside the BBA client's counter. Keep the receiver log and account for it in the program budget. Both reports cover what happened, discovery, proof, reproduction, and remediation without extrapolating severity.
