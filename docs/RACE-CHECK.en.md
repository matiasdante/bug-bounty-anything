# Single-use operation race (1.9.0)

[Español](RACE-CHECK.md) · **English**

`race-check` / `race_check` tests one single-use rule on **two disposable resources you own**. Config includes `schemaVersion: 1`, `class: "single-use-race"`, `policyReference`, `credentialEnv`, `actionUrl`, `actionField`, `controlResourceId`, `raceResourceId`, `controlStateUrl`, `raceStateUrl`, and `countPointer`. The three URLs must be exact, distinct, and on one origin. Scope needs JSON POST to `actionUrl`, GET to both state URLs, at least seven requests, and `minIntervalMs: 0`. Credentials are read from `BBA_TOKEN_*` or `BBA_COOKIE_*`.

The engine checks an initial count of zero, performs the action twice on the control resource, and requires rejection of the second use. If that control fails, **no race is run**. For the second resource it checks zero count, reserves two requests from the shared budget as a pair, and sends exactly two concurrent POSTs. `confirmed` requires both accepted, overlapping send windows, and final count two. One acceptance, final count one, and overlapping windows yield `not-reproduced`; all other cases are `unresolved`. Vulnerable and fixed variants are tested on synthetic loopback servers.

`artifact.json` seals the journal for `artifact-view`. A crash leaves uncertain reservations; this check never resumes or repeats state-changing actions. The operator must own, control, and clean up both resources and establish the single-use rule. A local double effect does not demonstrate financial impact or other affected routes. The report includes five sections and state evidence without credentials or bodies.
