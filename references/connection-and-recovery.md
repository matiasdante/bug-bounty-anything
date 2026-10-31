# Connection and recovery

[Español](connection-and-recovery.es.md) · **English**

Use this only for an observed runtime/connection blocker. The skill can guide an
investigation with existing tools without an MCP server. Do not probe unrelated
client configuration or reinstall dependencies before identifying the failure.

## Installed skill or repository

- Installed skill: read `runtime.json` beside `SKILL.md`. `command` is the Node
  executable and `args` contains the absolute built CLI path. Keep it as an
  argument array, with working directory/output paths in the case workspace.
- Repository: `node src/cli.ts --help`; built package: `node dist/cli.js --help`.
  Node 22.13+ is required. For a one-off run, use
  `npx --yes bug-bounty-anything@latest --help` from the public npm registry.
  Confirm the package identity before using a similarly named package.
- Missing built CLI: from the trusted package source run `npm run build` with
  existing prerequisites. If the package moved, install to a new skill directory
  from its current location or update only the stale runtime path under the
  host's actual write permissions. Do not overwrite another installation.
- For persistent skill or MCP setup, prefer
  `npm install --global bug-bounty-anything@latest`: registrations retain the
  CLI path, while a temporary `npx` cache entry may be removed.
- To install explicitly: `node dist/cli.js install-skill --out <new-skill-directory>`.
  In this user's environment personal skills live in `~/.agents/skills/`.
  The command copies instructions/references/UI metadata and records the runtime
  path; it does not copy dependencies or configure MCP. Keep the referenced
  package directory available. An existing destination is refused.
- For an explicit update of this package's existing skill, use
  `node dist/cli.js update-skill --out <existing-skill-directory>`. It verifies
  the runtime's package binding, rejects linked resources, backs up managed
  resources under `.bba-backups/` and preserves unrelated files. It does not
  update dependencies or MCP. Review the reported backup; do not delete a
  stale `.bba-update.lock.sqlite` until checking an interrupted update's files.

Skill discovery can require a fresh chat or restart. A directory on disk is not
proof that the current agent's skill catalog refreshed. Reading its `SKILL.md`
explicitly still permits using the workflow in the current chat.

## Diagnose the affected capability

Use CLI `doctor` once when local prerequisites are uncertain. It contacts no
remote target. Inspect individual checks: missing Chromium affects browser
capture, page inspection and browser proofs, not import, HTTP execution, `prepare` or `hunt`. A failed loopback check
can be a host sandbox restriction. Report that reason; do not weaken destination
validation, disable TLS or disguise blocked requests.

Do not install Node, browser binaries or packages unless that installation is
within the user's task authorization and host access. Explain any download first.
Use existing CLI/offline capabilities while a provider is unavailable.

## Codex MCP registration

From the built package, run `node dist/cli.js setup-mcp --root <case-workspace>`
for a read-only preview. Add `--apply` to register `bba` with `codex mcp add`.
The command refuses to replace a different `bba` entry unless `--replace` is
provided, backs up an existing `~/.codex/config.toml` under
`~/.codex/.bba-backups/`, and checks the new entry
with `codex mcp get bba`. It does not install Codex or dependencies. The default
registration advertises offline tools only; append `--allow-network` only when
the agent should have access to active tools. An individual target still needs
a valid, reviewed scope. Reconnect Codex and confirm `tools/list` after setup.

## Manual MCP

For an explicitly requested MCP registration, prepare a reviewable change to the
client's existing config using the real Node and built CLI paths and one selected
workspace root:

```json
{
  "command": "<absolute-node-executable>",
  "args": ["<absolute-package>/dist/cli.js", "mcp", "--root", "<case-workspace>"]
}
```

Resolve these illustrative paths before editing configuration. Offline tools are
the default. Add `--allow-network` only for authorized target execution; this flag
is a server capability switch, not evidence of asset-owner permission. The server
inherits credentials/header values from its environment, never tool arguments.
Restrict access to that process.

Preserve existing servers and secrets. Registration requires client reconnection;
verify actual tool discovery afterward. If a client blocks a call, inspect that
specific launch/policy error. Do not repeat setup or claim the CLI proved MCP works.

MCP paths are confined to `--root`; keep scope/input/output files there. A scope
is an operator assertion, not a signed program policy. Anyone who can edit it
can change its claims, so review workspace write access before enabling network.
