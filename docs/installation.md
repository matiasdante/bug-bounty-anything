# Installation and setup

**English** · [Español](es/installation.md) · [Português (Brasil)](pt-BR/installation.md) · [简体中文](zh/installation.md)

How to install the BBA skill, run it from source or from npm, diagnose the local environment, and register the MCP server. For commands that send requests, see the [CLI guide](cli.md).

## Invoke the skill

With project dependencies available:

```powershell
npm run build
node dist/cli.js install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
```

The output directory must be new. Installation copies instructions, references, and UI metadata; `runtime.json` points to this package's Node runtime and compiled CLI. Keep the project at that location. The command does not install dependencies or change MCP or other skills. Start a new chat if the skill catalog has not refreshed. `update-skill --out <existing-directory>` updates managed files, keeps a backup in `.bba-backups/`, checks that the installation belongs to this package, rejects resource links, and preserves unrelated files. `installation.json` stores managed file hashes; an interrupted update is never reported as complete.

For Claude Code, Codex, or Gemini CLI, `npm run package:skill -- --out dist-skill.zip` builds a portable ZIP with the compiled CLI, `SKILL.md`, and references. The older Windows PowerShell packager remains available. Unpack `bug-bounty-anything` into `.claude/skills/` or `~/.claude/skills/`. Initial MCP registration exposes offline tools only; install Chromium separately when browser checks are needed.

Ask the agent, for example, **`$bug-bounty-anything investigate https://authorized-service/ and prepare findings`**. The agent looks up current policy and creates the required files. It asks only for facts it cannot establish, such as test accounts or an access rule. Without authorization it stops active checks on that asset; public research may continue. The skill works through the CLI without requiring MCP and delegates client artifact analysis to REA where appropriate.

If policy or an authorization window is missing, `start-case --target <url> --out <directory>` records a pending case without creating a scope or making requests. Once permission is established, use `prepare`:

```powershell
node dist/cli.js prepare --scope scope.json --target https://authorized-service/ --out runs/investigation
```

This creates a scope copy, anonymous GET seed plan, checksummed case record, and investigation notes. It does not contact the target or prove permission. It rejects excluded or out of scope URLs, expired windows, and existing outputs. MCP also exposes `prepare` without enabling network access. A `budgetId` shares a persistent request count, interval, and duration across phases next to the canonical scope file; older scopes keep per-run limits.


## Requirements and local run

- Node.js **22.13.0 or newer**, with npm. Node provides TypeScript type stripping during development and native SQLite. The only production dependency is `playwright-core` 1.64.1 (Apache-2.0).
- For development or tests on Node 22.13, enable native TypeScript stripping with `$env:NODE_OPTIONS = '--experimental-strip-types'` in PowerShell. The published package runs compiled JavaScript and does not need this option.
- Run `npm install` and `npx playwright-core install --only-shell chromium` for capture and browser checks. Chromium downloads outside the repository. Other commands do not require it.
- Local labs and the inspector need connections to `127.0.0.1`. If a sandbox blocks loopback, run from a local terminal where it is allowed.

```powershell
npm run bba -- lab --variant vulnerable --out runs/vulnerable
npm run bba -- lab --variant fixed --out runs/fixed
npm run bba -- inspect runs/vulnerable
npm run bba -- report runs/vulnerable --out runs/vulnerable-export.md
npm run demo:core -- --out runs/core-demo
npm test
```

On PowerShell installations that block `npm.ps1`, use `npm.cmd`. Output files and directories must be new; BBA does not overwrite an investigation. `lab` starts a disposable server on `127.0.0.1`, creates two synthetic accounts and documents, sends five sequential requests, and shuts down even on error. Credentials stay in memory. `inspect` and `report` read verified local evidence without network access; `report` rebuilds the report from JSON. `demo:core` runs a second lab and writes SQLite checkpoints, a scope and plan without credentials, JSON export, and a report. Do not reuse its ephemeral credentials or port.


## Installation, diagnosis, and MCP

For a one-off CLI run directly from npm, without a global installation:

```powershell
npx --yes bug-bounty-anything@latest capabilities
npx --yes bug-bounty-anything@latest --help
```

`npx` downloads the published package and runs its `bba` command. For a persistent skill or MCP registration, install the package globally: registrations store the CLI path, and a temporary `npx` cache entry may later disappear.

```powershell
npm install --global bug-bounty-anything@latest
bba install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
bba doctor
```

For browser checks, install Chromium separately with `npx playwright-core install --only-shell chromium`. In the source repository, `npm install`, `npm run build`, and `npm test` remain the development commands. The public package and code use the [MIT license](../LICENSE).

The package exposes `bba`, including grouped `campaign`, `check`, and `study` subcommands, per-command help, and `--lang es|en`. `doctor` checks only local Node, SQLite, loopback, temporary storage, Chromium, and names (never values) of present `BBA_TOKEN_*`, `BBA_COOKIE_*`, `BBA_HEADER_*`, `BBA_INPUT_*`, and `BBA_BODY_*` variables.

```powershell
bba mcp --root C:/path/to/workspace
bba mcp --root C:/path/to/workspace --allow-network
```

MCP runs over stdio JSON-RPC with `initialize`, out-of-band `ping`, real cancellation through `notifications/cancelled`, and `tools`. `tools/list` is authoritative; active tools only appear with `--allow-network`. Paths are confined to `--root` on Windows and POSIX, including symlink and junction escapes; internal errors are sanitized. `setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` previews or applies registration with local backups.


