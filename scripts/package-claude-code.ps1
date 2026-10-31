$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$package = Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json
$version = $package.version
$output = Join-Path $projectRoot "bug-bounty-anything-$version-claude-code-manual.zip"
$partial = "$output.partial"
if (Test-Path -LiteralPath $output) { throw "Archive already exists: $output" }
if (Test-Path -LiteralPath $partial) { throw "Partial archive already exists: $partial" }
trap { if (Test-Path -LiteralPath $partial -PathType Leaf) { Remove-Item -LiteralPath $partial -Force }; break }
foreach ($required in @('SKILL.md', 'dist/cli.js', 'node_modules/playwright-core/package.json')) {
  if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $required) -PathType Leaf)) {
    throw "Missing required package file: $required"
  }
}
$dependency = Get-Content -LiteralPath (Join-Path $projectRoot 'node_modules/playwright-core/package.json') -Raw | ConvertFrom-Json
if ($dependency.version -ne $package.dependencies.'playwright-core') { throw 'The bundled playwright-core version differs from package.json' }

$skill = (Get-Content -LiteralPath (Join-Path $projectRoot 'SKILL.md') -Encoding UTF8 -Raw).Replace("`r`n", "`n")
if (-not $skill.Contains("version: `"$version`"")) { throw 'Skill and package versions differ' }
$eol = "`n"
$metadataLine = [regex]::new('(?m)^metadata:[ \t]*$')
if (-not $metadataLine.IsMatch($skill)) { throw 'Skill frontmatter metadata boundary missing' }
$skill = $metadataLine.Replace($skill, ('disable-model-invocation: true' + $eol + 'metadata:'), 1)
function Replace-Section([string]$body, [string]$start, [string]$end, [string]$replacement) {
  $first = $body.IndexOf($start, [System.StringComparison]::Ordinal)
  if ($first -lt 0) { throw "Missing skill section: $start" }
  $last = $body.IndexOf($end, $first, [System.StringComparison]::Ordinal)
  if ($last -lt 0) { throw "Missing skill section boundary: $end" }
  return $body.Substring(0, $first) + $replacement + $body.Substring($last)
}
$connection = @'
For Claude Code, this extracted folder contains the compiled BBA CLI and its
production dependency. Follow [Claude Code installation](INSTALL-CLAUDE-CODE.md)
to register its local stdio MCP server. Its default mode exposes offline tools.
Network tools require a deliberate `--allow-network` registration and a valid
per-target scope; do not infer that a connected MCP grants target permission.
Reconnect Claude Code and inspect `/mcp` after changing the registration.

'@
$skill = Replace-Section $skill 'For a requested MCP connection,' 'Use `capabilities` when coverage is uncertain;' $connection
$runtime = @'
Without MCP, use `node dist/cli.js` from this extracted skill folder. The
runtime and `playwright-core` are bundled here; Node.js 22.13 or later is required.
Store case outputs in the investigation workspace, outside the skill folder.

'@
$skill = Replace-Section $skill 'Without MCP, use the local CLI.' 'If the runtime is missing' $runtime

$install = @'
# BBA for Claude Code

[Español](INSTALL-CLAUDE-CODE.es.md) · **English**

This ZIP is a filesystem skill, not a direct Claude Code upload. Extract its
`bug-bounty-anything` folder under either `<project>/.claude/skills/` or
`~/.claude/skills/`. Claude Code then finds `SKILL.md` and the supporting files.
This variant is manually invoked with `/bug-bounty-anything`; it will not
activate itself on unrelated conversations. Claude Code's safety review still
applies when you invoke it.

Requires Node.js 22.13 or later. The ZIP includes the compiled CLI and
`playwright-core`; it does not include Chromium. From the extracted folder,
check the runtime with `node dist/cli.js capabilities`.

To connect the offline MCP server, run this in the project you will use for
investigations, replacing both placeholders with absolute paths:

```text
claude mcp add --transport stdio bba -- node <absolute-skill-folder>/dist/cli.js mcp --root <absolute-investigation-workspace>
claude mcp get bba
```

The default registration exposes only offline tools. If the target program
permits active testing and you have prepared an exact, current scope, register
the server with `--allow-network` after the workspace path. Review and replace
an existing registration deliberately; do not reset budgets. Restart or
reconnect Claude Code, then inspect `/mcp` and invoke `/bug-bounty-anything`.

Chromium is needed only for browser capture and browser-based checks. If those
are needed, install its headless shell explicitly with:

```text
node <absolute-skill-folder>/node_modules/playwright-core/cli.js install --only-shell chromium
```

That command downloads a browser outside this ZIP. Credentials are supplied
through `BBA_TOKEN_*`, `BBA_COOKIE_*` and other documented environment names,
never as MCP arguments. The skill and MCP do not authenticate a program policy
or guarantee a vulnerability on any target.
'@
$installEs = @'
# BBA para Claude Code

**Español** · [English](INSTALL-CLAUDE-CODE.md)

Este ZIP contiene una skill de archivos. Descomprimí `bug-bounty-anything` en
`<proyecto>/.claude/skills/` o `~/.claude/skills/`. Claude Code detecta
`SKILL.md` y sus archivos de apoyo. Esta variante se invoca manualmente con
`/bug-bounty-anything`; la revisión de seguridad de Claude Code sigue vigente.

Requiere Node.js 22.13 o posterior. El ZIP incluye CLI compilado y
`playwright-core`, pero no Chromium. Desde la carpeta extraída, comprobá
`node dist/cli.js capabilities`.

Para registrar MCP offline, ejecutá desde el proyecto de investigación con
rutas absolutas reales:

```text
claude mcp add --transport stdio bba -- node <carpeta-skill-absoluta>/dist/cli.js mcp --root <workspace-investigacion-absoluto>
claude mcp get bba
```

El modo inicial expone solo herramientas offline. Si el programa permite
pruebas activas y preparaste un scope vigente y exacto, registrá con
`--allow-network` después del workspace. Revisá cualquier registro existente
y reemplazalo deliberadamente; no reinicies presupuestos. Reconectá Claude
Code, inspeccioná `/mcp` e invocá `/bug-bounty-anything`.

Chromium hace falta solo para captura y pruebas de navegador. Si se necesita:

```text
node <carpeta-skill-absoluta>/node_modules/playwright-core/cli.js install --only-shell chromium
```

La descarga va fuera del ZIP. Las credenciales se pasan mediante `BBA_TOKEN_*`,
`BBA_COOKIE_*` y otras variables documentadas, nunca como argumentos MCP.
La skill y MCP no autentican una política ni garantizan fallas en un target.
'@

$archive = [System.IO.Compression.ZipFile]::Open($partial, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  $prefix = 'bug-bounty-anything/'
  function Add-Text([string]$name, [string]$body) {
    $entry = $archive.CreateEntry($prefix + $name, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    try {
      $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
      try { $writer.Write($body) } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
  }
  function Add-File([System.IO.FileInfo]$file) {
    if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Link in package: $($file.FullName)" }
    $rootPrefix = $projectRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $file.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "File outside project root: $($file.FullName)"
    }
    $relative = $file.FullName.Substring($rootPrefix.Length).Replace([char]92, [char]47)
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $archive, $file.FullName, ($prefix + $relative), [System.IO.Compression.CompressionLevel]::Optimal)
  }
  Add-Text 'SKILL.md' $skill
  Add-Text 'INSTALL-CLAUDE-CODE.md' $install
  Add-Text 'INSTALL-CLAUDE-CODE.es.md' $installEs
  foreach ($item in @('package.json', 'package-lock.json', 'README.md', 'README.en.md', 'SKILL.es.md', 'dist', 'docs', 'references', 'agents', 'cases', 'node_modules/playwright-core')) {
    $path = Join-Path $projectRoot $item
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing package item: $item" }
    if ((Get-Item -LiteralPath $path).PSIsContainer) {
      foreach ($file in (Get-ChildItem -LiteralPath $path -File -Recurse -Force)) { Add-File $file }
    } else { Add-File (Get-Item -LiteralPath $path) }
  }
} finally { $archive.Dispose() }

$check = [System.IO.Compression.ZipFile]::OpenRead($partial)
try {
  $names = @($check.Entries | ForEach-Object FullName)
  if ($names.Count -lt 150 -or $names.Count -ne @($names | Select-Object -Unique).Count) { throw 'Invalid archive entry count or duplicate' }
  foreach ($required in @('SKILL.md', 'INSTALL-CLAUDE-CODE.md', 'dist/cli.js', 'node_modules/playwright-core/package.json', 'docs/ROADMAP.md')) {
    if ($names -notcontains ('bug-bounty-anything/' + $required)) { throw "Missing archive entry: $required" }
  }
  if (@($names | Where-Object { -not $_.StartsWith('bug-bounty-anything/') -or $_ -match '\\|(^|/)\.\.(/|$)' }).Count) {
    throw 'Unsafe archive path'
  }
  Write-Output "Entries: $($names.Count)"
} finally { $check.Dispose() }
Move-Item -LiteralPath $partial -Destination $output
Write-Output "Archive: $output"
