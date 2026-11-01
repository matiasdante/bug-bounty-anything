# Instalação e configuração

[English](../installation.md) · [Español](../es/installation.md) · **Português (Brasil)** · [简体中文](../zh/installation.md)

Como instalar a skill do BBA, executá-la a partir do código-fonte ou do npm, diagnosticar o ambiente local e registrar o servidor MCP. Para os comandos que enviam requisições, consulte o [guia da CLI](cli.md).

## Invocar a skill

Com as dependências do projeto disponíveis:

```powershell
npm run build
node dist/cli.js install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
```

O diretório de saída deve ser novo. A instalação copia instruções, referências e metadados de UI; `runtime.json` aponta para o runtime do Node deste pacote e para a CLI compilada. Mantenha o projeto nesse local. O comando não instala dependências nem altera o MCP ou outras skills. Abra um novo chat se o catálogo de skills não tiver sido atualizado. `update-skill --out <diretório-existente>` atualiza os arquivos gerenciados, mantém um backup em `.bba-backups/`, verifica que a instalação pertence a este pacote, rejeita links para recursos e preserva arquivos alheios. `installation.json` guarda os hashes dos arquivos gerenciados; uma atualização interrompida nunca é informada como concluída.

Para Claude Code, Codex ou Gemini CLI, `npm run package:skill -- --out dist-skill.zip` gera um ZIP portátil com a CLI compilada, `SKILL.md` e as referências. O empacotador mais antigo para Windows PowerShell continua disponível. Descompacte `bug-bounty-anything` em `.claude/skills/` ou `~/.claude/skills/`. O registro MCP inicial expõe apenas ferramentas offline; instale o Chromium à parte quando precisar das verificações de navegador.

Peça ao agente, por exemplo, **`$bug-bounty-anything investigate https://authorized-service/ and prepare findings`**. O agente consulta a política vigente e cria os arquivos necessários. Só pergunta por fatos que não consegue estabelecer, como contas de teste ou uma regra de acesso. Sem autorização, interrompe as verificações ativas naquele ativo; a pesquisa pública pode continuar. A skill funciona pela CLI sem exigir MCP e delega ao REA, quando apropriado, a análise de artefatos de cliente.

Se faltar política ou janela de autorização, `start-case --target <url> --out <diretório>` registra um caso pendente sem criar um escopo nem fazer requisições. Uma vez estabelecida a permissão, use `prepare`:

```powershell
node dist/cli.js prepare --scope scope.json --target https://authorized-service/ --out runs/investigation
```

Isso cria uma cópia do escopo, um plano inicial de GET anônimos, um registro do caso com checksum e notas da investigação. Não contata o alvo nem prova a permissão. Rejeita URLs excluídas ou fora do escopo, janelas expiradas e saídas existentes. O MCP também expõe `prepare` sem habilitar o acesso à rede. Um `budgetId` compartilha uma contagem de requisições, intervalo e duração persistentes entre fases, ao lado do arquivo de escopo canônico; escopos antigos mantêm limites por execução.

## Requisitos e execução local

- Node.js **22.13.0 ou superior**, com npm. O Node fornece remoção de tipos TypeScript no desenvolvimento e SQLite nativo. A única dependência de produção é `playwright-core` 1.64.1 (Apache-2.0).
- Para desenvolver ou testar no Node 22.13, habilite a remoção nativa de tipos do TypeScript com `$env:NODE_OPTIONS = '--experimental-strip-types'` no PowerShell. O pacote publicado executa JavaScript compilado e não precisa dessa opção.
- Execute `npm install` e `npx playwright-core install --only-shell chromium` para a captura e as verificações de navegador. O Chromium é baixado fora do repositório. Os demais comandos não precisam dele.
- Os laboratórios locais e o inspetor precisam de conexões a `127.0.0.1`. Se um sandbox bloquear o loopback, execute a partir de um terminal local onde seja permitido.

```powershell
npm run bba -- lab --variant vulnerable --out runs/vulnerable
npm run bba -- lab --variant fixed --out runs/fixed
npm run bba -- inspect runs/vulnerable
npm run bba -- report runs/vulnerable --out runs/vulnerable-export.md
npm run demo:core -- --out runs/core-demo
npm test
```

Em instalações do PowerShell que bloqueiam `npm.ps1`, use `npm.cmd`. Arquivos e diretórios de saída devem ser novos; o BBA não sobrescreve uma investigação. `lab` inicia um servidor descartável em `127.0.0.1`, cria duas contas e documentos sintéticos, envia cinco requisições sequenciais e é encerrado mesmo em caso de erro. As credenciais ficam em memória. `inspect` e `report` leem evidência local verificada sem acesso à rede; `report` reconstrói o relatório a partir do JSON. `demo:core` executa um segundo laboratório e escreve checkpoints SQLite, um escopo e um plano sem credenciais, uma exportação JSON e um relatório. Não reutilize suas credenciais efêmeras nem sua porta.

## Instalação, diagnóstico e MCP

Para uma execução pontual da CLI direto do npm, sem instalação global:

```powershell
npx --yes bug-bounty-anything@latest capabilities
npx --yes bug-bounty-anything@latest --help
```

`npx` baixa o pacote publicado e executa seu comando `bba`. Para um registro persistente de skill ou MCP, instale o pacote globalmente: os registros guardam o caminho da CLI, e uma entrada temporária do cache do `npx` pode desaparecer depois.

```powershell
npm install --global bug-bounty-anything@latest
bba install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
bba doctor
```

Para as verificações de navegador, instale o Chromium à parte com `npx playwright-core install --only-shell chromium`. No repositório de código-fonte, `npm install`, `npm run build` e `npm test` continuam sendo os comandos de desenvolvimento. O pacote e o código públicos usam a [licença MIT](../../LICENSE).

O pacote expõe `bba`, incluindo os subcomandos agrupados `campaign`, `check` e `study`, ajuda por comando e `--lang es|en`. `doctor` verifica apenas Node local, SQLite, loopback, armazenamento temporário, Chromium e os nomes (nunca os valores) das variáveis `BBA_TOKEN_*`, `BBA_COOKIE_*`, `BBA_HEADER_*`, `BBA_INPUT_*` e `BBA_BODY_*` presentes.

```powershell
bba mcp --root C:/path/to/workspace
bba mcp --root C:/path/to/workspace --allow-network
```

O MCP roda sobre JSON-RPC via stdio com `initialize`, `ping` fora de banda, cancelamento real por `notifications/cancelled` e `tools`. `tools/list` é a fonte autoritativa; as ferramentas ativas só aparecem com `--allow-network`. Os caminhos ficam confinados a `--root` no Windows e no POSIX, inclusive contra fugas por symlink e junction; os erros internos são sanitizados. `setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` mostra a prévia ou aplica o registro com backups locais.
