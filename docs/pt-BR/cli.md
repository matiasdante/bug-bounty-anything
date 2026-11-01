# Guia da CLI

[English](../cli.md) · [Español](../es/cli.md) · **Português (Brasil)** · [简体中文](../zh/cli.md)

Referência de comandos do motor local: execução com escopo, importações, captura, avaliação, assinaturas, cabeçalhos do programa, arquivos do laboratório, limites e verificação. Instale primeiro com o [guia de instalação](installation.md).

## Execução com escopo e recuperação

O [guia de execução](EXECUTION.md) define contratos, limites, checkpoints e recuperação. Com escopo e plano preparados para recursos autorizados:

```powershell
npm run bba -- scope-check --scope scope.json --plan plan.json
npm run bba -- run --scope scope.json --plan plan.json --out runs/investigation
npm run bba -- resume runs/investigation --scope scope.json
npm run bba -- inspect-run runs/investigation
npm run bba -- export-run runs/investigation --out runs/investigation-export.json
npm run bba -- report-run runs/investigation --out runs/investigation-report.md
```

`scope-check` valida formato, janela e correspondência de destino; **não verifica a permissão do dono do ativo**. Estabeleça essa permissão e as regras vigentes antes de escrever o escopo. `run` e `resume` enviam requisições; os demais comandos acima são offline. Ctrl+C registra o que se sabe. `resume` mantém orçamento e evidência, exige o mesmo escopo vigente e executa apenas etapas não iniciadas. Uma requisição em voo cujo resultado se perdeu permanece inconclusiva e nunca é repetida automaticamente. Paradas causadas por erros ou limites exigem revisão e, quando cabível, uma nova investigação.

## Importar superfície e política

```powershell
npm run bba -- import-surface --format har|openapi|rea|graphql|js-bundle --input source.json --out runs/surface.json [--quarantine]
npm run bba -- import-policy --format hackerone|bugcrowd|intigriti|security-txt --input policy.json --out runs/policy-draft
```

O importador offline projeta endpoints a partir de HAR 1.2, JSON Swagger 2.0/OpenAPI 3.0/3.1, evidência REA, introspecção/SDL de GraphQL e bundles JS/SourceMap v3. Não contata URLs nem concede autorização. `--quarantine` conta e ignora entradas não representáveis em vez de rejeitar o lote inteiro. As entradas distinguem dados observados de HAR/REA de dados declarados de schema ou JS e retêm os localizadores de origem. Cabeçalhos, corpos, valores de query, exemplos e descrições são descartados. Segmentos numéricos, UUID e longos viram `{opaque}`. Caracteres de caminho RFC 3986 e nomes de query com colchetes são suportados, enquanto escapes ambíguos continuam bloqueados. A importação de políticas extrai ativos HTTPS exatos para `scope.draft.json`; domínios com curinga ficam em `manualReviewWildcards`, nunca expandidos silenciosamente.

## Captura com Chromium

```powershell
npm run bba -- capture --scope scope.json --plan plan.json --out runs/capture
```

O Chromium headless visita cada etapa do plano e escreve `surface.json`, `capture.json` e `pages.json` (caminhos observados, ações e nomes de campo sem valores nem queries). Os modos de escopo são `loopback-lab` e `public-https`. Foram testados servidores locais e navegação pública delimitada em `www.dcs.ar`; esse piloto não testou login, permissões nem payloads.

Toda requisição do navegador passa pelo transporte do BBA: GET exato dentro do escopo, DNS fixado, validação de IP público, sem redirecionamentos, com limites de timeout, tamanho, intervalo e orçamento. As demais requisições são bloqueadas; após uma parada, as etapas seguintes são marcadas como `not-sent`. O tráfego próprio do Chromium é direcionado a um sink loopback que rejeita e é contado como `leak-attempts`; a resolução de DNS e o UDP direto de WebRTC estão desabilitados. Os testes exercitam esses limites. `preconnect` e `dns-prefetch` não abriram conexões na build fixada do Chromium, então não são afirmados como vetores comprovados.

`credentialEnv` aceita `BBA_TOKEN_*` como Bearer ou `BBA_COOKIE_*` como cabeçalho Cookie; nunca são enviados juntos e os valores nunca são persistidos. O operador obtém o cookie de sessão. O BBA não faz login nem aplica `Set-Cookie`, então sessões rotativas podem perder a autenticação. Cada etapa usa um contexto efêmero com service workers bloqueados. Em `surface.json`, `status: null` significa que nenhuma requisição foi enviada. A captura não tem checkpoints: uma queda pode perder o registro das requisições enviadas. Login por formulário, POST e crawling estão fora deste caminho. Códigos de saída: `0` completo, `1` interrompido, `130` cancelado.

## Avaliar hipóteses de autorização

```powershell
npm run bba -- evaluate-run runs/investigation --checks checks.json --out runs/evaluation.md
```

Este comparador offline lê uma execução verificada e as hipóteses declaradas em `checks.json` para `bola`, `bfla` e `property-exposure`. Cada verificação usa um controle anônimo e um baseline e um probe com credenciais diferentes contra a mesma URL. Um controle negado e duas respostas 200 idênticas resultam apenas em `needs-validation`; um probe negado com baseline válido resulta em `not-reproduced`; controles abertos, baselines que falham, respostas ausentes, 5xx ou respostas 200 diferentes são `unresolved`. Um 200 diferente em exposição de propriedades pode ser um vazamento parcial. Compara hashes de resposta, não retém conteúdo nem mede impacto, e não pode verificar papéis ou donos declarados. `not-reproduced` não significa que o sistema seja seguro. Os laboratórios locais vulnerável e corrigido exercitam esses casos sobre HTTP real.

## Importar candidatos de scanners

```powershell
npm run bba -- import-candidates --format zap|nuclei|subfinder --input zap-report.json --scope scope.json --out runs/candidates.json
```

O BBA **não** executa ZAP, Nuclei nem Subfinder. A atividade deles contornaria o transporte de escopo e orçamento do BBA. Ele normaliza offline JSON do ZAP, JSONL do Nuclei ou JSONL do Subfinder fornecidos pelo operador, até 2 MiB e 5.000 registros. Todo candidato permanece `unvalidated`. O status de escopo é `in-scope`, `excluded`, `out-of-scope` ou `unparseable`; os hostnames do Subfinder são comparados sem DNS. Descrições, evidência bruta, ataques, requisições, respostas e valores de query são descartados. A severidade do scanner é um rótulo da fonte, não uma avaliação do BBA. Duplicados são contados e unificados. Os formatos foram modelados a partir da documentação das ferramentas e de testes sintéticos, não de uma execução real de scanner. A consulta de avisos e de deltas de versão continua manual.

## Avaliação congelada

```powershell
npm run bba -- eval --out runs/evaluation.md
```

Executa 18 casos loopback obrigatórios: seis comparações de resposta, três casos inconclusivos de orçamento, seis limites de escopo, duas verificações de segredos e um caso de recuperação. `FROZEN_DIGEST` protege os IDs dos casos e os resultados esperados. O comparador de hashes reporta candidatos, não achados confirmados; o caminho autônomo de BOLA tem testes separados. As métricas sintéticas do laboratório não estimam taxas reais de detecção ou de falsos positivos e não provam que um alvo seja seguro. O isolamento do Chromium tem testes de captura próprios.

## Assinaturas, rascunhos de envio e inspetor local

```powershell
bba keygen --out keys/operator
bba sign-evidence runs/investigation --key keys/operator/bba-ed25519.key.pem
bba verify-signature runs/investigation --pub keys/operator/bba-ed25519.pub.pem
bba export-submission runs/investigation --platform hackerone|bugcrowd|ghsa --out runs/submission.md
bba ui runs/investigation --out runs/inspector.html
```

A assinatura Ed25519 verifica arquivos ou diretórios completos, inclusive adições e remoções posteriores. `export-submission` escreve rascunhos em Markdown com comandos `curl` redigidos e bases CVSS v3.1/v4.0 conservadoras, somente para achados `confirmed`. `ui` serve um inspetor somente leitura em `127.0.0.1` com CSP estrita, ou exporta HTML autônomo sem JavaScript nem recursos externos. Os comandos de campanha abrem e vinculam um caso à sua política, verificam integridade e orçamento, capturam uma URL exata, executam um perfil semântico e retomam trabalho pausado sem repetir etapas registradas; veja [campanhas](CAMPAIGNS.md).

## Cabeçalhos de identificação do programa

`scope.requestHeaders` suporta marcadores por origem em `run`, `resume`, `capture` e `hunt`:

```json
"requestHeaders": [
  { "origin": "https://authorized-service", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://authorized-service", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

O operador define os valores no ambiente. Só são permitidos os nomes `user-agent` ou `x-*` em minúsculas, nunca cabeçalhos de autenticação, cookie, host ou transporte. Os valores devem ter de 1 a 512 caracteres ASCII imprimíveis, sem quebras de linha. O escopo guarda referências e nomes, nunca valores. Valores ausentes falham antes de enviar ou reservar requisições. Cada marcador vai apenas para a origem declarada. Escopos existentes sem este campo continuam funcionando.

## Arquivos e contratos

`lab` escreve `investigation.json`, um bundle versionado com escopo, cinco registros de evidência, duas hipóteses e checksum SHA-256, além de `report.md` com resultado, reprodução, referências de evidência, impacto e limitações. [src/contracts.ts](../../src/contracts.ts) valida a entrada. A evidência guarda hora UTC, ator, rota, status HTTP e apenas campos sintéticos permitidos, não capturas HTTP completas, cabeçalhos de autenticação, cookies, corpos de erro nem campos inesperados. Na leitura, o BBA valida estrutura, versão, IDs, referências, checksum e consistência das conclusões. Hashes detectam alterações acidentais; **não são assinaturas nem prova de autenticidade de terceiros**. JSON é dado, nunca código executável.

Uma escrita interrompida do laboratório permanece como `.incomplete`. `run/resume` usam contratos de checkpoint separados. As saídas em `runs/` são ignoradas pelo Git.

## Limites do executor

O caminho fixo de `lab` só permite GET para duas rotas exatas do laboratório, sem queries, redirecionamentos nem domínios arbitrários. Tem cinco requisições, timeout de dois segundos por requisição e limite de resposta de 4.096 bytes. Para em redirecionamentos, 429, 5xx, timeouts, corpos grandes demais ou conteúdo fora do contrato. Os limites gerais de `run/resume` vêm do escopo e preservam o estado parcial. Metadados HTTP e hashes, isolados, não são interpretados como vulnerabilidades.

## Verificação

`npm test` usa `node:test` e servidores HTTP locais reais para variantes vulnerável/corrigida, controles inconclusivos, isolamento, limites, segredos, escopo, checkpoints, integridade e CLI. Inclui cancelamento e recuperação após morte de processo sem requisições duplicadas. A seleção de DNS público usa um resolvedor controlado; os testes não contatam serviços de produção. `npm run check` faz verificações estritas de TypeScript sem emitir JS; `npm run verify` executa check, build e testes. O CI roda em Ubuntu e Windows com Node 22.13 e 24.

Códigos de saída: `0` concluído (inclusive um laboratório que encontrou vulnerabilidades), `1` erro ou interrompido, `2` argumentos inválidos, `3` parcial com resultados inconclusivos, `130` cancelado. Um código de saída zero não é evidência de ausência de vulnerabilidades.
