# Estudos reproduzíveis de casos publicados

[English](../PUBLISHED-CASE-STUDIES.md) · [Español](../es/PUBLISHED-CASE-STUDIES.md) · **Português (Brasil)** · [简体中文](../zh/PUBLISHED-CASE-STUDIES.md)

O primeiro estudo usa o [artigo Titan de Faav](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records) como referência de método. `cases/faav-titan-jwt-2026.json` identifica a publicação e a classe de bug, mas não contém token, dados de serviço nem alvo autorizado. Uma investigação histórica e uma reprodução atual são coisas distintas.

## Fluxo do agente

1. Leia a política vigente do programa e registre fonte, janela, ativos, exclusões, técnicas permitidas, limite de requisições e conta de teste própria. Sem isso, fique na análise offline; uma publicação não concede permissão.
2. Importe Swagger 2.0/OpenAPI JSON com `import-surface --format openapi`. Omite corpos, exemplos e segredos e mantém rotas, métodos, autenticação declarada e procedência. Registre em `historical.json` pistas históricas públicas estruturadas, sem supor que sejam válidas hoje.
3. Crie `policy.json` e `profile.json` a partir de fatos verificados. O agente os escreve; o usuário não precisa escrever JSON. O perfil se refere a variáveis de ambiente, a uma consulta inofensiva sobre dados próprios e a um fato JSON protegido. Sem segredos em arquivos.
4. Execute `study-bundle` e `study-plan`. O planejamento seleciona uma operação opcionalmente autenticada e uma operação protegida na mesma origem dentro dos prefixos permitidos; uma pista histórica pode desempatar. Sem um candidato único, retorna `unresolved` e não envia requisições. Revise `analysis.json`, `scope.json` e `jwt-config.json` antes do trabalho ativo.
5. Com o token assinado e o corpo no ambiente, execute `study-run`: anônimo, JWT original, JWT com claim alterado mantendo a assinatura antiga e JWT original de novo. Confirme só quando o anônimo for negado e o mesmo fato protegido próprio aparecer com os dois tokens. `resume-study` valida o bundle e os artefatos originais sem repetir tentativas incertas.

```powershell
node dist/cli.js import-surface --format openapi --input api.json --out runs/surface.json
node dist/cli.js study-bundle --case cases/faav-titan-jwt-2026.json --policy policy.json --surface runs/surface.json --historical historical.json --profile profile.json --out runs/study-input.json
node dist/cli.js study-plan --input runs/study-input.json --out runs/study-plan
node dist/cli.js study-run --input runs/study-input.json --out runs/study-active
node dist/cli.js resume-study runs/study-active --input runs/study-input.json
```

Bundle e plano são offline; run e resume podem enviar requisições. Os nomes MCP são `study_bundle`, `study_plan`, `study_run` e `resume_study`; os dois últimos exigem `--allow-network`. As saídas devem ser novas. Preserve o caminho canônico de `study-input.json`, pois `.bba-budgets/<budgetId>` é guardado ao lado dele.

## Contratos mínimos

- `policy.json`: `schemaVersion: 1`, `mode`, `sourceUrl`, `reviewedAt`, `authorization` (`reference`, `validFrom`, `validUntil`), `assets` e `excluded` como `{origin,pathPrefixes}`, `techniques: ["jwt-signature-integrity"]`, `budgetId` e `limits` do escopo. As exclusões prevalecem. Formato e tempo são validados; o investigador verifica a legitimidade da política.
- `historical.json`: `schemaVersion: 1`, `sourceUrl`, `capturedAt` e `routes: [{path,clue}]`, onde `clue` é `routing-definition` ou `endpoint-reference`. As fontes históricas sugerem onde olhar.
- `profile.json`: `schemaVersion: 1`, `credentialEnv` (`BBA_TOKEN_*`), `proofPointer`, `request` e `mutation` conforme o [contrato de JWT](JWT-INTEGRITY.md). Corpos POST usam `BBA_BODY_*`; escolha dados próprios e um fato privado estável.
- `study-input.json`: bundle portátil validado com cinco entradas. `study-plan/analysis.json` contém candidatos e um grafo de procedência; o escopo e a configuração de JWT exigem um único candidato. `study-active/report.md` é um rascunho de cinco perguntas.

## Afirmações do relatório

O rascunho cobre o problema, a descoberta, a prova de exploração, a reprodução e a correção, com IDs de evidência e limites. `confirmed` mostra a aceitação do JWT alterado para a conta/fato declarados. Não mostra privilégios de outras identidades, leituras em massa, severidade nem que o alvo do artigo continue vulnerável. `not-reproduced` exclui apenas a mutação testada. Os relatórios permanecem locais para revisão antes do envio. Este MVP trata uma classe de hipótese e um candidato por execução; não automatiza reconhecimento amplo nem inferência de identidades/claims.
