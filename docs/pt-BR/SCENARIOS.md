# Cenários controlados com sessão real de navegador

[English](../SCENARIOS.md) · [Español](../es/SCENARIOS.md) · **Português (Brasil)** · [简体中文](../zh/SCENARIOS.md)

```powershell
node dist/cli.js browser-scenario --scope scope.json --config scenario.json --out runs/scenario
```

MCP: `browser_scenario`, somente com rede habilitada. Executa um fluxo declarado em um contexto efêmero do Chromium: navegação, preenchimento de campos, cliques e espera por um seletor visível. Cookies de login e rotação são aplicados em memória a partir dos atributos reais de Set-Cookie. A saída registra observações, não uma afirmação automática de vulnerabilidade.

## Contrato

`scenario.json` tem exatamente `schemaVersion: 1`, `policyReference`, `boundary: "controlled-workflow"`, `sessionOrigin`, `plan`, `actions`, `maxRedirects` e `observe`.

- `sessionOrigin` é a origem permitida para a qual cookies/Bearer gerados pelo navegador podem retornar.
- `plan` é o contrato de `run` com até 100 requisições conhecidas, todas com `credentialEnv: null`. As credenciais de sessão vêm do navegador; os dados de login vêm das ações e de corpos vinculados ao ambiente. Fora de `sessionOrigin`, só GET é permitido e as credenciais são retidas.
- `actions` contém de 1 a 30 itens, começando por navigate. As formas incluem `{ "kind": "navigate", "stepId": "home" }`, `{ "kind": "fill", "selector": "#username", "valueEnv": "BBA_INPUT_USER" }`, `{ "kind": "click", "selector": "#submit" }` e `{ "kind": "wait", "selector": "#dashboard" }`.
- `maxRedirects` vai de 0 a 5. Todo destino deve corresponder a uma requisição declarada, incluindo método e corpo quando o Chromium os fornece.
- `observe` tem até 20 entradas `{ "name": "identity", "selector": "#identity", "attribute": null }`. Null lê textContent; pode-se escolher um atributo. Presença, digest e truncamento em 4.096 caracteres são retidos.

URL completa, método e bytes do corpo são comparados antes do envio. Um formulário conhecido pode usar `body: { "format": "form", "valueEnv": "BBA_BODY_LOGIN" }` e ações de preenchimento com `BBA_INPUT_USER` / `BBA_INPUT_PASSWORD`. O corpo esperado deve coincidir exatamente com a serialização do formulário, incluindo ordem, codificação e campos ocultos. Entradas ausentes ou corpos diferentes/dinâmicos sem vínculo são bloqueados. POST/PUT/PATCH/DELETE exigem regras explícitas de escopo, recursos próprios e limpeza para mudanças de estado.

## Isolamento e fidelidade

O CDP Fetch intercepta cada salto de redirecionamento; as rotas do Playwright cobririam apenas a primeira URL. A política de rede do navegador continua ativa e o seguimento direto de redirecionamentos é proibido. O proxy que rejeita tráfego e a política de WebRTC continuam ativos; service workers, WebSockets e downloads são bloqueados. O relay devolve ao Chromium os Set-Cookie e cabeçalhos CSP/CORS selecionados. Encaminha cookies/Bearer gerados pelo navegador apenas para `sessionOrigin`; nunca usa um perfil pessoal de navegador, persiste uma sessão nem envia esses cabeçalhos a outra origem. Formulários de login, tokens dinâmicos e domínios SSO não são inferidos; janelas ou provedores extras exigem definições explícitas.

Queries, corpos esperados e valores de preenchimento vêm do ambiente. Nunca coloque credenciais em seletores, IDs, URLs base ou referências. As etapas podem projetar fatos de respostas JSON como em `run`. Não existe checkpoint retomável da sessão de navegador: após uma queda, o orçamento e as reservas permanecem, mas a sessão é perdida.

## Artefatos

`scope.json` e `config.json` retêm referências, não valores. `requests.jsonl` sincroniza as reservas antes do envio e guarda metadados/fatos, ações concluídas e erros de rede sanitizados. `scenario.json` guarda resultados, contagens, fatos do DOM e checksum. `artifact.json` sela journal, resultado e fontes para o `artifact-view` paginado. Corpos, senhas, cookies e tokens nunca são salvos. Uma ação concluída ou uma mudança no DOM mostra comportamento observado, não segurança. Um relatório precisa de regra esperada, controles, identidade/estado e evidência de impacto. Os testes locais cobrem login por formulário, redirecionamentos, dois cookies, rotação, leitura autenticada, redação e bloqueio de requisições não declaradas.
