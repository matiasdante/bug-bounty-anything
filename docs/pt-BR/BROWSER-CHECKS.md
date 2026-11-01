# Verificações de XSS e CORS no Chromium

[English](../BROWSER-CHECKS.md) · [Español](../es/BROWSER-CHECKS.md) · **Português (Brasil)** · [简体中文](../zh/BROWSER-CHECKS.md)

`browser-check --scope scope.json --config browser.json --out <novo-diretório>` e a ferramenta MCP `browser_check` executam comparações finitas contra dados e origens controlados. Exigem Chromium, escopo autorizado e técnicas permitidas. Cabeçalhos ou texto refletido, por si sós, não são evidência suficiente.

Todas as requisições usam o transporte do BBA. Só são enviados GET cuja URL completa, método e entradas vinculadas ao ambiente coincidam com as etapas declaradas. Os cabeçalhos CSP, CORS, de isolamento de origem e `nosniff` são preservados; redirecionamentos não são seguidos. Service workers, WebSockets, downloads e acessos fora do plano são bloqueados. O proxy loopback que rejeita tráfego e a política de WebRTC continuam ativos. `budgetId` ativa o orçamento compartilhado.

## Campos comuns

Use `schemaVersion: 1`, `class`, `policyReference`, `observationMs` (50–5000), `baseline`, `probe` e `resources`. As etapas usam o contrato de `run`: ID único, GET, URL base, `credentialEnv` e entrada de query opcional vinda de `BBA_INPUT_*`. `resources` lista os ativos que as páginas realmente exigem; hosts descobertos não são adicionados automaticamente. Essas verificações não aceitam corpos de requisição nem projeções.

## XSS

Defina `class: "xss"`, `boundary: "untrusted-input-script"` e `markerEnv: "BBA_INPUT_MARKER"`. Baseline e probe navegam para a mesma URL base com as mesmas credenciais, mas com entradas concretas diferentes. O marcador opaco e único tem de 12 a 128 caracteres alfanuméricos, hífens ou sublinhados. O agente prepara uma entrada inofensiva e um payload mínimo específico do contexto que tenta executar `window.__bbaProof(marker)`. O payload fica numa variável de ambiente, não no plano nem no relatório. O Chromium expõe a função apenas para observar que o marcador esperado foi chamado a partir da origem da aplicação. Nunca lê cookies, arquivos, tokens nem dados de outros usuários.

A verificação só confirma quando o probe executa o marcador e o baseline não. Texto escapado ou bloqueio por CSP não confirma. Execução nos dois controles, recursos obrigatórios bloqueados, orçamento esgotado e falhas permanecem inconclusivos. Um resultado negativo cobre apenas a entrada, o contexto e a janela observados. O operador deve demonstrar que o atacante controla a entrada e que existe um contexto executável não pretendido; self-XSS ou HTML intencional não é automaticamente reportável. Não há gerador universal de payloads nem teste de XSS armazenado que possa atingir usuários reais.

## CORS

Defina `class: "cors"`, `boundary: "private-cross-origin-read"`, `protectedPointer` e `target` (GET de dados privados). O baseline abre uma página na origem do alvo; o probe abre uma página numa origem diferente, controlada e permitida. Configure o cookie:

```json
"cookie": {
  "origin": "https://service.example",
  "valueEnv": "BBA_COOKIE_A",
  "sameSite": "Lax"
}
```

O `credentialEnv` do alvo deve corresponder a esse cookie. Só as etapas da origem do alvo podem usá-lo; a página estrangeira nunca o recebe do relay. O valor é uma string de cookie `name=value; name2=value2`. O Chromium recebe os cookies de teste com a URL e o SameSite declarados; Secure deriva de HTTPS. Isso deve modelar a sessão real. O BBA não infere atributos de cookie nem automatiza login ou rotação.

São feitos um controle anônimo, uma leitura de mesma origem e um `fetch` de origem estrangeira com `credentials: "include"`. O relay preserva `Origin`, os cabeçalhos CORS e a entrega real de cookies do navegador; nunca adiciona um cookie que o Chromium omitiu. A confirmação exige negação anônima e leitura bem-sucedida, pelo navegador e de origem estrangeira, do mesmo campo privado. O Chromium rejeita `Access-Control-Allow-Origin: *` com credenciais. 401 no probe, dados públicos, valores diferentes e evidência insuficiente permanecem inconclusivos. Se o relay recebeu os dados mas o navegador não pôde lê-los, aquela leitura específica não foi reproduzida; isso nada diz sobre todas as políticas CORS. A origem do atacante e os atributos do cookie são pré-condições materiais do relatório.

## Evidência e recuperação

As cópias de scope/config excluem valores de ambiente. `requests.jsonl` sincroniza as reservas antes do envio e guarda respostas mínimas e comparações redigidas. `browser-check.json` guarda observações, resultado e checksum; `artifact.json` vincula journal, resultado e fontes para o `artifact-view` paginado. `report.md` é um rascunho. Corpos, cookies, payloads e o marcador original não são salvos; reconstrua entradas seguras e pré-condições exatas antes de reportar.

As verificações de navegador não podem ser retomadas. Após uma queda, revise o journal e as reservas incertas do orçamento compartilhado antes de usar um novo diretório de saída. Continuam valendo as paradas por duração, intervalo, bytes, 3xx/429/5xx e cancelamento. Foram testados apps sintéticos vulneráveis/corrigidos, CSP, CORS com curinga, credenciais ausentes, dados filtrados e sessões expiradas.
