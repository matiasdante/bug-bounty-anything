# Verificações de entrada delimitadas (1.9.0)

[English](../INPUT-PROOFS.md) · [Español](../es/INPUT-PROOFS.md) · **Português (Brasil)** · [简体中文](../zh/INPUT-PROOFS.md)

As duas ferramentas reutilizam o escopo exato, as `requestRules`, o orçamento compartilhado e os checkpoints SQLite. As entradas são geradas ou vinculadas à configuração; as credenciais vêm do ambiente. Uma execução incompleta retém as reservas e só pode retomar etapas não iniciadas com o mesmo escopo e a mesma configuração.

## Expressão de template

`template-check` / `template_check` recebe `schemaVersion: 1`, `class: "template-arithmetic"`, `policyReference`, `url`, `parameter`, `pointer`, `operands: [a,b,c]` e `credentialEnv` (`null` ou uma referência `BBA_TOKEN_*` / `BBA_COOKIE_*`). Os operandos são inteiros distintos de 2 a 997. O escopo deve autorizar o GET exato e o nome do parâmetro de query. O motor envia `a*b` literal, `{{a*b}}` e `{{b*c}}` a um recurso, projeta um campo JSON e guarda apenas digests. Confirma a **avaliação dessa sintaxe** quando o controle permanece literal e ambas as expressões retornam seus produtos. Se ambas permanecem literais, o resultado é `not-reproduced`; os demais resultados são `unresolved`. O operador deve estabelecer que o campo deveria ter tratado a entrada como texto literal. Não são testados SQL, NoSQL, execução de comandos, arquivos nem dados de terceiros. `resume-template-check` / `resume_template_check` usa o mesmo escopo e a mesma configuração.

## Callback de URL

`ssrf-callback-check` / `ssrf_callback_check` recebe `schemaVersion: 1`, `class: "outbound-fetch"`, `policyReference`, `triggerUrl`, `queryName`, `credentialEnv`, `callbackUrl`, `receiptUrl` e `receiptPointer`. Trigger, callback e recibo devem ser caminhos exatos dentro do escopo. O callback usa uma origem separada que você possui e termina num token opaco de ao menos 12 caracteres. Seu receptor expõe um booleano JSON em `receiptPointer` que muda de `false` para `true` somente depois deste callback.

O motor lê o recibo, envia a URL de callback como valor de query ao trigger e depois consulta o recibo no máximo duas vezes. Uma transição `false` → `true` com trigger 200 demonstra uma requisição de saída para **esse receptor próprio**, supondo que esteja bem configurado e que a política declarada proíba o destino. Não prova acesso à rede interna, acesso a metadados nem divulgação da resposta. Nunca gera URLs internas, segue redirecionamentos nem varre destinos. `resume-ssrf-callback` / `resume_ssrf_callback` mantém os limites.

A chamada do serviço ao receptor é uma requisição adicional fora do contador do cliente BBA. Guarde o log do receptor e considere-a no orçamento do programa. Os dois relatórios cobrem o que ocorreu, a descoberta, a prova, a reprodução e a correção, sem extrapolar severidade.
