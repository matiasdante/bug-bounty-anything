# Objetivo e fluxo autônomo do BBA

[English](../HUNT.md) · [Español](../es/HUNT.md) · **Português (Brasil)** · [简体中文](../zh/HUNT.md)

O objetivo é partir de um site autorizado, descobrir sua superfície, gerar e executar hipóteses, confirmar uma vulnerabilidade com controles, documentar a prova e deixar um rascunho pronto para revisão de bug bounty. Contas, regras e escopo são definidos uma vez; o framework propõe verificações dentro desses limites, sem uma lista manual de bugs esperados.

## Implementação atual

`hunt --scope scope.json --config hunt.json --out runs/hunt` implementa isso para a leitura indevida de campos privados entre duas contas (BOLA), pela CLI ou pelo MCP com rede habilitada. A skill prepara os arquivos a partir do serviço e da política vigente; `prepare` inicia um caso offline. É uma rota especializada, não um requisito quando não há contas ou uma regra de somente-dono disponíveis.

```json
{
  "schemaVersion": 1,
  "seed": "https://service.example/",
  "identityUrl": "https://service.example/api/me",
  "identityField": "id",
  "ownerField": "ownerId",
  "privateField": "privateNotes",
  "accounts": ["BBA_TOKEN_A", "BBA_TOKEN_B"],
  "boundary": "owner-only"
}
```

As URLs de exemplo são estruturais, não alvos. Os segredos vêm das variáveis de ambiente referenciadas; `BBA_COOKIE_*` também suporta cookies. Use duas contas distintas que você controla, sem permissões compartilhadas nos recursos verificados. O operador estabelece que o campo é somente-dono; um campo chamado `ownerId` não estabelece a regra de negócio. O escopo contém origens e caminhos exatos, possivelmente caminhos permitidos não visitados. A descoberta não o expande: links externos, excluídos, com query ou não representáveis não são visitados. Sem curingas nem enumeração de objetos de terceiros.

## Confirmação

1. Consultar o endpoint de identidade com cada credencial e exigir IDs distintos devolvidos pelo servidor.
2. Seguir os links HTML a partir da semente com as duas contas, dentro dos limites comuns de escopo, orçamento, intervalo, timeout, tamanho e deadline.
3. Para um documento JSON pertencente a uma dessas identidades e com o campo privado configurado, gerar uma hipótese.
4. Ler o mesmo recurso de forma anônima e com a outra conta. Confirmar somente quando o acesso anônimo for negado e a segunda identidade receber o mesmo dono e o mesmo valor protegido.
5. Escrever o resultado, as referências de evidência e o relatório. Sessões inválidas, dados públicos ou controles incompletos nunca confirmam.

Pare na primeira confirmação para evitar ler mais recursos por uma mesma causa. Links descobertos e não visitados continuam como lacunas de cobertura; uma prova positiva não resolve outras classes. `scope.requestHeaders` adiciona marcadores de identificação por origem vinculados ao ambiente, sem persistir valores. HTTP 200 ou hashes de corpo iguais, isolados, não bastam. O relatório vincula a resposta, a evidência de identidade e os digests do campo protegido. Propriedade e confidencialidade continuam dependendo das pré-condições declaradas pelo operador.

## Artefatos

- `requests.jsonl` sincroniza a intenção antes de cada envio e depois guarda metadados da resposta e comparações redigidas de identidade/campo. IDs numéricos vinculam o relatório às requisições.
- `hunt.json` guarda a superfície descoberta, a resposta de origem, as hipóteses, os estados, o orçamento gasto, as paradas, os limites e o checksum.
- `report.md` contém a regra de acesso, as pré-condições, a reprodução numerada, ator/recurso, evidência, efeito observado, correção e lacunas de triagem.

Nenhuma credencial, cookie ou valor privado original é guardado. URLs autorizadas e nomes de campo são retidos; não coloque segredos neles. A evidência redigida pode ser reproduzida com contas de teste, mas não é uma captura completa de tráfego. Os hashes não autenticam o autor. Tentativas sem resultado permanecem no journal. Ctrl+C registra os fatos parciais e termina com 130. Cancelamento, deadline e autorização são reverificados após as esperas de intervalo. `hunt` não pode retomar sozinho nem repetir tentativas incertas. Uma nova execução exige uma nova pasta e a revisão do orçamento consumido; `run/resume` estático usa seu próprio mecanismo de checkpoint.

## Lacunas de cobertura

`hunt` não executa JavaScript nem infere papéis/tenants; seu gerador de links HTML cobre apenas BOLA. Outras rotas oferecem [investigação semântica](INVESTIGATION.md), [XSS/CORS no Chromium](BROWSER-CHECKS.md) e [sessões de navegador](SCENARIOS.md). Não há confirmação genérica de injeção/SSRF nem inferência universal de regras de negócio. A ausência de um recurso descoberto adequado pode não gerar nenhuma hipótese, o que não é um achado de segurança. Aqui não há envio automático, garantia de recompensa, deduplicação em programas ativos nem validação em produção.

## Revisão histórica anterior à 1.2

Foi revisado o trabalho anterior do Claude em escopo/transporte, captura, importações, avaliação, persistência, CLI/MCP, empacotamento e avaliação congelada. Foram mantidos orçamento/checkpoints, isolamento de destinos, importadores com procedência, isolamento de navegador por identidade, MCP restrito e empacotamento JS. O BBA acrescentou a geração autônoma de hipóteses; `evaluate-run` agora deixa coincidências de hash como `needs-validation`, com respostas de propriedade diferentes como `unresolved`. A avaliação congelada revisão 2 registra zero confirmações e três omissões em vez de inflar métricas de detecção. A captura já não encaminha credenciais da página para outra origem e reverifica cancelamento/deadline após esperar. O build rejeita alvos de remoção que não sejam o `dist` ou o `.build-test` do workspace e rejeita links. O piloto DCS internamente autorizado nunca autorizou novos testes nem cumpriu um piloto de bounty de terceiros. Seis testes de navegador foram inicialmente ignorados sem Chromium; a 1.2 executou a suíte completa e um piloto público delimitado no DCS. Nenhum dos dois prova ampla cobertura web.
