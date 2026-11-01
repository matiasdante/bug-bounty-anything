# Exposição entre identidades correlacionada ao cache (1.9.0)

[English](../CACHE-CHECK.md) · [Español](../es/CACHE-CHECK.md) · **Português (Brasil)** · [简体中文](../zh/CACHE-CHECK.md)

`cache-check` / `cache_check` envia sete requisições GET exatas a um recurso seu, com duas contas controladas. A configuração exige `schemaVersion: 1`, `class: "cross-identity-cache"`, `policyReference`, `identityUrl`, `identityPointer`, `resourceUrl`, `protectedPointer`, `accountA`, `accountB`, `bustQueryName` e dois `bustTokens` opacos e distintos. Os valores das contas vêm das variáveis de ambiente `BBA_TOKEN_*` ou `BBA_COOKIE_*`, nunca da configuração. O escopo deve permitir as duas rotas, o nome do parâmetro de query e ao menos sete requisições.

A verificação estabelece identidades distintas e a negação anônima. Confirma que A lê o campo protegido com um parâmetro de cache-busting e B não, aquece a URL compartilhada sem esse parâmetro como A e depois a lê como B. `confirmed` exige que B receba o campo protegido de A na URL compartilhada; `not-reproduced` exige que B seja negado. Controles incompletos, ou B também lendo o campo com cache busting, são `unresolved`, pois uma falha geral de autorização poderia explicar o resultado. `resume-cache-check` / `resume_cache_check` mantém escopo, contas, configuração e orçamento sem repetir reservas incertas.

O operador deve verificar que os tokens de busting não têm efeito semântico, que as contas não compartilham permissão e que o recurso pertence a elas. Isso mostra uma exposição **correlacionada** ao cache; não identifica a camada de cache nem o algoritmo de chave, nem estabelece outras rotas afetadas. Só são retidos fatos projetados e digests, nunca o valor protegido. O rascunho de cinco seções limita o impacto ao campo verificado.
