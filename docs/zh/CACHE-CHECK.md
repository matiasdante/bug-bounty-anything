# 与缓存相关的跨身份暴露 (1.9.0)

[English](../CACHE-CHECK.md) · [Español](../es/CACHE-CHECK.md) · [Português (Brasil)](../pt-BR/CACHE-CHECK.md) · **简体中文**

`cache-check` / `cache_check` 使用两个受控账号，向你拥有的一个资源发送七个精确的 GET 请求。配置需要 `schemaVersion: 1`、`class: "cross-identity-cache"`、`policyReference`、`identityUrl`、`identityPointer`、`resourceUrl`、`protectedPointer`、`accountA`、`accountB`、`bustQueryName` 以及两个互不相同的不透明 `bustTokens`。账号的值来自环境变量 `BBA_TOKEN_*` 或 `BBA_COOKIE_*`，绝不来自配置。范围必须允许这两条路由、该查询参数名以及至少七个请求。

检查会确认两个身份各不相同，并确认匿名请求被拒绝。它验证 A 带缓存破坏参数时可以读取受保护字段而 B 不能；随后以 A 的身份在不带该参数的共享 URL 上预热缓存，再以 B 的身份读取。`confirmed` 要求 B 在共享 URL 上收到 A 的受保护字段；`not-reproduced` 要求 B 被拒绝。对照不完整，或 B 在带缓存破坏参数时也能读取该字段，则为 `unresolved`，因为这可能是通用的授权失败所致。`resume-cache-check` / `resume_cache_check` 会保留范围、账号、配置和预算，且不会重复不确定的预留。

操作者必须确认缓存破坏令牌没有语义影响、两个账号没有共享权限，且该资源确实属于它们。这表明的是与缓存**相关**的暴露；它不能识别缓存层或键算法，也不能证明其他路由受影响。只保留投影出的事实和摘要，绝不保存受保护的值。五个部分的草稿将影响限定在被检查的字段上。
