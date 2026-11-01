# 一次性操作的竞态 (1.9.0)

[English](../RACE-CHECK.md) · [Español](../es/RACE-CHECK.md) · [Português (Brasil)](../pt-BR/RACE-CHECK.md) · **简体中文**

`race-check` / `race_check` 在**你拥有的两个一次性资源**上测试一条单次使用规则。配置包括 `schemaVersion: 1`、`class: "single-use-race"`、`policyReference`、`credentialEnv`、`actionUrl`、`actionField`、`controlResourceId`、`raceResourceId`、`controlStateUrl`、`raceStateUrl` 和 `countPointer`。三个 URL 必须精确、互不相同且位于同一来源。范围需要对 `actionUrl` 的 JSON POST、对两个状态 URL 的 GET、至少七个请求以及 `minIntervalMs: 0`。凭据读取自 `BBA_TOKEN_*` 或 `BBA_COOKIE_*`。

引擎会检查初始计数为零，在对照资源上执行两次该动作，并要求第二次使用被拒绝。如果这个对照失败，则**不会进行任何竞态测试**。对第二个资源，它检查计数为零，从共享预算中成对预留两个请求，并恰好发送两个并发 POST。`confirmed` 要求两者都被接受、发送时间窗口重叠且最终计数为二。只接受一次、最终计数为一且窗口重叠时为 `not-reproduced`；其余情况均为 `unresolved`。存在漏洞和已修复两个版本都在合成的回环服务器上做了测试。

`artifact.json` 为 `artifact-view` 封存日志。崩溃会留下不确定的预留；此检查绝不会恢复或重复会改变状态的动作。操作者必须拥有、控制并清理这两个资源，并确立单次使用规则。本地出现双重效果并不能证明财务影响或其他受影响的路由。报告包含五个部分和状态证据，不含凭据或请求体。
