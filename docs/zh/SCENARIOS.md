# 基于真实浏览器会话的受控场景

[English](../SCENARIOS.md) · [Español](../es/SCENARIOS.md) · [Português (Brasil)](../pt-BR/SCENARIOS.md) · **简体中文**

```powershell
node dist/cli.js browser-scenario --scope scope.json --config scenario.json --out runs/scenario
```

MCP：`browser_scenario`，仅在启用网络时可用。它在临时的 Chromium 上下文中运行已声明的流程：导航、填写字段、点击，以及等待可见的选择器。登录 Cookie 和轮换会依据真实的 Set-Cookie 属性在内存中应用。输出记录的是观察结果，而不是自动给出的漏洞结论。

## 契约

`scenario.json` 恰好包含 `schemaVersion: 1`、`policyReference`、`boundary: "controlled-workflow"`、`sessionOrigin`、`plan`、`actions`、`maxRedirects` 和 `observe`。

- `sessionOrigin` 是浏览器生成的 Cookie/Bearer 允许返回的来源。
- `plan` 是 `run` 契约，最多包含 100 个已知请求，且全部带有 `credentialEnv: null`。会话凭据来自浏览器；登录数据来自动作和绑定到环境的请求体。在 `sessionOrigin` 之外只允许 GET，且不带凭据。
- `actions` 包含 1–30 项，以 navigate 开头。形式包括 `{ "kind": "navigate", "stepId": "home" }`、`{ "kind": "fill", "selector": "#username", "valueEnv": "BBA_INPUT_USER" }`、`{ "kind": "click", "selector": "#submit" }` 和 `{ "kind": "wait", "selector": "#dashboard" }`。
- `maxRedirects` 为 0–5。每个目的地都必须与一个已声明的请求匹配，Chromium 提供方法和请求体时也包括在内。
- `observe` 最多包含 20 个 `{ "name": "identity", "selector": "#identity", "attribute": null }` 条目。null 表示读取 textContent；也可以改为选择某个属性。会保留是否存在、摘要，以及在 4,096 个字符处的截断。

发送前会匹配完整 URL、方法和请求体字节。已知表单可使用 `body: { "format": "form", "valueEnv": "BBA_BODY_LOGIN" }` 以及使用 `BBA_INPUT_USER` / `BBA_INPUT_PASSWORD` 的填写动作。期望的请求体必须与表单序列化结果完全一致，包括顺序、编码和隐藏字段。缺失的输入，或不同/动态且未绑定的请求体都会被阻止。POST/PUT/PATCH/DELETE 需要显式的范围规则、自有资源，以及对状态变更的清理。

## 隔离与保真度

CDP Fetch 会拦截每一跳重定向；仅靠 Playwright 路由只能覆盖第一个 URL。浏览器网络策略保持生效，且不允许直接跟随重定向。拒绝流量的代理和 WebRTC 策略保持生效；Service Worker、WebSocket 和下载被阻止。中继会把选定的 Set-Cookie 以及 CSP/CORS 响应头送回 Chromium。它只把浏览器生成的 Cookie/Bearer 转发给 `sessionOrigin`，绝不使用个人浏览器配置文件、持久化会话，也绝不把这些头发送到其他来源。登录表单、动态令牌和 SSO 域名不会被推断；额外的窗口或提供方需要显式定义。

查询、期望的请求体和填写的值都来自环境变量。切勿把凭据放进选择器、ID、基础 URL 或引用中。步骤可以像 `run` 一样投影 JSON 响应事实。浏览器会话没有可恢复的检查点：崩溃后预算和预留仍在，但会话会丢失。

## 产物

`scope.json` 和 `config.json` 保留的是引用，而不是值。`requests.jsonl` 在发送前同步预留记录，并保存元数据/事实、已完成的动作以及经过清理的网络错误。`scenario.json` 保存结果、计数、DOM 事实和校验和。`artifact.json` 为分页的 `artifact-view` 封存日志、结果和来源。请求体、密码、Cookie 和令牌绝不保存。一个已完成的动作或 DOM 变化展示的是观察到的行为，而不是安全性。报告需要期望的规则、对照、身份/状态以及影响的证据。本地测试涵盖表单登录、重定向、两个 Cookie、轮换、已认证读取、脱敏以及对未声明请求的阻止。
