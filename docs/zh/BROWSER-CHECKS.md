# Chromium 中的 XSS 与 CORS 检查

[English](../BROWSER-CHECKS.md) · [Español](../es/BROWSER-CHECKS.md) · [Português (Brasil)](../pt-BR/BROWSER-CHECKS.md) · **简体中文**

`browser-check --scope scope.json --config browser.json --out <新目录>` 和 MCP 工具 `browser_check` 针对受控数据和来源执行有限次数的对比。它们需要 Chromium、已授权的范围和允许的技术。仅凭响应头或被反射的文本，证据并不充分。

所有请求都使用 BBA 的传输层。只有完整 URL、方法以及绑定到环境的输入都与已声明步骤一致的 GET 才会被发送。CSP、CORS、来源隔离和 `nosniff` 响应头会被保留；不跟随重定向。Service Worker、WebSocket、下载以及计划之外的访问都会被阻止。拒绝流量的回环代理和 WebRTC 策略保持生效。`budgetId` 会启用共享预算。

## 通用字段

使用 `schemaVersion: 1`、`class`、`policyReference`、`observationMs`（50–5000）、`baseline`、`probe` 和 `resources`。步骤沿用 `run` 契约：唯一 ID、GET、基础 URL、`credentialEnv`，以及来自 `BBA_INPUT_*` 的可选查询输入。`resources` 列出页面确实需要的资产；发现的主机不会被自动加入。这些检查不接受请求体或投影。

## XSS

设置 `class: "xss"`、`boundary: "untrusted-input-script"` 和 `markerEnv: "BBA_INPUT_MARKER"`。baseline 与 probe 使用相同凭据访问同一个基础 URL，但输入的具体内容不同。唯一的不透明标记由 12–128 个字母数字、连字符或下划线字符组成。智能体会准备无害的输入和针对具体上下文的最小 payload，试图调用 `window.__bbaProof(marker)`。payload 保存在环境变量中，而不是计划或报告里。Chromium 暴露该函数只是为了观察期望的标记是否从应用来源被调用。它绝不读取 Cookie、文件、令牌或其他用户的数据。

只有当 probe 执行了标记而 baseline 没有时，检查才会确认。被转义的文本或被 CSP 阻止都不构成确认。两个对照中都执行、必需资源被阻止、预算耗尽以及失败，都保持为不确定。负面结果仅覆盖所观察到的输入、上下文和时间窗口。操作者必须证明攻击者能够控制输入，并存在非预期的可执行上下文；self-XSS 或预期内的 HTML 不会自动构成可报告问题。不存在通用的 payload 生成器，也不测试可能影响真实用户的存储型 XSS。

## CORS

设置 `class: "cors"`、`boundary: "private-cross-origin-read"`、`protectedPointer` 和 `target`（读取私有数据的 GET）。baseline 在目标来源打开页面；probe 在另一个受控且被允许的来源打开页面。配置 Cookie：

```json
"cookie": {
  "origin": "https://service.example",
  "valueEnv": "BBA_COOKIE_A",
  "sameSite": "Lax"
}
```

目标的 `credentialEnv` 必须与该 Cookie 一致。只有目标来源的步骤可以使用它；外来页面绝不会从中继处收到它。其值是 `name=value; name2=value2` 形式的 Cookie 字符串。Chromium 会按声明的 URL 和 SameSite 接收测试 Cookie；Secure 由 HTTPS 推导。这必须与真实会话一致。BBA 不会推断 Cookie 属性，也不会自动化登录或轮换。

检查会执行匿名对照、同源读取，以及带 `credentials: "include"` 的外来来源 `fetch`。中继会保留 `Origin`、CORS 响应头以及浏览器实际的 Cookie 投递行为；绝不会添加 Chromium 省略的 Cookie。确认需要匿名请求被拒绝，并且外来来源的浏览器成功读取到同一个私有字段。Chromium 会拒绝带凭据的 `Access-Control-Allow-Origin: *`。probe 返回 401、公开数据、数值不同以及证据不足，都保持为不确定。如果中继收到了数据但浏览器无法读取，则这次具体读取未被复现；这并不能说明所有 CORS 策略的情况。攻击者来源和 Cookie 属性是报告的重要前提条件。

## 证据与恢复

scope/config 副本不包含环境变量的值。`requests.jsonl` 在发送前同步预留记录，并保存最小化的响应和脱敏后的对比。`browser-check.json` 保存观察、结果和校验和；`artifact.json` 关联日志、结果和来源，供分页的 `artifact-view` 使用。`report.md` 是草稿。响应体、Cookie、payload 和原始标记都不会被保存；报告前请重新构造安全输入和确切的前提条件。

浏览器检查无法恢复。崩溃后，请先查看日志和共享预算中不确定的预留，再使用新的输出目录。时长、间隔、字节数、3xx/429/5xx 和取消导致的停止仍然适用。已测试合成的存在漏洞/已修复应用、CSP、通配 CORS、缺少凭据、被过滤的数据和过期会话。
