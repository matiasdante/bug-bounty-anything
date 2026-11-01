# CLI 指南

[English](../cli.md) · [Español](../es/cli.md) · [Português (Brasil)](../pt-BR/cli.md) · **简体中文**

本地引擎的命令参考：带范围的执行、导入、抓取、评估、签名、项目请求头、实验文件、限制和验证。请先按[安装指南](installation.md)安装。

## 带范围的执行与恢复

[执行指南](EXECUTION.md)定义了契约、限制、检查点和恢复。在为已授权资源准备好范围和计划之后：

```powershell
npm run bba -- scope-check --scope scope.json --plan plan.json
npm run bba -- run --scope scope.json --plan plan.json --out runs/investigation
npm run bba -- resume runs/investigation --scope scope.json
npm run bba -- inspect-run runs/investigation
npm run bba -- export-run runs/investigation --out runs/investigation-export.json
npm run bba -- report-run runs/investigation --out runs/investigation-report.md
```

`scope-check` 验证格式、时间窗口和目的地匹配；**它不会核实资产所有者的许可**。写出范围之前，请先确立该许可和当前的规则。`run` 和 `resume` 会发送请求；上面其余命令都是离线的。Ctrl+C 会记录已知的情况。`resume` 保留预算和证据，要求使用相同的当前范围，并且只运行尚未开始的步骤。结果丢失的在途请求保持为不确定，且绝不会被自动重试。因错误或限制导致的停止需要审阅，必要时开启新的调查。

## 导入攻击面与政策

```powershell
npm run bba -- import-surface --format har|openapi|rea|graphql|js-bundle --input source.json --out runs/surface.json [--quarantine]
npm run bba -- import-policy --format hackerone|bugcrowd|intigriti|security-txt --input policy.json --out runs/policy-draft
```

离线导入器会从 HAR 1.2、Swagger 2.0/OpenAPI 3.0/3.1 JSON、REA 证据、GraphQL 内省/SDL 以及 JS bundle/SourceMap v3 中投影出端点。它不会联系 URL，也不授予授权。`--quarantine` 会统计并跳过无法表示的条目，而不是拒绝整批。条目会区分观察到的 HAR/REA 数据与声明的 schema 或 JS 数据，并保留来源定位信息。请求头、请求体、查询值、示例和描述都会被丢弃。数字、UUID 和过长的路径段会变成 `{opaque}`。支持 RFC 3986 的路径字符和带方括号的查询名，有歧义的转义仍被阻止。政策导入会把精确的 HTTPS 资产提取到 `scope.draft.json`；通配符域名保存在 `manualReviewWildcards` 中，绝不会被悄悄展开。

## 使用 Chromium 抓取

```powershell
npm run bba -- capture --scope scope.json --plan plan.json --out runs/capture
```

无头 Chromium 会访问计划的每一步，并写出 `surface.json`、`capture.json` 和 `pages.json`（观察到的路径、动作和字段名，不含值和查询）。范围模式为 `loopback-lab` 和 `public-https`。已测试本地服务器以及对 `www.dcs.ar` 的有边界公开导航；该试点没有测试登录、权限或 payload。

每个浏览器请求都经过 BBA 的传输层：范围内精确的 GET、固定的 DNS、公网 IP 验证、不重定向，以及超时、大小、间隔和预算限制。其他请求被阻止；停止之后，后续步骤被标记为 `not-sent`。Chromium 自己的流量被导向一个拒绝流量的回环 sink，并计为 `leak-attempts`；DNS 解析和直接的 WebRTC UDP 被禁用。测试覆盖了这些边界。在固定版本的 Chromium 中，`preconnect` 和 `dns-prefetch` 没有打开连接，因此不声称它们是已证实的向量。

`credentialEnv` 可接受作为 Bearer 的 `BBA_TOKEN_*`，或作为 Cookie 头的 `BBA_COOKIE_*`；二者绝不会同时发送，值也绝不持久化。会话 Cookie 由操作者获取。BBA 不会登录，也不会应用 `Set-Cookie`，因此轮换的会话可能变为未认证。每一步都使用阻止 Service Worker 的临时上下文。在 `surface.json` 中，`status: null` 表示没有发送请求。抓取没有检查点：崩溃可能丢失已发送请求的记录。表单登录、POST 和爬取不在此路径内。退出码：`0` 完成，`1` 已停止，`130` 已取消。

## 评估授权假设

```powershell
npm run bba -- evaluate-run runs/investigation --checks checks.json --out runs/evaluation.md
```

这个离线对比器读取经过验证的运行，以及 `checks.json` 中针对 `bola`、`bfla` 和 `property-exposure` 声明的假设。每项检查使用一个匿名对照，以及用不同凭据对同一 URL 发起的 baseline 和 probe。对照被拒绝且两个 200 响应相同，只会得到 `needs-validation`；probe 被拒绝而 baseline 有效，则为 `not-reproduced`；对照开放、baseline 失败、响应缺失、5xx 或 200 响应不同，则为 `unresolved`。属性暴露中不同的 200 可能是部分泄漏。它比较响应哈希，不保留内容，也不衡量影响，并且无法核实声明的角色或所有者。`not-reproduced` 并不意味着系统是安全的。本地的存在漏洞和已修复实验环境通过真实 HTTP 演练了这些情形。

## 导入扫描器候选项

```powershell
npm run bba -- import-candidates --format zap|nuclei|subfinder --input zap-report.json --scope scope.json --out runs/candidates.json
```

BBA **不会**运行 ZAP、Nuclei 或 Subfinder。它们的活动会绕过 BBA 的范围与预算传输层。BBA 离线规范化由操作者提供的 ZAP JSON、Nuclei JSONL 或 Subfinder JSONL，上限为 2 MiB 和 5,000 条记录。每个候选项都保持 `unvalidated`。范围状态为 `in-scope`、`excluded`、`out-of-scope` 或 `unparseable`；Subfinder 的主机名在不做 DNS 的情况下比较。描述、原始证据、攻击、请求、响应和查询值都会被丢弃。扫描器的严重程度只是来源的标签，不是 BBA 的评估。重复项会被计数并合并。格式依据工具文档和合成测试建模，而不是一次真实的扫描器运行。通告和版本差异的查询仍然是手工的。

## 冻结评估

```powershell
npm run bba -- eval --out runs/evaluation.md
```

运行 18 个强制性的回环用例：六个响应对比、三个预算不确定用例、六个范围边界、两项机密检查和一个恢复用例。`FROZEN_DIGEST` 保护用例 ID 和期望结果。哈希对比器报告的是候选项，而不是已确认的发现；自主 BOLA 路径另有测试。合成的实验指标不能估计真实世界的检出率或误报率，也不能证明目标是安全的。Chromium 隔离另有抓取测试。

## 签名、提交草稿与本地检查器

```powershell
bba keygen --out keys/operator
bba sign-evidence runs/investigation --key keys/operator/bba-ed25519.key.pem
bba verify-signature runs/investigation --pub keys/operator/bba-ed25519.pub.pem
bba export-submission runs/investigation --platform hackerone|bugcrowd|ghsa --out runs/submission.md
bba ui runs/investigation --out runs/inspector.html
```

Ed25519 签名会验证完整的文件或目录，包括之后的新增和删除。`export-submission` 写出 Markdown 草稿，其中的 `curl` 命令已脱敏，并且仅对 `confirmed` 的发现给出保守的 CVSS v3.1/v4.0 基线。`ui` 在 `127.0.0.1` 上以严格的 CSP 提供只读检查器，或导出不含 JavaScript 和外部资源的独立 HTML。案例档案命令可以创建案例并将其与政策关联、检查完整性和预算、抓取精确的 URL、执行语义配置，并在不重复已记录步骤的情况下恢复暂停的工作；参见[案例档案](CAMPAIGNS.md)。

## 项目标识请求头

`scope.requestHeaders` 在 `run`、`resume`、`capture` 和 `hunt` 中支持按来源设置的标记：

```json
"requestHeaders": [
  { "origin": "https://authorized-service", "name": "x-bug-bounty", "valueEnv": "BBA_HEADER_RESEARCHER" },
  { "origin": "https://authorized-service", "name": "user-agent", "valueEnv": "BBA_HEADER_AGENT" }
]
```

值由操作者在环境中设置。只允许小写的 `user-agent` 或 `x-*` 名称，不允许认证、Cookie、主机或传输类请求头。值必须是 1–512 个不含换行的可打印 ASCII 字符。范围保存的是引用和名称，绝不保存值。缺失的值会在发送或预留请求之前失败。每个标记只发送到其声明的来源。没有此字段的现有范围仍然可用。

## 文件与契约

`lab` 写出 `investigation.json`（一个带版本的包，含范围、五条证据记录、两个假设和 SHA-256 校验和），以及包含结果、复现、证据引用、影响和局限的 `report.md`。[src/contracts.ts](../../src/contracts.ts) 负责验证输入。证据保存 UTC 时间、行为者、路由、HTTP 状态，以及仅限允许的合成字段，不保存完整的 HTTP 捕获、认证头、Cookie、错误响应体或意外字段。读取时，BBA 会验证结构、版本、ID、引用、校验和以及结论的一致性。哈希能发现意外的改动；**它们不是签名，也不能证明第三方的真实性**。JSON 是数据，绝不是可执行代码。

被中断的实验写入会保持为 `.incomplete`。`run/resume` 使用单独的检查点契约。`runs/` 下的输出会被 Git 忽略。

## 执行器限制

固定的 `lab` 路径只允许对两个精确的实验路由发 GET，没有查询、重定向或任意域名。它有五个请求、每个请求两秒超时和 4,096 字节的响应上限。遇到重定向、429、5xx、超时、响应体过大或超出契约的内容时会停止。通用的 `run/resume` 限制来自范围，并保留部分状态。仅凭 HTTP 元数据和哈希不会被解释为漏洞。

## 验证

`npm test` 使用 `node:test` 和真实的本地 HTTP 服务器，覆盖存在漏洞/已修复变体、不确定对照、隔离、限制、机密、范围、检查点、完整性和 CLI。其中包括取消，以及进程死亡后不产生重复请求的恢复。公网 DNS 的选择使用受控解析器；测试不会联系生产服务。`npm run check` 执行严格的 TypeScript 检查且不生成 JS；`npm run verify` 依次运行 check、build 和测试。CI 在 Ubuntu 和 Windows 上使用 Node 22.13 和 24 运行。

退出码：`0` 完成（包括发现了漏洞的实验环境），`1` 错误或已停止，`2` 参数无效，`3` 部分完成且结果不确定，`130` 已取消。退出码为零并不能证明不存在漏洞。
