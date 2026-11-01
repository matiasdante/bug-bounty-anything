# 已发表案例的可复现研究

[English](../PUBLISHED-CASE-STUDIES.md) · [Español](../es/PUBLISHED-CASE-STUDIES.md) · [Português (Brasil)](../pt-BR/PUBLISHED-CASE-STUDIES.md) · **简体中文**

第一项研究把 [Faav 的 Titan 文章](https://blog.faav.net/how-i-couldve-accessed-17-trillion-microsoft-records)作为方法参考。`cases/faav-titan-jwt-2026.json` 标识了该出版物和漏洞类别，但不含令牌、服务数据或已授权的目标。历史调查与当前的复现是两回事。

## 智能体工作流

1. 阅读项目当前的政策，并记录来源、时间窗口、资产、排除项、允许的技术、请求上限和自有测试账号。缺少这些时，只停留在离线分析；出版物并不授予许可。
2. 使用 `import-surface --format openapi` 导入 Swagger 2.0/OpenAPI JSON。它省略请求体、示例和机密，保留路由、方法、声明的认证方式和来源追溯。把结构化的公开历史线索记录在 `historical.json` 中，不要假定它们如今仍然有效。
3. 根据已核实的事实创建 `policy.json` 和 `profile.json`。由智能体来写；用户无需自己写 JSON。配置引用环境变量、针对自有数据的无害查询以及一个受保护的 JSON 事实。文件中不含机密。
4. 运行 `study-bundle` 和 `study-plan`。规划会在允许的前缀内，于同一来源选取一个可选认证的操作和一个受保护的操作；历史线索可以用来决胜。没有唯一候选项时，返回 `unresolved` 且不发送请求。在主动工作之前，请审阅 `analysis.json`、`scope.json` 和 `jwt-config.json`。
5. 在环境中提供已签名的令牌和请求体，运行 `study-run`：匿名、原始 JWT、保留旧签名但修改 claim 的 JWT，以及再次使用原始 JWT。只有匿名请求被拒绝，并且两个令牌都出现同一个自有受保护事实时才确认。`resume-study` 会验证包和原始产物，且不重复不确定的尝试。

```powershell
node dist/cli.js import-surface --format openapi --input api.json --out runs/surface.json
node dist/cli.js study-bundle --case cases/faav-titan-jwt-2026.json --policy policy.json --surface runs/surface.json --historical historical.json --profile profile.json --out runs/study-input.json
node dist/cli.js study-plan --input runs/study-input.json --out runs/study-plan
node dist/cli.js study-run --input runs/study-input.json --out runs/study-active
node dist/cli.js resume-study runs/study-active --input runs/study-input.json
```

包和计划是离线的；run 和 resume 可能发送请求。MCP 名称为 `study_bundle`、`study_plan`、`study_run` 和 `resume_study`；后两者需要 `--allow-network`。输出必须是新的。请保留 `study-input.json` 的规范路径，因为 `.bba-budgets/<budgetId>` 存放在它旁边。

## 最小契约

- `policy.json`：`schemaVersion: 1`、`mode`、`sourceUrl`、`reviewedAt`、`authorization`（`reference`、`validFrom`、`validUntil`）、以 `{origin,pathPrefixes}` 表示的 `assets` 和 `excluded`、`techniques: ["jwt-signature-integrity"]`、`budgetId` 以及范围的 `limits`。排除项优先。格式和时间会被验证；政策是否合法由调查者核实。
- `historical.json`：`schemaVersion: 1`、`sourceUrl`、`capturedAt` 和 `routes: [{path,clue}]`，其中 `clue` 为 `routing-definition` 或 `endpoint-reference`。历史来源只是提示该去哪里查看。
- `profile.json`：`schemaVersion: 1`、`credentialEnv`（`BBA_TOKEN_*`）、`proofPointer`、`request` 和 `mutation`，遵循 [JWT 契约](JWT-INTEGRITY.md)。POST 请求体使用 `BBA_BODY_*`；请选择自有数据和一个稳定的私有事实。
- `study-input.json`：经过验证的、含五项输入的可移植包。`study-plan/analysis.json` 包含候选项和来源追溯图；范围和 JWT 配置要求有唯一的候选项。`study-active/report.md` 是一份五个问题的草稿。

## 报告中的论断

草稿涵盖问题、发现、利用证明、复现和修复，并附带证据 ID 和局限。`confirmed` 表明被修改的 JWT 对所声明的账号/事实被接受。它不能说明其他身份的权限、批量读取、严重程度，也不能说明文章所述的目标至今仍存在漏洞。`not-reproduced` 仅排除所测试的变异。报告留在本地，供提交前审阅。这个 MVP 每次运行只处理一类假设和一个候选项；它不会自动进行大范围侦察，也不会推断身份或 claim。
