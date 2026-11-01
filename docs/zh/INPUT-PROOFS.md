# 有边界的输入检查 (1.9.0)

[English](../INPUT-PROOFS.md) · [Español](../es/INPUT-PROOFS.md) · [Português (Brasil)](../pt-BR/INPUT-PROOFS.md) · **简体中文**

两个工具都复用精确的范围、`requestRules`、共享预算和 SQLite 检查点。输入由配置生成或绑定；凭据来自环境变量。未完成的运行会保留预留，只能用相同的范围和配置恢复尚未开始的步骤。

## 模板表达式

`template-check` / `template_check` 接受 `schemaVersion: 1`、`class: "template-arithmetic"`、`policyReference`、`url`、`parameter`、`pointer`、`operands: [a,b,c]` 和 `credentialEnv`（`null` 或 `BBA_TOKEN_*` / `BBA_COOKIE_*` 引用）。操作数是 2 到 997 之间互不相同的整数。范围必须授权该精确的 GET 和查询参数名。引擎向同一个资源发送字面量 `a*b`、`{{a*b}}` 和 `{{b*c}}`，投影一个 JSON 字段，且只保存摘要。当对照保持字面量且两个表达式都返回各自的乘积时，它确认的是**对该语法的求值**。如果两者都保持字面量，则结果为 `not-reproduced`；其他情形为 `unresolved`。操作者必须确立该字段本应把输入当作字面文本处理。不测试 SQL、NoSQL、命令执行、文件和第三方数据。`resume-template-check` / `resume_template_check` 使用相同的范围和配置。

## URL 回调

`ssrf-callback-check` / `ssrf_callback_check` 接受 `schemaVersion: 1`、`class: "outbound-fetch"`、`policyReference`、`triggerUrl`、`queryName`、`credentialEnv`、`callbackUrl`、`receiptUrl` 和 `receiptPointer`。触发、回调和回执都必须是范围内的精确路径。回调使用你拥有的独立来源，并以至少 12 个字符的不透明令牌结尾。其接收端在 `receiptPointer` 处暴露一个 JSON 布尔值，仅在此回调之后才从 `false` 变为 `true`。

引擎先读取回执，把回调 URL 作为查询值发送给触发端，然后最多轮询回执两次。触发返回 200 且出现 `false` → `true` 的转变，说明服务向**该自有接收端**发出了外联请求，前提是接收端配置正确且已声明的政策禁止该目的地。它不能证明可以访问内网、元数据，或响应内容被泄露。它绝不生成内部 URL、跟随重定向或扫描多个目的地。`resume-ssrf-callback` / `resume_ssrf_callback` 保留这些限制。

服务对接收端的回调是 BBA 客户端计数器之外的额外请求。请保留接收端日志，并将其计入项目预算。两份报告涵盖发生了什么、如何发现、证明、复现和修复，不会外推严重程度。
