# 针对自有状态的跨源表单 (1.9.0)

[English](../CSRF-CHECK.md) · [Español](../es/CSRF-CHECK.md) · [Português (Brasil)](../pt-BR/CSRF-CHECK.md) · **简体中文**

`csrf-check` / `csrf_check` 使用 Chromium，从一个已声明的攻击者来源向你控制的账号上的某个动作发送**一次** POST 表单。配置字段为 `schemaVersion: 1`、`class: "cross-origin-form"`、`policyReference`、`attackerPageUrl`、`stateUrl`、`actionUrl`、`cookieEnv`、`sameSite`、`formField`、`formValue`、`statePointer`、`beforeValue` 和 `afterValue`。范围必须允许两个来源、对攻击者页面和状态的 GET、对精确动作的表单 POST，以及至少五个请求。`BBA_COOKIE_*` 的值来自环境变量，绝不持久化。

引擎会检查初始状态和匿名请求被拒绝的情况。然后在隔离的浏览器上下文中打开攻击者页面，构造已声明的简单表单，确认 Chromium 发送了预期的 Cookie 和 `Origin`，并比较最终状态。`confirmed` 要求发生已声明的状态转换且响应成功。如果状态没有改变，并且浏览器省略了 Cookie 或服务器拒绝了该动作，则结果为 `not-reproduced`；对照不完整则为 `unresolved`。它不会推断或强制使用其他 SameSite 设置、动态令牌或未声明的动作。

测试状态由操作者创建并恢复。把结果称为 **CSRF**，需要一个真正跨站的攻击者，以及按政策确实需要经过认证的用户意图的动作。`127.0.0.1` 上的两个实验端口是不同的来源，但可能属于同一站点；该实验环境只验证引擎的表单/Cookie/状态流程。`artifact-view` 读取已封存的日志。崩溃后需要检查；该动作不会被重试。
