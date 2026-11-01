# 安装与配置

[English](../installation.md) · [Español](../es/installation.md) · [Português (Brasil)](../pt-BR/installation.md) · **简体中文**

如何安装 BBA 技能、从源码或 npm 运行它、诊断本地环境以及注册 MCP 服务器。会发送请求的命令请参见 [CLI 指南](cli.md)。

## 调用技能

在项目依赖可用的情况下：

```powershell
npm run build
node dist/cli.js install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
```

输出目录必须是新目录。安装会复制说明、参考资料和界面元数据；`runtime.json` 指向此包的 Node 运行时和已编译的 CLI。请让项目保持在该位置。该命令不会安装依赖，也不会更改 MCP 或其他技能。如果技能目录尚未刷新，请开启新的对话。`update-skill --out <已有目录>` 会更新受管文件，在 `.bba-backups/` 中保留备份，检查该安装是否属于此包，拒绝资源链接，并保留无关文件。`installation.json` 保存受管文件的哈希；被中断的更新绝不会被报告为已完成。

对于 Claude Code、Codex 或 Gemini CLI，`npm run package:skill -- --out dist-skill.zip` 会生成包含已编译 CLI、`SKILL.md` 和参考资料的可移植 ZIP。较早的 Windows PowerShell 打包器仍然可用。把 `bug-bounty-anything` 解压到 `.claude/skills/` 或 `~/.claude/skills/`。最初的 MCP 注册只暴露离线工具；需要浏览器检查时请单独安装 Chromium。

例如，向智能体提问：**`$bug-bounty-anything investigate https://authorized-service/ and prepare findings`**。智能体会查阅当前政策并创建所需文件。它只会询问无法自行确定的事实，例如测试账号或访问规则。没有授权时，它会停止对该资产的主动检查；公开资料研究可以继续。该技能通过 CLI 工作，不需要 MCP，并在合适时把客户端产物的分析交给 REA。

如果缺少政策或授权时间窗口，`start-case --target <url> --out <目录>` 会记录一个待定案例，不创建范围，也不发送请求。确立许可之后，使用 `prepare`：

```powershell
node dist/cli.js prepare --scope scope.json --target https://authorized-service/ --out runs/investigation
```

这会创建范围副本、匿名 GET 的初始计划、带校验和的案例记录和调查笔记。它不会联系目标，也不证明许可。它会拒绝被排除或范围外的 URL、已过期的窗口和已存在的输出。MCP 同样暴露 `prepare`，且不启用网络访问。`budgetId` 会在各阶段之间共享一个持久的请求计数、间隔和时长，并存放在规范范围文件旁；旧范围保持按次运行的限制。

## 要求与本地运行

- Node.js **22.13.0 或更高版本**，以及 npm。Node 在开发时提供 TypeScript 类型剥离，并提供原生 SQLite。唯一的生产依赖是 `playwright-core` 1.64.1（Apache-2.0）。
- 在 Node 22.13 上开发或测试时，请在 PowerShell 中用 `$env:NODE_OPTIONS = '--experimental-strip-types'` 启用原生的 TypeScript 类型剥离。已发布的包运行编译后的 JavaScript，不需要此选项。
- 抓取和浏览器检查需要运行 `npm install` 和 `npx playwright-core install --only-shell chromium`。Chromium 会下载到仓库之外。其他命令不需要它。
- 本地实验环境和检查器需要连接 `127.0.0.1`。如果沙箱阻止了回环，请在允许回环的本地终端中运行。

```powershell
npm run bba -- lab --variant vulnerable --out runs/vulnerable
npm run bba -- lab --variant fixed --out runs/fixed
npm run bba -- inspect runs/vulnerable
npm run bba -- report runs/vulnerable --out runs/vulnerable-export.md
npm run demo:core -- --out runs/core-demo
npm test
```

在阻止 `npm.ps1` 的 PowerShell 环境中，请使用 `npm.cmd`。输出文件和目录必须是新的；BBA 不会覆盖已有的调查。`lab` 在 `127.0.0.1` 启动一个一次性服务器，创建两个合成账号和文档，发送五个顺序请求，即使出错也会关闭。凭据只保留在内存中。`inspect` 和 `report` 无需联网即可读取经过验证的本地证据；`report` 从 JSON 重建报告。`demo:core` 运行第二个实验环境，并写入 SQLite 检查点、不含凭据的范围和计划、JSON 导出以及报告。请勿重复使用其临时凭据或端口。

## 安装、诊断与 MCP

直接从 npm 一次性运行 CLI，无需全局安装：

```powershell
npx --yes bug-bounty-anything@latest capabilities
npx --yes bug-bounty-anything@latest --help
```

`npx` 会下载已发布的包并运行其 `bba` 命令。要持久注册技能或 MCP，请全局安装该包：注册会保存 CLI 的路径，而临时的 `npx` 缓存条目之后可能消失。

```powershell
npm install --global bug-bounty-anything@latest
bba install-skill --out "$env:USERPROFILE/.agents/skills/bug-bounty-anything"
bba doctor
```

浏览器检查需要用 `npx playwright-core install --only-shell chromium` 单独安装 Chromium。在源码仓库中，`npm install`、`npm run build` 和 `npm test` 仍是开发命令。公开的包和代码使用 [MIT 许可证](../../LICENSE)。

该包提供 `bba`，包括分组的 `campaign`、`check` 和 `study` 子命令、按命令的帮助以及 `--lang es|en`。`doctor` 只检查本地的 Node、SQLite、回环、临时存储、Chromium，以及已存在的 `BBA_TOKEN_*`、`BBA_COOKIE_*`、`BBA_HEADER_*`、`BBA_INPUT_*` 和 `BBA_BODY_*` 变量的名称（绝不检查值）。

```powershell
bba mcp --root C:/path/to/workspace
bba mcp --root C:/path/to/workspace --allow-network
```

MCP 通过 stdio 上的 JSON-RPC 运行，支持 `initialize`、带外的 `ping`、通过 `notifications/cancelled` 实现的真实取消以及 `tools`。`tools/list` 是权威来源；主动工具仅在 `--allow-network` 时出现。在 Windows 和 POSIX 上，路径都被限制在 `--root` 之内，包括防止符号链接和 junction 逃逸；内部错误会被清理。`setup-mcp --root <workspace> --client codex|claude|gemini [--apply] [--allow-network] [--replace]` 会预览或应用注册，并保留本地备份。
