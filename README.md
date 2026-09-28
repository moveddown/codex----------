# ChatGPT / Codex 联网诊断

基于 Qt 5.12.12 的 Windows 桌面工具。针对 Codex 桌面端、VS Code 插件和 ChatGPT Windows 桌面端的“无法连接 / 没有网络”问题，对比直连、系统代理和指定代理，导出有证据的脱敏报告。

## 运行

打开 `deploy/NetworkDoctor/NetworkDoctor.exe`，保持整个文件夹完整，不能只复制 EXE。

1. 打开 Fastlink，并开启系统代理。
2. 选择使用方式；指定代理默认 `HTTP 127.0.0.1:7892`，可按实际设置修改。
3. 点击“开始一键诊断”。逐项超时默认 6 秒，较差网络下完整检查可能需要几分钟，支持取消。
4. 查看“诊断结论”和“逐项证据”。可以导出 Markdown 给其他 AI，或导出 JSON 留档。
5. 实际客户端正常时，使用“保存正常基线”；以后可选择该文件对比。

程序只读取设置和发起基础网络探测，不修改系统配置，不自动上传报告。代理认证暂不支持。

## 检测范围

- 非环回活动网络接口数量。
- Windows 当前用户 Internet 代理设置、静态 HTTPS 代理及排除规则；PAC/自动发现明确跳过。
- 当前诊断进程的 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY 线索。
- Codex `.env` 中可识别的代理变量、配置文件存在性；VS Code 默认用户严格 JSON 设置中的 `http.proxy`。JSONC、Profile、工作区、远程与 WSL 设置不作猜测。
- 本地 DNS、到目标或代理的 TCP、带证书验证的 TLS 1.2+、不携带登录凭据的 HTTPS HEAD。
- 默认目标 `chatgpt.com` 和 `auth.openai.com`。发布目录的 `targets.json` 可调整 1～8 个域名；这些目标不是官方完整网络白名单。
- 手动选择日志时，只扫描最多末尾 1 MiB，输出固定错误关键词的计数，不导出原文、文件路径或凭据。计数不与检测时间自动关联，也不能独立证明根因。

## 理解结果

“通过”只针对这一项检查。端口可连接不证明代理能转发；TLS 成功不证明登录成功；HTTP 403/401 等响应不等于断网，也不能据此断定封号。

从 0.1.2 开始，配置读取、未设置代理变量等普通观察显示为蓝色“信息”；无凭据 HEAD 返回 401/403/405 或重定向时显示为蓝色“已响应”，不把它当成业务成功，也不直接当成客户端故障。相同 HTTP 状态在结论中合并，原始代码仍完整保留。407（代理认证）、429、5xx 等仍显示警告，连接与 TLS 失败仍保留失败状态。代理有响应时，直连失败仅作为路径差异说明，不建议为此重启正常工作的应用。

HTTP 使用 HEAD，不跟随重定向，不采集正文、Cookie、Authorization 或 Location；网页、防护层与实际业务请求的响应可能不同。这里没有验证账号、登录、模型请求、WebSocket 或流式对话。所有使用方式共享基础网络目标，应用配置检查按选择切换。

显式直连只表示没有指定应用层代理，仍可能经过 VPN、TUN 或透明代理。本地 DNS 结果不代表代理侧解析结果。Windows 当前用户设置不代表 WinHTTP 服务配置或目标应用进程实际环境；本工具没有自动“修复”应用。

## 报告与隐私

报告记录批次、版本、时区、检测对象、超时、路径、开始时间、耗时、错误码、证据和结论。使用结构化白名单采集与文本脱敏；不读取认证文件。域名、公网解析地址、代理主机/端口以及证书指纹会作为必要证据保留，分享前可自行审阅。所有导出和基线均由用户选择本地文件位置。

## 构建与测试

在项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

默认 Qt 根目录为 `D:\QT\Qt5.12.12`，可用 `-QtRoot` 指定。使用 MinGW 7.3 64 位和 qmake，脚本构建 Release、运行 QtTest，并调用 windeployqt 生成发布目录。OpenSSL DLL 来自本机 Qt Creator 安装；这是当前 Qt 5.12 开发环境的兼容方案，面向长期维护或广泛分发应评估升级到受支持的 Qt/TLS 版本。

Qt Creator 可直接打开 `NetworkDoctor.pro`。主要模块：`model` 负责证据/规则/报告，`platform` 负责 Windows 配置读取，`engine` 负责后台检测，`mainwindow` 负责界面。

从 0.1.1 开始，qmake 工程在 Debug / Release 构建时均自动把 OpenSSL DLL 复制到对应 EXE 目录，支持 Qt Creator 的影子构建目录。已打开的旧工程更新后先执行“构建 → 执行 qmake”，然后构建运行。默认从同一套 Qt 安装的 `Tools/QtCreator/bin` 获取 DLL；其他安装布局可在 qmake 参数中指定 `OPENSSL_RUNTIME_DIR`。

诊断前会先进行 TLS 自检。依赖缺失或加载失败时，只报告一次“工具自检失败”，保留 DLL 加载错误，不继续执行网络诊断，也不允许保存为正常基线。发布脚本会使用仅包含 Windows 系统目录的 PATH 验证 TLS 自检，避免开发环境掩盖依赖遗漏。

受控测试覆盖脱敏、代理选择、状态分类、报告序列化、基线差异、目标校验、日志隐私和检测超时/取消。真实网络结果依赖当前环境，不能替代真实客户端验证。

```powershell
# 无界面检测并导出 JSON，完成后退出
.\deploy\NetworkDoctor\NetworkDoctor.exe --diagnose --output .\report.json
# 不联网，渲染界面用于布局检查
.\deploy\NetworkDoctor\NetworkDoctor.exe --smoke .\window.png
```

产品事实参考：[OpenAI 错误说明](https://developers.openai.com/api/docs/guides/error-codes)、[Codex 配置参考](https://developers.openai.com/codex/config-reference)。端点探测和诊断规则是本工具的有限检查，不是 OpenAI 官方健康认证。
