# 首版验证记录

## 0.1.2 报告误解修复（2026-09-28）

- 用户提供 VS Code 插件实际可用时的报告 `Doc/diagnosis-20260928-104409.md`。证据显示系统代理及指定代理的 TLS 均通过，5 次无凭据 HEAD 返回 403，chatgpt.com 的直连 TCP 超时。
- 修正展示：配置观察默认使用“信息”；401/403/405 和 3xx 的 HEAD 响应使用“已响应”，不视为业务通过；相同状态码合并说明。结论首先说明有响应的目标与路径，保留各项证据标识。
- 代理路径有响应时，直连失败只提示路径差异，不要求重启正常应用。超时证据显示明确的超时描述，不再出现容易误解的 Unknown error。
- 407、429、5xx 等继续警告，TCP/TLS 的真实失败不隐藏。HTTP 的 Qt 错误枚举明确说明可能来自状态码映射。
- 新增同报告组合的回归测试：5 次 403 合并、代理响应/直连失败、异常路径仍保留、407 不算目标可达。QtTest 共 11 项通过、0 失败。
- Release 打包及隔离 PATH 的 TLS 自检通过，用户的 Qt Creator Debug 影子构建已更新到 0.1.2。
- 原始用户报告未修改；其“插件实际可用”来自用户反馈，不作为工具自动验证的业务成功。

## 0.1.1 调试运行修复（2026-09-28）

- 用户通过 Qt Creator 的 Debug 模式运行。根因是旧版仅向发布目录部署 OpenSSL DLL，影子构建的 Debug EXE 目录没有部署，因此 TLS 检测不可用。这与实际 Codex 可用不矛盾。
- qmake 现在在 Debug / Release 每次构建时自动部署两个 TLS DLL；应用按绝对路径从 EXE 目录加载，并在诊断前执行一次运行环境自检。
- 已在用户现有的 `build-NetworkDoctor-Desktop_Qt_5_12_12_MinGW_64_bit-Debug` 目录重新构建，Debug TLS 自检通过。
- Debug 实际联网验证：系统代理与指定代理的 TLS 均通过，HTTP HEAD 返回 403；这表示探测请求收到了响应，不能等同于真实客户端不可用。
- Release 使用只含 Windows 系统目录的 PATH 自检通过，避免借用 Qt 开发目录的 TLS 依赖。
- 故意只复制 EXE、不提供 TLS DLL 的受控回归验证通过：结果为“工具自检失败（未执行网络诊断）”，只有一条自检证据，不发送后续网络探测。
- QtTest 更新为 10 项通过、0 失败（8 个业务测试，加初始化和清理）。新增自检失败短路及重复结论合并测试。
- 证据文件：`build/debug-tls-self-check.json`、`build/debug-diagnosis.json`、`build/tls-self-check.json`、`build/missing-tls-result.json`、`build/test-results.txt`。

以下为 0.1.0 历史记录。

日期：2026-09-28。版本：0.1.0。

## 构建与交付

- Qt 5.12.12，MinGW 7.3 64 位，Release 构建通过。
- `build.ps1` 完整执行通过，包括 qmake、编译、windeployqt、TLS DLL 拷贝及 QtTest。
- 交付目录：`deploy/NetworkDoctor`，30 个文件，约 56 MiB。
- 打包程序启动及界面渲染检查通过；截图位于 `build/window.png`。中文、默认代理 7892、结果页签和导出操作可见，无截断。

## 自动化测试

QtTest 共 9 项通过、0 失败（其中 7 个业务测试，加初始化和清理）。结果位于 `build/test-results.txt`。

| 测试 | 覆盖内容 |
| --- | --- |
| redaction | Authorization、Cookie、URL 凭据和参数、用户目录、邮箱、Key 脱敏 |
| proxyPaths | 按 HTTPS 选择静态代理、排除规则、PAC 跳过、无 HTTPS 代理的直连、非法端口和认证代理拒绝 |
| classification | HTTP 401/403 与断网区分、系统直连失败不误认为代理端口失败、同目标路径对比 |
| reportAndBaseline | JSON 写入与回读一致、Markdown 证据、状态/耗时变化、不同对象拒绝直接比较 |
| targetValidation | 目标配置加载、拒绝带账号或查询参数的 URL |
| logPrivacy | 错误关键词提取、不泄露原始日志与文件路径 |
| timeoutAndCancel | 本地受控代理接受 CONNECT 后保持静默，验证 TLS 超时；连续两次启动并取消，验证结果和线程结束 |

## 实际探测

通过打包程序 `--diagnose --output` 完成检测并成功导出 JSON。样本位于 `build/diagnosis-local.json`，属于当前开发检测进程，不代表用户桌面应用的实际运行环境。

- `127.0.0.1:7892` TCP 可连接。
- 经指定代理访问 `chatgpt.com` 和 `auth.openai.com` 时，TLS 证书与主机名验证通过。
- 两个目标的无凭据 HEAD 探测均返回 HTTP 403，被标记为“警告”，没有被归类为单纯断网或封号。
- 直连 TCP 超时，后续 TLS/HTTP 正确跳过。
- 该检测进程读到自动发现/PAC 设置，系统代理路径明确跳过，未声称验证了实际用户的静态系统代理路径。

## 尚未验证的范围

- 实际 ChatGPT/Codex 登录、对话、WebSocket 和流式连接。
- 用户正常桌面会话中的 Fastlink 系统代理配置及故障复现。
- PAC 执行、代理认证、VS Code JSONC/Profile/远程配置、Codex TOML 自定义 provider、WSL。
- 日志关键词不进行时间关联与根因证明。
- 真实断网、证书失效、DNS 故障等不同现场环境仍需要后续实测；不得把规则测试和一次实际探测当作覆盖所有网络情况。

开发产生的截图、报告及构建输出不纳入源码版本控制。
