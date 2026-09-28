#include "platform.h"
#include <QNetworkInterface>
#include <QSslSocket>
#ifdef Q_OS_WIN
#include <windows.h>
#include <winhttp.h>
#endif

QString initializeBundledTls()
{
    QStringList details;
    // Load by absolute path, crypto first. Keep libraries loaded for Qt's lifetime.
    // Do not silently borrow TLS DLLs from a developer's PATH or working directory.
    for (const QString &name : {"libcrypto-1_1-x64.dll", "libssl-1_1-x64.dll"}) {
        const QString path = QCoreApplication::applicationDirPath() + "/" + name;
        if (!QFileInfo::exists(path)) {
            details << name + QStringLiteral("：程序目录中缺失");
            QCoreApplication::instance()->setProperty("bundledTlsOk", false);
            QCoreApplication::instance()->setProperty("tlsLoadDetails", details.join("；"));
            return details.join("；");
        }
        QLibrary library(path);
        library.setLoadHints(QLibrary::PreventUnloadHint);
        if (!library.load()) {
            details << name + QStringLiteral("：加载失败，") + clean(library.errorString());
            QCoreApplication::instance()->setProperty("bundledTlsOk", false);
            QCoreApplication::instance()->setProperty("tlsLoadDetails", details.join("；"));
            return details.join("；");
        }
        details << name + QStringLiteral("：已从程序目录加载");
    }
    QCoreApplication::instance()->setProperty("bundledTlsOk", true);
    QCoreApplication::instance()->setProperty("tlsLoadDetails", details.join("；"));
    return details.join("；");
}

Check tlsRuntimeCheck()
{
    Check c;
    c.layer = QStringLiteral("工具自检"); c.route = QStringLiteral("本机"); c.target = QStringLiteral("TLS 运行环境");
    c.started = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    auto property = QCoreApplication::instance()->property("bundledTlsOk");
    bool bundled = !property.isValid() || property.toBool();
    bool usable = bundled && QSslSocket::supportsSsl();
    c.status = usable ? QStringLiteral("通过") : QStringLiteral("失败");
    c.code = usable ? "SSL_READY" : "SSL_UNAVAILABLE";
    c.detail = QCoreApplication::instance()->property("tlsLoadDetails").toString()
        + QStringLiteral("；Qt 编译时 TLS：") + QSslSocket::sslLibraryBuildVersionString()
        + QStringLiteral("；Qt 运行时 TLS：") + (usable ? QSslSocket::sslLibraryVersionString() : QStringLiteral("未就绪"));
    if (!usable) c.detail += QStringLiteral("。这是检测工具自身的依赖问题，尚未进行网络诊断。请从完整发布文件夹运行，不要单独复制 EXE；若文件齐全仍失败，请提交此自检证据检查 DLL 位数及间接依赖。");
    return c;
}

ProxySettings systemSettings()
{
    ProxySettings result;
#ifdef Q_OS_WIN
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = {};
    result.readOk = WinHttpGetIEProxyConfigForCurrentUser(&config);
    if (result.readOk) {
        result.server = config.lpszProxy ? QString::fromWCharArray(config.lpszProxy) : QString();
        result.bypass = config.lpszProxyBypass ? QString::fromWCharArray(config.lpszProxyBypass) : QString();
        result.automatic = config.fAutoDetect || (config.lpszAutoConfigUrl && *config.lpszAutoConfigUrl);
        result.summary = QStringLiteral("来源：Windows 当前用户 Internet 代理设置；静态代理 %1；自动发现/PAC %2；排除规则 %3 条（逐目标应用）")
            .arg(result.server.isEmpty() ? QStringLiteral("未启用") : QStringLiteral("已启用"), result.automatic ? QStringLiteral("已启用") : QStringLiteral("未启用"))
            .arg(result.bypass.split(';', QString::SkipEmptyParts).size());
    } else result.summary = QStringLiteral("Windows 代理设置读取失败，错误码 %1").arg(GetLastError());
    if (config.lpszProxy) GlobalFree(config.lpszProxy);
    if (config.lpszProxyBypass) GlobalFree(config.lpszProxyBypass);
    if (config.lpszAutoConfigUrl) GlobalFree(config.lpszAutoConfigUrl);
#else
    result.summary = QStringLiteral("当前平台不支持 Windows 代理读取");
#endif
    return result;
}

Route systemRoute(const ProxySettings &s, const QString &host)
{
    Route r; r.name = QStringLiteral("系统代理");
    if (!s.readOk || s.automatic) {
        r.supported = false;
        r.reason = !s.readOk ? s.summary : QStringLiteral("检测到 PAC/自动发现；本版不解析自动代理，系统路径跳过。可使用指定代理进行对比。");
        return r;
    }
    for (QString pattern : s.bypass.split(';', QString::SkipEmptyParts)) {
        pattern = pattern.trimmed();
        if ((pattern == "<local>" && !host.contains('.')) || QRegExp(pattern, Qt::CaseInsensitive, QRegExp::Wildcard).exactMatch(host)) {
            r.reason = QStringLiteral("目标命中系统代理排除规则，按系统配置直连"); return r;
        }
    }
    if (s.server.isEmpty()) { r.reason = QStringLiteral("系统未设置静态代理，按系统配置直连"); return r; }
    QString endpoint;
    bool socks = false;
    if (!s.server.contains('=')) endpoint = s.server;
    else {
        QMap<QString, QString> map;
        for (const auto &part : s.server.split(';', QString::SkipEmptyParts)) {
            int equal = part.indexOf('='); if (equal > 0) map.insert(part.left(equal).trimmed().toLower(), part.mid(equal + 1).trimmed());
        }
        endpoint = map.value("https");
        if (endpoint.isEmpty() && map.contains("socks")) { endpoint = map.value("socks"); socks = true; }
        if (endpoint.isEmpty()) { r.reason = QStringLiteral("静态系统代理未配置 HTTPS，按该配置直连"); return r; }
    }
    QUrl url(endpoint.contains("://") ? endpoint : "http://" + endpoint);
    if (socks || !url.isValid() || url.host().isEmpty() || url.port() < 1 || !url.userInfo().isEmpty() || url.scheme() != "http") {
        r.supported = false; r.reason = QStringLiteral("静态代理格式、协议或认证不受支持。使用手动 HTTP/SOCKS5 代理对比；系统路径不作猜测。"); return r;
    }
    r.proxy = QNetworkProxy(QNetworkProxy::HttpProxy, url.host(), quint16(url.port()));
    r.reason = QStringLiteral("已读取并应用 Windows 静态 HTTPS 代理");
    return r;
}

static Check observation(const QString &target, const QString &detail, const QString &code = "OBSERVED", const QString &status = QStringLiteral("信息"))
{
    Check c; c.layer = QStringLiteral("环境"); c.route = QStringLiteral("本机"); c.target = target; c.detail = detail;
    c.code = code; c.status = status; c.started = QDateTime::currentDateTime().toString(Qt::ISODateWithMs); return c;
}

QList<Check> environmentChecks(const Options &o, const ProxySettings &settings)
{
    QList<Check> checks;
    int active = 0;
    for (const auto &iface : QNetworkInterface::allInterfaces())
        if (iface.flags().testFlag(QNetworkInterface::IsUp) && iface.flags().testFlag(QNetworkInterface::IsRunning)
            && !iface.flags().testFlag(QNetworkInterface::IsLoopBack) && !iface.addressEntries().isEmpty()) ++active;
    checks << observation(QStringLiteral("网络接口"), QStringLiteral("发现 %1 个运行中的非环回接口（含虚拟接口）；有接口不等于能访问互联网，不采集 MAC 或本机地址。").arg(active),
                          active ? "INTERFACE_UP" : "NO_ACTIVE_INTERFACE", active ? QStringLiteral("通过") : QStringLiteral("警告"));
    checks << observation(QStringLiteral("Windows 系统代理"), settings.summary, settings.readOk ? "PROXY_READ" : "PROXY_READ_FAILED", settings.readOk ? QStringLiteral("信息") : QStringLiteral("警告"));
    auto sys = systemRoute(settings, o.targets.value(0));
    if (sys.supported && sys.proxy.type() != QNetworkProxy::NoProxy &&
        (sys.proxy.hostName() != o.host || sys.proxy.port() != o.port || (sys.proxy.type() == QNetworkProxy::Socks5Proxy) != o.socks))
        checks << observation(QStringLiteral("代理配置对比"), QStringLiteral("系统：%1；指定：%2:%3。端口/协议/地址存在差异，需结合连接结果判断。").arg(proxyDescription(sys.proxy), o.host).arg(o.port), "PROXY_DIFFERENT");
    auto env = QProcessEnvironment::systemEnvironment();
    for (const QString &name : {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}) {
        QString value = env.value(name);
        if (value.isEmpty()) value = env.value(name.toLower());
        QUrl endpoint(value.contains("://") ? value : "http://" + value);
        bool differs = name != "NO_PROXY" && !value.isEmpty() && endpoint.isValid() && !endpoint.host().isEmpty()
            && (endpoint.host() != o.host || endpoint.port() != o.port);
        checks << observation(name, QStringLiteral("来源：诊断进程继承的环境，不代表目标应用。%1")
            .arg(name == "NO_PROXY" ? (value.isEmpty() ? QStringLiteral("未设置") : QStringLiteral("已设置排除规则（内容不导出）；本工具探测不自动使用此变量")) : safeEndpoint(value)), differs ? "ENV_PROXY_DIFFERENT" : "ENV_OBSERVED");
    }
    if (o.application.contains("Codex")) {
        QString root = env.value("CODEX_HOME", QDir::homePath() + "/.codex");
        QFile file(root + "/.env");
        if (file.open(QIODevice::ReadOnly)) {
            if (file.size() <= 256 * 1024) {
                const auto lines = QString::fromUtf8(file.readAll()).split('\n');
                int count = 0;
                QRegularExpression rx("^\\s*(?:export\\s+)?(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)\\s*=\\s*(.*?)\\s*$", QRegularExpression::CaseInsensitiveOption);
                for (const auto &line : lines) {
                    auto m = rx.match(line); if (!m.hasMatch()) continue;
                    QString value = m.captured(2); if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\''))) value = value.mid(1, value.size()-2);
                    checks << observation(QStringLiteral("Codex .env / ") + m.captured(1).toUpper(), m.captured(1).compare("NO_PROXY", Qt::CaseInsensitive) == 0 ? QStringLiteral("存在排除规则（不导出内容）") : safeEndpoint(value)); ++count;
                }
                if (!count) checks << observation(QStringLiteral("Codex .env"), QStringLiteral("未发现可识别的代理变量；不读取认证文件，也不导出其他变量。"));
            } else checks << observation(QStringLiteral("Codex .env"), QStringLiteral("文件超过读取上限，跳过。"), "SIZE_LIMIT", QStringLiteral("跳过"));
        } else checks << observation(QStringLiteral("Codex .env"), QStringLiteral("文件不存在或不可读；不推断实际应用代理。"), "UNAVAILABLE", QStringLiteral("跳过"));
        checks << observation(QStringLiteral("Codex 配置"), QFileInfo::exists(root + "/config.toml") ? QStringLiteral("配置文件存在；本版不解析 TOML，不导出内容。自定义 provider、base_url、沙箱与 WSL 的实际路径未验证。") : QStringLiteral("默认位置未发现配置文件；未验证自定义配置位置。"), "CONFIG_SCOPE", QStringLiteral("跳过"));
    }
    if (o.application.contains("VS Code")) {
        QFile file(env.value("APPDATA") + "/Code/User/settings.json");
        if (file.open(QIODevice::ReadOnly) && file.size() <= 1024 * 1024) {
            auto content = QString::fromUtf8(file.readAll());
            // JSONC is intentionally not guessed: parse only strict JSON; never export raw settings.
            QJsonParseError error; auto doc = QJsonDocument::fromJson(content.toUtf8(), &error);
            if (error.error == QJsonParseError::NoError && doc.isObject())
                checks << observation(QStringLiteral("VS Code http.proxy"), safeEndpoint(doc.object()["http.proxy"].toString()) + QStringLiteral("；仅默认用户设置，不代表扩展进程、工作区、Profile 或远程环境。"));
            else checks << observation(QStringLiteral("VS Code 设置"), QStringLiteral("设置包含 JSONC 或无法解析；本版跳过，不猜测有效配置。"), "JSONC_UNSUPPORTED", QStringLiteral("跳过"));
        } else checks << observation(QStringLiteral("VS Code 设置"), QStringLiteral("默认用户设置不可读、不存在或超出大小上限；未验证其他 Profile。"), "UNAVAILABLE", QStringLiteral("跳过"));
    }
    checks << observation(QStringLiteral("应用日志与实际请求"), QStringLiteral("未自动收集日志。可选择单个日志文件提取错误类别计数；不导出原文。登录、对话和应用进程环境尚未验证。"), "APP_UNVERIFIED", QStringLiteral("跳过"));
    return checks;
}

Check summarizeLog(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return observation(QStringLiteral("用户选择的日志"), QStringLiteral("日志不可读。"), "READ_FAILED", QStringLiteral("失败"));
    const bool truncated = file.size() > 1024 * 1024;
    if (truncated) file.seek(file.size() - 1024 * 1024);
    auto text = QString::fromUtf8(file.read(1024 * 1024));
    QStringList findings;
    const QStringList patterns = {"ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT", "ECONNRESET", "CERTIFICATE_VERIFY_FAILED", "SSL", "proxy", "Reconnecting", "stream disconnected", "401", "403", "429", "503"};
    for (const auto &p : patterns) {
        int count = text.count(QRegularExpression("\\b" + QRegularExpression::escape(p) + "\\b", QRegularExpression::CaseInsensitiveOption));
        if (count) findings << p + "=" + QString::number(count);
    }
    return observation(QStringLiteral("用户选择的日志"), QStringLiteral("仅扫描%1，原文、路径、时间与凭据不导出；关键词计数可能误匹配，不证明本批次根因。%2")
        .arg(truncated ? QStringLiteral("末尾 1 MiB") : QStringLiteral("整个文件（≤1 MiB）"), findings.isEmpty() ? QStringLiteral("未命中预设关键词。") : findings.join("；")), "LOG_COUNTS");
}
