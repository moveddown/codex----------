#include "model.h"

QString clean(QString text)
{
    text.replace(QRegularExpression(QStringLiteral("(?i)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password)\\s*[:=]\\s*[^\\r\\n]+")), QStringLiteral("\\1=[已隐藏]"));
    text.replace(QRegularExpression(QStringLiteral("(?i)\\b(?:sk-[A-Za-z0-9_-]+|Bearer\\s+[^\\s]+)")), QStringLiteral("[凭据已隐藏]"));
    text.replace(QRegularExpression(QStringLiteral("(?i)(https?|socks5h?)://[^\\s/@]+(?::[^\\s/@]*)?@")), QStringLiteral("\\1://[凭据已隐藏]@"));
    text.replace(QRegularExpression(QStringLiteral("(?i)(https?://[^\\s?#]+)[?#][^\\s]*")), QStringLiteral("\\1?[参数已隐藏]"));
    text.replace(QRegularExpression(QStringLiteral("(?i)[A-Z]:[\\\\/]Users[\\\\/][^\\\\/\\s]+")), QStringLiteral("[用户目录]"));
    text.replace(QRegularExpression(QStringLiteral("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")), QStringLiteral("[邮箱已隐藏]"));
    text.replace(QRegularExpression(QStringLiteral("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]")), QString());
    return text.left(4096);
}

QString safeEndpoint(const QString &value)
{
    if (value.trimmed().isEmpty()) return QStringLiteral("未设置");
    QUrl url(value.contains("://") ? value.trimmed() : "http://" + value.trimmed());
    if (!url.isValid() || url.host().isEmpty()) return QStringLiteral("已设置，但格式无法识别（原值不导出）");
    return clean(url.scheme() + "://" + url.host() + (url.port() > 0 ? ":" + QString::number(url.port()) : "")
        + (!url.userInfo().isEmpty() ? QStringLiteral(" [含凭据，已隐藏]") : QString()));
}

QString proxyDescription(const QNetworkProxy &p)
{
    if (p.type() == QNetworkProxy::NoProxy) return QStringLiteral("应用层直连（可能仍经过 VPN/TUN）");
    return (p.type() == QNetworkProxy::Socks5Proxy ? "SOCKS5 " : "HTTP ") + clean(p.hostName()) + ":" + QString::number(p.port());
}

QJsonObject Check::json() const
{
    return {{"id", id}, {"layer", layer}, {"route", route}, {"target", clean(target)}, {"status", status},
            {"code", code}, {"detail", clean(detail)}, {"started", started}, {"elapsed_ms", double(elapsed)}, {"timeout_ms", timeout}};
}

QString httpProbeStatus(int status)
{
    if (status >= 200 && status < 300) return QStringLiteral("通过");
    if ((status >= 300 && status < 400) || status == 401 || status == 403 || status == 405)
        return QStringLiteral("已响应");
    return status > 0 ? QStringLiteral("警告") : QStringLiteral("失败");
}

QStringList conclusions(const QJsonArray &checks)
{
    QStringList result;
    QStringList runtimeFailures;
    for (const auto &value : checks) {
        auto c = value.toObject();
        if (c["code"] == "SSL_UNAVAILABLE") runtimeFailures << c["id"].toString();
    }
    if (!runtimeFailures.isEmpty()) {
        return {QStringLiteral("[%1] 工具自检失败：TLS 运行环境未就绪，HTTPS 检查无法执行。这是检测软件自身的问题，不是 Codex / ChatGPT 网络故障的证据。").arg(runtimeFailures.join(", ")),
                QStringLiteral("请运行完整发布文件夹内的 NetworkDoctor.exe，不要单独复制 EXE。若仍失败，请在“逐项证据”查看 TLS 自检的 DLL 加载结果，并导出报告。无需据此修改 Fastlink 或系统网络。"),
                QStringLiteral("本次无法判断目标应用网络状态；实际 Codex 可以使用与这个自检失败结果并不矛盾。")};
    }
    QMap<QString, QStringList> directFailed, proxyResponded, responsesByRoute, httpNotes;
    QSet<QString> responseTargets;
    bool response = false;
    for (const auto &value : checks) {
        auto c = value.toObject();
        QString id = c["id"].toString(), layer = c["layer"].toString(), code = c["code"].toString();
        QString route = c["route"].toString(), state = c["status"].toString(), target = c["target"].toString();
        if (layer == "TCP" && state == QStringLiteral("失败") && code.startsWith("PROXY_"))
            result << QStringLiteral("[%1] 已确认：本次无法连接 %2 的代理端点。检查 Fastlink 是否运行、监听地址与端口是否一致；这不直接证明远端服务故障。").arg(id, route);
        if (layer == "TLS" && state == QStringLiteral("失败"))
            result << QStringLiteral("[%1] 已确认：%2 TLS 验证/握手失败。检查证书、系统时间及代理链路；不要关闭证书验证。").arg(id, route);
        if (layer == "DNS" && state == QStringLiteral("失败"))
            result << QStringLiteral("[%1] 本地 DNS 解析未成功。先查看代理路径是否有响应；若代理可用，不能据此认定整个网络断开。若所有路径失败，再检查 DNS 配置与基础网络。").arg(id);
        if (code == "ENV_PROXY_DIFFERENT")
            result << QStringLiteral("[%1] 诊断进程继承的代理变量与指定代理不同。请核对目标应用启动环境；这里的差异不证明目标应用正在使用该变量。").arg(id);
        if (route == QStringLiteral("直连") && state == QStringLiteral("失败")) directFailed[target] << id;
        if (layer == "HTTP" && code.startsWith("HTTP_")) {
            bool validCode = false;
            int status = code.mid(5).toInt(&validCode);
            if (!validCode) continue;
            if (status != 407) {
                response = true;
                responseTargets.insert(target);
                responsesByRoute[route] << id;
                if (route != QStringLiteral("直连")) proxyResponded[target] << id;
            }
            if (status >= 300) httpNotes[QString::number(status)] << id;
        }
        if (code == "PROXY_DIFFERENT") result << QStringLiteral("[%1] 系统代理与指定代理不同。请确认 Fastlink 实际监听端口，并对照两条路径的结果；差异本身不证明配置错误。").arg(id);
    }
    for (auto it = proxyResponded.begin(); it != proxyResponded.end(); ++it) if (directFailed.contains(it.key()))
        result << QStringLiteral("[%1 / %2] 路径对比：同一目标 %3 的直连未通过，代理路径已收到响应。若应用使用代理，直连失败不等于应用断网；不要仅因这项对比修改配置或重启正常工作的应用。").arg(directFailed[it.key()].join(","), it.value().join(","), it.key());
    for (auto it = httpNotes.begin(); it != httpNotes.end(); ++it) {
        int status = it.key().toInt();
        if (httpProbeStatus(status) == QStringLiteral("已响应"))
            result << QStringLiteral("[%1] 探测说明：%2 次 HTTP %3 响应已合并。这是无登录凭据的 HEAD 探测结果，不是单纯断网，也不能据此判断插件异常。响应来源及拒绝/重定向的具体原因未确定；保留原始代码供排查。若实际应用可用，无需仅因此处理。").arg(it.value().join(",")).arg(it.value().size()).arg(status);
        else if (status == 407)
            result << QStringLiteral("[%1] HTTP 407：代理要求认证，尚不能据此确认目标可达。请核对所选代理的认证要求。").arg(it.value().join(","));
        else
            result << QStringLiteral("[%1] HTTP %2：探测获得异常响应，仍需关注。仅凭本次 HEAD 不能证明实际应用故障；若应用也不可用，请结合应用错误与发生时间复测。").arg(it.value().join(",")).arg(status);
    }
    if (response) {
        QStringList paths;
        for (auto it = responsesByRoute.begin(); it != responsesByRoute.end(); ++it) paths << it.key() + " [" + it.value().join(",") + "]";
        result.prepend(QStringLiteral("基础连接已有响应：%1 个目标通过以下路径收到 HTTPS/HTTP 响应：%2。这说明这些探测路径有响应，不代表所有路径或实际业务都正常。").arg(responseTargets.size()).arg(paths.join(QStringLiteral("；"))));
        result << QStringLiteral("实际应用状态：本工具尚未验证登录、对话及流式连接。若插件实际可用，可保持当前配置并保存正常基线；仅在实际出现故障时结合这些证据排查。");
    }
    else result << QStringLiteral("本次尚未获得目标 HTTP 响应。请查看首个失败或跳过的检查；现有证据不足以判断账号或服务是否可用。");
    result << QStringLiteral("本工具进程的环境不等于 Codex、VS Code 或 ChatGPT 进程的环境；未读取目标进程环境，也未验证 WSL。");
    return result;
}

QJsonObject newReport(const Options &o)
{
    return {{"schema_version", 1}, {"software_version", "0.1.2"}, {"batch_id", QUuid::createUuid().toString(QUuid::WithoutBraces)},
            {"started", QDateTime::currentDateTime().toString(Qt::ISODateWithMs)},
            {"timezone", QString::fromUtf8(QTimeZone::systemTimeZoneId())}, {"application", o.application},
            {"system", QSysInfo::prettyProductName() + " / " + QSysInfo::currentCpuArchitecture()},
            {"qt_version", qVersion()}, {"timeout_ms", o.timeoutMs}, {"checks", QJsonArray()},
            {"targets", QJsonArray::fromStringList(o.targets)}, {"run_status", QStringLiteral("检测中")},
            {"scope", QStringLiteral("无凭据的 DNS/TCP/TLS/HTTPS HEAD 探测；不跟随重定向、不读取响应正文；不验证账号、登录、对话、WebSocket。代理端解析不可观测；不修改系统配置。")}};
}

QString markdown(const QJsonObject &r)
{
    QString out = QStringLiteral("# 网络诊断报告\n\n");
    for (const QString &key : {"schema_version", "software_version", "batch_id", "started", "finished", "timezone", "application", "system", "qt_version", "run_status", "scope"})
        out += "- " + key + ": " + r[key].toVariant().toString() + "\n";
    out += QStringLiteral("\n## 结论与下一步\n\n");
    for (const auto &s : conclusions(r["checks"].toArray())) out += "- " + s + "\n";
    out += QStringLiteral("\n## 检测证据\n\n");
    for (const auto &v : r["checks"].toArray()) {
        auto c = v.toObject();
        out += QStringLiteral("### %1 · %2 / %3 / %4\n\n").arg(c["id"].toString(), c["layer"].toString(), c["route"].toString(), c["status"].toString());
        out += QStringLiteral("- 目标：%1\n- 开始：%2\n- 耗时：%3 ms；超时：%4 ms\n- 观测代码（不一定代表故障）：%5\n\n%6\n\n")
            .arg(c["target"].toString(), c["started"].toString()).arg(c["elapsed_ms"].toInt()).arg(c["timeout_ms"].toInt()).arg(c["code"].toString(), c["detail"].toString());
    }
    if (r.contains("baseline_diff")) {
        out += QStringLiteral("## 基线对比\n\n");
        for (const auto &v : r["baseline_diff"].toArray()) out += "- " + v.toString() + "\n";
    }
    out += QStringLiteral("## 提交给其他 AI 的说明\n\n请根据证据标识分析，区分事实、可能原因与未验证事项。优先给出少量可执行的复测步骤，说明还缺哪些信息。不要仅凭超时或 403 推断封号、防火墙拦截或服务故障。报告不包含认证凭据或原始日志，未自动上传。\n");
    return out;
}

QStringList compareReports(const QJsonObject &before, const QJsonObject &after)
{
    QStringList diff;
    if (before["application"] != after["application"] || before["targets"] != after["targets"] || before["timeout_ms"] != after["timeout_ms"])
        return {QStringLiteral("检测对象、目标或超时配置不同，不能直接对比。请选择相同配置的基线。")};
    QMap<QString, QJsonObject> old;
    auto key = [](const QJsonObject &c) { return c["layer"].toString()+"|"+c["route"].toString()+"|"+c["target"].toString(); };
    for (const auto &v : before["checks"].toArray()) old.insert(key(v.toObject()), v.toObject());
    for (const auto &v : after["checks"].toArray()) {
        auto c = v.toObject(); auto k = key(c);
        if (!old.contains(k)) { diff << k + QStringLiteral("：新增检查或目标变化"); continue; }
        auto prev = old.take(k);
        if (prev["status"] != c["status"] || prev["code"] != c["code"] || prev["detail"] != c["detail"])
            diff << k + QStringLiteral("：%1 → %2；之前：%3；现在：%4").arg(prev["status"].toString(), c["status"].toString(), prev["detail"].toString(), c["detail"].toString());
        if (qAbs(prev["elapsed_ms"].toInt() - c["elapsed_ms"].toInt()) > 1000)
            diff << k + QStringLiteral("：耗时 %1 → %2 ms").arg(prev["elapsed_ms"].toInt()).arg(c["elapsed_ms"].toInt());
    }
    for (auto it = old.begin(); it != old.end(); ++it) diff << it.key() + QStringLiteral("：本次未执行");
    if (diff.isEmpty()) diff << QStringLiteral("未发现检查状态、配置或超过 1 秒的耗时变化。");
    diff << QStringLiteral("差异是排查线索，不直接证明故障原因。");
    return diff;
}

bool saveJson(const QString &path, const QJsonObject &value, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) { *error = file.errorString(); return false; }
    auto bytes = QJsonDocument(value).toJson(QJsonDocument::Indented);
    if (file.write(bytes) != bytes.size() || !file.commit()) { *error = file.errorString(); return false; }
    return true;
}

bool loadTargets(const QString &path, QStringList *targets, QString *error)
{
    if (!QFileInfo::exists(path)) return true; // Built-in defaults are used in a development build.
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 16384) { *error = QStringLiteral("目标配置不可读或超过 16 KiB。"); return false; }
    QJsonParseError parse; auto doc = QJsonDocument::fromJson(file.readAll(), &parse);
    auto list = doc.object()["targets"].toArray();
    if (parse.error != QJsonParseError::NoError || doc.object()["schema_version"].toInt() != 1 || list.isEmpty() || list.size() > 8) {
        *error = QStringLiteral("targets.json 格式错误，须包含 1 至 8 个主机名。"); return false;
    }
    QStringList result;
    QRegularExpression domain("^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$");
    for (const auto &v : list) {
        if (!v.isString() || !domain.match(v.toString()).hasMatch()) { *error = QStringLiteral("检测目标必须是纯域名，不能包含 URL、账号、路径或查询参数。"); return false; }
        if (!result.contains(v.toString().toLower())) result << v.toString().toLower();
    }
    *targets = result; return true;
}
