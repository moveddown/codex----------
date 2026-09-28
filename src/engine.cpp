#include "engine.h"
#include "platform.h"
#include <QtNetwork>
#include <functional>

namespace {
Check beginCheck(const QString &layer, const QString &target, const QString &route, int timeout)
{
    Check c; c.layer = layer; c.target = target; c.route = route; c.timeout = timeout;
    c.started = QDateTime::currentDateTime().toString(Qt::ISODateWithMs); return c;
}
// Nested loops live only in the worker thread. Polling gives bounded cancellation latency.
void waitLoop(QEventLoop &loop, QThread *worker, int timeout, bool &timedOut, bool &cancelled)
{
    QTimer limit, cancel;
    limit.setSingleShot(true); cancel.setInterval(40);
    QObject::connect(&limit, &QTimer::timeout, &loop, [&] { timedOut = true; loop.quit(); });
    QObject::connect(&cancel, &QTimer::timeout, &loop, [&] { if (worker->isInterruptionRequested()) { cancelled = true; loop.quit(); } });
    if (worker->isInterruptionRequested()) { cancelled = true; return; }
    limit.start(timeout); cancel.start(); loop.exec();
}
}

Engine::Engine(const Options &o, QObject *parent) : QThread(parent), options(o) {}
Engine::~Engine() { requestInterruption(); wait(); }

void Engine::add(Check c)
{
    c.id = QString("E%1").arg(checks.size() + 1, 3, 10, QChar('0'));
    checks.append(c.json()); emit observed(c.json());
}

void Engine::skipped(const QString &host, const Route &route, const QString &layer, const QString &reason)
{
    auto c = beginCheck(layer, host, route.name, options.timeoutMs);
    c.status = isInterruptionRequested() ? QStringLiteral("取消") : QStringLiteral("跳过");
    c.code = isInterruptionRequested() ? "CANCELLED" : "PRECONDITION"; c.detail = reason; add(c);
}

void Engine::dns(const QString &host)
{
    auto c = beginCheck("DNS", host, QStringLiteral("本地解析"), options.timeoutMs);
    QElapsedTimer elapsed; elapsed.start(); QEventLoop loop;
    bool timedOut = false, cancelled = false, resolved = false;
    QHostInfo info;
    int lookup = QHostInfo::lookupHost(host, &loop, [&](const QHostInfo &value) { info = value; resolved = true; loop.quit(); });
    waitLoop(loop, this, options.timeoutMs, timedOut, cancelled);
    if (!resolved) QHostInfo::abortHostLookup(lookup);
    c.elapsed = elapsed.elapsed();
    c.status = cancelled ? QStringLiteral("取消") : (resolved && info.error() == QHostInfo::NoError && !info.addresses().isEmpty() ? QStringLiteral("通过") : QStringLiteral("失败"));
    c.code = cancelled ? "CANCELLED" : (timedOut ? "DNS_TIMEOUT" : QString::number(info.error()));
    QStringList ips; for (const auto &ip : info.addresses()) ips << ip.toString();
    c.detail = QStringLiteral("本地解析：%1。代理侧 DNS 不可观测，本地解析失败不阻止代理探测。").arg(resolved ? (ips.isEmpty() ? clean(info.errorString()) : ips.join(", ")) : QStringLiteral("未完成")); add(c);
}

bool Engine::tcp(const QString &target, const Route &route)
{
    auto c = beginCheck("TCP", target, route.name, options.timeoutMs);
    const bool direct = route.proxy.type() == QNetworkProxy::NoProxy;
    const QString host = direct ? target : route.proxy.hostName();
    quint16 port = direct ? 443 : route.proxy.port();
    QTcpSocket socket; socket.setProxy(QNetworkProxy::NoProxy);
    QEventLoop loop; QElapsedTimer elapsed; elapsed.start(); bool timedOut = false, cancelled = false;
    connect(&socket, &QTcpSocket::connected, &loop, &QEventLoop::quit);
    connect(&socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::error), &loop, &QEventLoop::quit);
    socket.connectToHost(host, port);
    waitLoop(loop, this, options.timeoutMs, timedOut, cancelled);
    bool ok = !cancelled && !timedOut && socket.state() == QAbstractSocket::ConnectedState;
    c.elapsed = elapsed.elapsed(); c.status = cancelled ? QStringLiteral("取消") : (ok ? QStringLiteral("通过") : QStringLiteral("失败"));
    c.code = cancelled ? "CANCELLED" : (ok ? "TCP_CONNECTED" : (direct ? QString() : QString("PROXY_")) + (timedOut ? QString("TCP_TIMEOUT") : "SOCKET_" + QString::number(socket.error())));
    c.detail = QStringLiteral("实际 TCP 对象 %1:%2；%3。%4").arg(host).arg(port).arg(cancelled ? QStringLiteral("用户取消") : (timedOut ? QStringLiteral("在设定时间内未建立连接") : (ok ? QStringLiteral("连接成功") : clean(socket.errorString()))), direct ? QStringLiteral("应用层直连，未验证 TLS 或 HTTP") : QStringLiteral("仅证明代理端口可连接，不代表代理能访问目标"));
    socket.abort(); add(c); return ok;
}

bool Engine::tls(const QString &host, const Route &route)
{
    auto c = beginCheck("TLS", host, route.name, options.timeoutMs);
    if (!QSslSocket::supportsSsl()) {
        c.status = QStringLiteral("跳过"); c.code = "SSL_UNAVAILABLE"; c.detail = QStringLiteral("Qt TLS 运行库不可用；请使用完整发布目录。"); add(c); return false;
    }
    QSslSocket socket; socket.setProxy(route.proxy); socket.setPeerVerifyMode(QSslSocket::VerifyPeer); socket.setProtocol(QSsl::TlsV1_2OrLater);
    QEventLoop loop; QElapsedTimer elapsed; elapsed.start(); bool timedOut = false, cancelled = false;
    QStringList errors;
    connect(&socket, &QSslSocket::encrypted, &loop, &QEventLoop::quit);
    connect(&socket, QOverload<QAbstractSocket::SocketError>::of(&QSslSocket::error), &loop, &QEventLoop::quit);
    connect(&socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors), &loop, [&](const QList<QSslError> &list) {
        for (const auto &e : list) errors << QString::number(e.error()) + ":" + clean(e.errorString());
        loop.quit();
    });
    socket.connectToHostEncrypted(host, 443);
    waitLoop(loop, this, options.timeoutMs, timedOut, cancelled);
    bool ok = !cancelled && !timedOut && socket.isEncrypted() && errors.isEmpty();
    c.elapsed = elapsed.elapsed(); c.status = cancelled ? QStringLiteral("取消") : (ok ? QStringLiteral("通过") : QStringLiteral("失败"));
    c.code = cancelled ? "CANCELLED" : (timedOut ? "TLS_TIMEOUT" : (ok ? "TLS_VERIFIED" : "TLS_" + QString::number(socket.error())));
    c.detail = proxyDescription(route.proxy) + QStringLiteral("；TLS 1.2+；") + (ok ? QStringLiteral("证书和主机名验证通过；证书 SHA256=") + QString::fromLatin1(socket.peerCertificate().digest(QCryptographicHash::Sha256).toHex()) : (errors.isEmpty() ? clean(socket.errorString()) : errors.join("；")))
        + QStringLiteral("；Qt TLS=") + QSslSocket::sslLibraryVersionString();
    socket.abort(); add(c); return ok;
}

void Engine::http(const QString &host, const Route &route)
{
    auto c = beginCheck("HTTP", host, route.name, options.timeoutMs);
    QNetworkAccessManager manager; manager.setProxy(route.proxy);
    QNetworkRequest request(QUrl("https://" + host + "/"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setRawHeader("User-Agent", "NetworkDoctor/0.1.2 diagnostic-head");
    auto ssl = QSslConfiguration::defaultConfiguration(); ssl.setPeerVerifyMode(QSslSocket::VerifyPeer); ssl.setProtocol(QSsl::TlsV1_2OrLater); request.setSslConfiguration(ssl);
    QElapsedTimer elapsed; elapsed.start(); auto reply = manager.head(request); reply->setReadBufferSize(65536);
    QEventLoop loop; bool timedOut = false, cancelled = false;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    waitLoop(loop, this, options.timeoutMs, timedOut, cancelled);
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    c.elapsed = elapsed.elapsed();
    c.status = cancelled ? QStringLiteral("取消") : (timedOut ? QStringLiteral("失败") : httpProbeStatus(status));
    c.code = cancelled ? "CANCELLED" : (timedOut ? "HTTP_TIMEOUT" : (status ? "HTTP_" + QString::number(status) : "NETWORK_" + QString::number(reply->error())));
    c.detail = QStringLiteral("HEAD https://%1/；路径 %2；HTTP %3；QtNetworkError=%4。%5")
        .arg(host, proxyDescription(route.proxy)).arg(status).arg(reply->error())
        .arg(status ? QStringLiteral("收到响应；QtNetworkError 可能只是 HTTP 状态映射，并不等于连接中断。响应者可能是服务边缘/防护层；不读取正文、Cookie 或认证头。不跟随重定向。HEAD 与实际业务请求可能有不同结果，已响应不等于业务通过。") : clean(reply->errorString()));
    reply->abort(); delete reply; add(c);
}

void Engine::run()
{
    checks = QJsonArray(); report = newReport(options);
    emit progress(QStringLiteral("检查工具自身的 TLS 运行环境"));
    auto runtime = tlsRuntimeCheck(); add(runtime);
    if (runtime.code != "SSL_READY") {
        report["checks"] = checks;
        report["finished"] = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
        report["run_status"] = QStringLiteral("工具自检失败（未执行网络诊断）");
        report["conclusions"] = QJsonArray::fromStringList(conclusions(checks));
        emit completed(report); return;
    }
    auto settings = systemSettings();
    emit progress(QStringLiteral("读取本机网络与代理配置"));
    for (auto c : environmentChecks(options, settings)) { if (isInterruptionRequested()) break; add(c); }
    Route direct; direct.name = QStringLiteral("直连");
    Route manual; manual.name = QStringLiteral("指定代理"); manual.proxy = QNetworkProxy(options.socks ? QNetworkProxy::Socks5Proxy : QNetworkProxy::HttpProxy, options.host, options.port);
    for (const auto &host : options.targets) {
        if (isInterruptionRequested()) break;
        emit progress(QStringLiteral("DNS · ") + host); dns(host);
        QList<Route> routes = {direct, systemRoute(settings, host), manual};
        for (const auto &route : routes) {
            if (isInterruptionRequested()) break;
            auto c = beginCheck(QStringLiteral("路径"), host, route.name, 0);
            c.status = route.supported ? QStringLiteral("通过") : QStringLiteral("跳过");
            c.code = route.supported ? "ROUTE_SELECTED" : "ROUTE_UNSUPPORTED";
            c.detail = (route.supported ? proxyDescription(route.proxy) + "；" : QString()) + route.reason; add(c);
            if (!route.supported) { for (const QString &layer : {"TCP", "TLS", "HTTP"}) skipped(host, route, layer, route.reason); continue; }
            emit progress(route.name + " · TCP · " + host);
            if (!tcp(host, route)) { skipped(host, route, "TLS", QStringLiteral("前置 TCP 检查未通过")); skipped(host, route, "HTTP", QStringLiteral("前置 TCP 检查未通过")); continue; }
            emit progress(route.name + " · TLS · " + host);
            if (!tls(host, route)) { skipped(host, route, "HTTP", QStringLiteral("前置 TLS 检查未通过")); continue; }
            if (isInterruptionRequested()) { skipped(host, route, "HTTP", QStringLiteral("用户取消")); break; }
            emit progress(route.name + " · HTTP · " + host); http(host, route);
        }
    }
    report["checks"] = checks;
    report["finished"] = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    report["run_status"] = isInterruptionRequested() ? QStringLiteral("已取消（部分结果）") : QStringLiteral("已完成");
    report["conclusions"] = QJsonArray::fromStringList(conclusions(checks));
    emit completed(report);
}
