#pragma once
#include <QtCore>
#include <QNetworkProxy>

struct Check {
    QString id, layer, route, target, status, code, detail, started;
    qint64 elapsed = 0;
    int timeout = 0;
    QJsonObject json() const;
};
struct Route {
    QString name, reason;
    QNetworkProxy proxy = QNetworkProxy(QNetworkProxy::NoProxy);
    bool supported = true;
};
struct Options {
    QString application = QStringLiteral("Codex 桌面客户端");
    QString host = QStringLiteral("127.0.0.1");
    quint16 port = 7892;
    bool socks = false;
    int timeoutMs = 6000;
    QStringList targets = {QStringLiteral("chatgpt.com"), QStringLiteral("auth.openai.com")};
};
QString clean(QString text);
QString safeEndpoint(const QString &value);
QString proxyDescription(const QNetworkProxy &proxy);
QStringList conclusions(const QJsonArray &checks);
QString httpProbeStatus(int status);
QString markdown(const QJsonObject &report);
QStringList compareReports(const QJsonObject &before, const QJsonObject &after);
QJsonObject newReport(const Options &options);
bool saveJson(const QString &path, const QJsonObject &value, QString *error);
bool loadTargets(const QString &path, QStringList *targets, QString *error);
