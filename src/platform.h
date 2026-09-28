#pragma once
#include "model.h"

struct ProxySettings {
    bool readOk = false, automatic = false;
    QString server, bypass;
    QString summary;
};
ProxySettings systemSettings();
Route systemRoute(const ProxySettings &settings, const QString &host);
QList<Check> environmentChecks(const Options &options, const ProxySettings &settings);
Check summarizeLog(const QString &path);
QString initializeBundledTls();
Check tlsRuntimeCheck();
