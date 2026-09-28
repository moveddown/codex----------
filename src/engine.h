#pragma once
#include "model.h"
#include <QThread>

class Engine : public QThread {
    Q_OBJECT
public:
    explicit Engine(const Options &options, QObject *parent = nullptr);
    ~Engine() override;
signals:
    void observed(QJsonObject check);
    void progress(QString text);
    void completed(QJsonObject report);
protected:
    void run() override;
private:
    Options options;
    QJsonObject report;
    QJsonArray checks;
    void add(Check check);
    bool tcp(const QString &target, const Route &route);
    bool tls(const QString &host, const Route &route);
    void http(const QString &host, const Route &route);
    void dns(const QString &host);
    void skipped(const QString &host, const Route &route, const QString &layer, const QString &reason);
};
