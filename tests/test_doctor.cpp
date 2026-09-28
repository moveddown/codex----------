#include <QtTest>
#include <QtNetwork>
#include "model.h"
#include "platform.h"
#include "engine.h"

class DoctorTests : public QObject {
    Q_OBJECT
private slots:
    void redaction();
    void proxyPaths();
    void classification();
    void reportAndBaseline();
    void targetValidation();
    void logPrivacy();
    void timeoutAndCancel();
    void runtimeFailure();
    void healthyProxyWithRejectedProbe();
};

void DoctorTests::redaction()
{
    QString text = clean("Authorization: Bearer secret-alpha\nCookie: session=secret-beta\nhttps://alice:secret-gamma@localhost:7892/path?token=secret-delta\nC:\\Users\\PrivateName\\file\nsk-secret-epsilon\nperson@example.com");
    for (const QString &secret : {"secret-alpha","secret-beta","secret-gamma","secret-delta","PrivateName","secret-epsilon","person@example.com"}) QVERIFY2(!text.contains(secret),qPrintable(text));
    QCOMPARE(safeEndpoint("http://user:password@127.0.0.1:7892/path?key=abcdef"),QStringLiteral("http://127.0.0.1:7892 [含凭据，已隐藏]"));
    QVERIFY(!safeEndpoint("not a proxy secret").contains("secret"));
}

void DoctorTests::runtimeFailure()
{
    Check c; c.id="E001"; c.code="SSL_UNAVAILABLE"; c.layer="TLS"; c.status=QStringLiteral("失败");
    auto result=conclusions({c.json(),c.json(),c.json()}).join('\n');
    QCOMPARE(result.count(QStringLiteral("工具自检失败")),1);
    QVERIFY(!result.contains(QStringLiteral("本次尚未获得目标 HTTP 响应")));
    QCoreApplication::instance()->setProperty("bundledTlsOk",false);
    Engine engine{Options()}; QSignalSpy done(&engine,&Engine::completed);
    engine.start(); QVERIFY(done.wait(3000)); QVERIFY(engine.wait(1000));
    auto r=qvariant_cast<QJsonObject>(done.at(0).at(0));
    QCOMPARE(r["checks"].toArray().size(),1);
    QVERIFY(r["run_status"].toString().contains(QStringLiteral("未执行网络诊断")));
    QCoreApplication::instance()->setProperty("bundledTlsOk",QVariant());
}

void DoctorTests::proxyPaths()
{
    ProxySettings s; s.readOk = true; s.server = "http=127.0.0.1:8000;https=127.0.0.1:7892";
    auto r = systemRoute(s,"chatgpt.com"); QVERIFY(r.supported); QCOMPARE(r.proxy.port(),quint16(7892));
    s.bypass = "*.example.com;<local>"; QCOMPARE(systemRoute(s,"x.example.com").proxy.type(),QNetworkProxy::NoProxy);
    s.automatic = true; QVERIFY(!systemRoute(s,"chatgpt.com").supported);
    s.automatic = false; s.server = "http=127.0.0.1:8000"; QCOMPARE(systemRoute(s,"chatgpt.com").proxy.type(),QNetworkProxy::NoProxy);
    s.server = "127.0.0.1:99999"; QVERIFY(!systemRoute(s,"chatgpt.com").supported);
    s.server = "http://user:secret@127.0.0.1:7892"; QVERIFY(!systemRoute(s,"chatgpt.com").supported);
}

void DoctorTests::classification()
{
    Check c; c.id="E001"; c.layer="HTTP"; c.route=QStringLiteral("指定代理"); c.target="chatgpt.com"; c.status=QStringLiteral("警告"); c.code="HTTP_403";
    auto result = conclusions({c.json()}).join('\n'); QVERIFY(result.contains(QStringLiteral("不是单纯断网"))); QVERIFY(result.contains(QStringLiteral("尚未验证")));
    c.layer="TCP"; c.route=QStringLiteral("系统代理"); c.status=QStringLiteral("失败"); c.code="SOCKET_0";
    QVERIFY(!conclusions({c.json()}).join('\n').contains(QStringLiteral("无法连接 系统代理 的代理端点")));
    c.code="PROXY_SOCKET_0"; QVERIFY(conclusions({c.json()}).join('\n').contains(QStringLiteral("代理端点")));
    c.route=QStringLiteral("直连"); c.code="TCP_TIMEOUT";
    Check response=c; response.id="E002"; response.route=QStringLiteral("指定代理"); response.layer="HTTP"; response.code="HTTP_401"; response.status=QStringLiteral("警告");
    QVERIFY(conclusions({c.json(),response.json()}).join('\n').contains(QStringLiteral("同一目标")));
}

void DoctorTests::healthyProxyWithRejectedProbe()
{
    QJsonArray evidence;
    Check c; c.layer="TCP"; c.route=QStringLiteral("直连"); c.target="chatgpt.com"; c.id="E014"; c.status=QStringLiteral("失败"); c.code="TCP_TIMEOUT"; evidence.append(c.json());
    for (int i=0;i<5;++i) {
        c.layer="HTTP"; c.id=QString("H%1").arg(i); c.route=i%2 ? QStringLiteral("系统代理") : QStringLiteral("指定代理");
        c.target=i<2 ? "chatgpt.com" : "auth.openai.com"; c.code="HTTP_403"; c.status=httpProbeStatus(403); evidence.append(c.json());
    }
    auto result=conclusions(evidence).join('\n');
    QVERIFY(result.startsWith(QStringLiteral("基础连接已有响应")));
    QCOMPARE(result.count("HTTP 403"),1);
    QVERIFY(result.contains(QStringLiteral("5 次")));
    QVERIFY(result.contains(QStringLiteral("直连失败不等于应用断网")));
    QVERIFY(!result.contains(QStringLiteral("重启应用复测")));
    QCOMPARE(httpProbeStatus(401),QStringLiteral("已响应"));
    QCOMPARE(httpProbeStatus(403),QStringLiteral("已响应"));
    QCOMPARE(httpProbeStatus(405),QStringLiteral("已响应"));
    QCOMPARE(httpProbeStatus(302),QStringLiteral("已响应"));
    for (int status : {407,429,500,503}) QCOMPARE(httpProbeStatus(status),QStringLiteral("警告"));
    QCOMPARE(httpProbeStatus(0),QStringLiteral("失败"));
    c.id="F1"; c.layer="TLS"; c.status=QStringLiteral("失败"); c.code="TLS_13"; evidence.append(c.json());
    QVERIFY(conclusions(evidence).join('\n').contains(QStringLiteral("TLS 验证/握手失败")));
    c.layer="HTTP"; c.code="HTTP_503"; c.status=httpProbeStatus(503);
    QVERIFY(conclusions({c.json()}).join('\n').contains(QStringLiteral("仍需关注")));
    c.code="HTTP_407";
    QVERIFY(!conclusions({c.json()}).join('\n').contains(QStringLiteral("基础连接已有响应")));
}

void DoctorTests::reportAndBaseline()
{
    Options o; auto report=newReport(o); Check c; c.id="E001"; c.layer="DNS"; c.target="chatgpt.com"; c.status=QStringLiteral("通过"); c.detail="1.2.3.4"; report["checks"]=QJsonArray{c.json()};
    QTemporaryDir dir; QString error; QVERIFY(saveJson(dir.filePath("report.json"),report,&error)); QFile file(dir.filePath("report.json")); QVERIFY(file.open(QIODevice::ReadOnly)); auto parsed=QJsonDocument::fromJson(file.readAll()).object();
    QCOMPARE(parsed,report); QVERIFY(markdown(report).contains("E001")); QVERIFY(markdown(report).contains("1.2.3.4"));
    auto changed=report; c.status=QStringLiteral("失败"); c.elapsed=2200; changed["checks"]=QJsonArray{c.json()};
    auto diff=compareReports(report,changed).join('\n'); QVERIFY(diff.contains(QStringLiteral("通过 → 失败"))); QVERIFY(diff.contains("2200"));
    changed["application"]="Other"; QVERIFY(compareReports(report,changed).join('\n').contains(QStringLiteral("不能直接对比")));
}

void DoctorTests::targetValidation()
{
    QTemporaryDir dir; QString error; QStringList targets={"chatgpt.com"};
    QJsonObject bad{{"schema_version",1},{"targets",QJsonArray{"https://user:secret@example.com/?token=secret"}}};
    QVERIFY(saveJson(dir.filePath("targets.json"),bad,&error)); QVERIFY(!loadTargets(dir.filePath("targets.json"),&targets,&error));
    bad["targets"]=QJsonArray{"chatgpt.com","auth.openai.com"}; QVERIFY(saveJson(dir.filePath("targets.json"),bad,&error)); QVERIFY(loadTargets(dir.filePath("targets.json"),&targets,&error)); QCOMPARE(targets.size(),2);
}

void DoctorTests::logPrivacy()
{
    QTemporaryDir dir; QFile file(dir.filePath("private.log")); QVERIFY(file.open(QIODevice::WriteOnly)); file.write("Authorization: secret-abcdef\nECONNREFUSED 403\nCookie: secret-qwerty\n"); file.close();
    auto c=summarizeLog(file.fileName()); auto bytes=QJsonDocument(c.json()).toJson(); QVERIFY(!bytes.contains("secret-")); QVERIFY(!bytes.contains("private.log")); QVERIFY(bytes.contains("ECONNREFUSED=1"));
}

void DoctorTests::timeoutAndCancel()
{
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost,0));
    QList<QTcpSocket*> sockets;
    connect(&server,&QTcpServer::newConnection,this,[&] {
        while (server.hasPendingConnections()) { auto socket=server.nextPendingConnection(); sockets << socket;
            connect(socket,&QTcpSocket::readyRead,socket,[socket] { auto bytes=socket->readAll(); if (bytes.startsWith("CONNECT")) socket->write("HTTP/1.1 200 Connection established\r\n\r\n"); });
        }
    });
    Options o; o.targets=QStringList{"127.0.0.1"}; o.port=server.serverPort(); o.timeoutMs=180;
    Engine engine(o); QSignalSpy done(&engine,&Engine::completed); engine.start(); QVERIFY(done.wait(10000)); QVERIFY(engine.wait(2000));
    auto report=qvariant_cast<QJsonObject>(done.at(0).at(0)); bool tlsTimeout=false;
    for (const auto &v : report["checks"].toArray()) { auto c=v.toObject(); if (c["route"]==QStringLiteral("指定代理") && c["code"]=="TLS_TIMEOUT") tlsTimeout=true; }
    QVERIFY2(tlsTimeout,qPrintable(markdown(report)));
    for (int round=0;round<2;++round) {
        Engine cancelled(o); QSignalSpy finished(&cancelled,&Engine::completed); cancelled.start();
        QTimer::singleShot(30,&cancelled,[&] { cancelled.requestInterruption(); });
        QVERIFY(finished.wait(5000)); QVERIFY(cancelled.wait(2000));
        auto r=qvariant_cast<QJsonObject>(finished.at(0).at(0)); QVERIFY(r["run_status"].toString().contains(QStringLiteral("已取消")));
    }
    for (auto socket:sockets) delete socket;
}

QTEST_GUILESS_MAIN(DoctorTests)
#include "test_doctor.moc"
