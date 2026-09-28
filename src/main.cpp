#include "mainwindow.h"
#include "platform.h"

int main(int argc, char *argv[])
{
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication app(argc,argv); app.setApplicationName("NetworkDoctor"); app.setApplicationVersion("0.1.2");
    QCommandLineParser parser; parser.addHelpOption(); parser.addVersionOption();
    parser.addOption({"diagnose", "Run diagnostics and export JSON, then exit."});
    parser.addOption({"output", "JSON output path for --diagnose", "path"});
    parser.addOption({"self-check", "Check bundled TLS without network; requires --output."});
    parser.addOption({"smoke", "Render the window to the given PNG and exit (no network).", "png"});
    parser.process(app);
    initializeBundledTls();
    if (parser.isSet("self-check")) {
        if (!parser.isSet("output")) return 2;
        auto check = tlsRuntimeCheck(); QString error;
        if (!saveJson(parser.value("output"),check.json(),&error)) return 3;
        return check.code == "SSL_READY" ? 0 : 5;
    }
    MainWindow window;
    if (parser.isSet("diagnose")) {
        if (!parser.isSet("output")) return 2;
        QObject::connect(&window,&MainWindow::diagnosisFinished,&app,[&] {
            QString error; const bool ok = saveJson(parser.value("output"),window.currentReport(),&error); app.exit(ok ? 0 : 3);
        });
        QTimer::singleShot(0,&window,&MainWindow::startDiagnosis);
    } else {
        window.show();
        if (parser.isSet("smoke")) QTimer::singleShot(600,&app,[&] { const bool ok = window.grab().save(parser.value("smoke")); app.exit(ok ? 0 : 4); });
    }
    return app.exec();
}
