#include "mainwindow.h"
#include "platform.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("联网诊断 · ChatGPT / Codex")); resize(1120, 820); setMinimumSize(900, 660);
    auto central = new QWidget; setCentralWidget(central); auto layout = new QVBoxLayout(central); layout->setContentsMargins(24, 20, 24, 18); layout->setSpacing(12);
    auto title = new QLabel(QStringLiteral("ChatGPT / Codex 联网诊断")); title->setObjectName("title"); layout->addWidget(title);
    auto intro = new QLabel(QStringLiteral("一键检查连接路径，用证据定位问题。默认针对 Fastlink 系统代理，端口 7892。")); intro->setWordWrap(true); layout->addWidget(intro);
    auto box = new QGroupBox(QStringLiteral("检测设置")); auto grid = new QGridLayout(box);
    application = new QComboBox; application->addItems({QStringLiteral("Codex 桌面客户端"), QStringLiteral("Codex VS Code 插件"), QStringLiteral("ChatGPT Windows 桌面客户端")});
    protocol = new QComboBox; protocol->addItems({"HTTP", "SOCKS5"});
    host = new QLineEdit("127.0.0.1"); host->setMaxLength(253);
    port = new QSpinBox; port->setRange(1,65535); port->setValue(7892);
    timeout = new QSpinBox; timeout->setRange(2,20); timeout->setValue(6); timeout->setSuffix(QStringLiteral(" 秒 / 项"));
    grid->addWidget(new QLabel(QStringLiteral("使用方式")),0,0); grid->addWidget(application,0,1,1,3);
    grid->addWidget(new QLabel(QStringLiteral("超时")),0,4); grid->addWidget(timeout,0,5);
    grid->addWidget(new QLabel(QStringLiteral("指定代理")),1,0); grid->addWidget(protocol,1,1); grid->addWidget(host,1,2,1,2); grid->addWidget(port,1,4,1,2);
    auto hint = new QLabel(QStringLiteral("对比：直连 / 系统代理 / 指定代理。HTTP 是初始假设，可修改；端口可连接不代表代理服务正常。")); hint->setWordWrap(true); grid->addWidget(hint,2,0,1,6); layout->addWidget(box);
    auto actions = new QHBoxLayout; start = new QPushButton(QStringLiteral("开始一键诊断")); start->setObjectName("primary"); cancel = new QPushButton(QStringLiteral("取消")); cancel->setEnabled(false);
    state = new QLabel(QStringLiteral("准备就绪 · 无需 API Key，不修改网络配置")); state->setWordWrap(true); actions->addWidget(start); actions->addWidget(cancel); actions->addWidget(state,1); layout->addLayout(actions);
    progress = new QProgressBar; progress->setRange(0,1); progress->setValue(0); progress->setTextVisible(false); progress->setFixedHeight(5); layout->addWidget(progress);
    auto tabs = new QTabWidget;
    summary = new QPlainTextEdit; summary->setReadOnly(true); summary->setPlainText(QStringLiteral("点击“开始一键诊断”。\n\n检测目标：chatgpt.com、auth.openai.com。\n检测基础连接，不发送对话、不携带登录凭据。\n\n完成后，这里会显示已确认的问题、证据编号和下一步建议。\n\n检测结果可以导出给其他 AI 分析；工具不会自动上传报告。"));
    tabs->addTab(summary, QStringLiteral("诊断结论"));
    auto details = new QWidget; auto detailsLayout = new QVBoxLayout(details); detailsLayout->setContentsMargins(0,0,0,0);
    auto splitter = new QSplitter(Qt::Vertical);
    table = new QTableWidget(0,7); table->setHorizontalHeaderLabels({QStringLiteral("证据"),QStringLiteral("层级"),QStringLiteral("路径"),QStringLiteral("目标"),QStringLiteral("结果"),QStringLiteral("耗时 ms"),QStringLiteral("代码")});
    table->setSelectionBehavior(QAbstractItemView::SelectRows); table->setSelectionMode(QAbstractItemView::SingleSelection); table->setEditTriggers(QAbstractItemView::NoEditTriggers); table->setAlternatingRowColors(true);
    table->verticalHeader()->hide(); table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents); table->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
    evidence = new QPlainTextEdit; evidence->setReadOnly(true); evidence->setPlaceholderText(QStringLiteral("选择一行查看检测证据与限制"));
    splitter->addWidget(table); splitter->addWidget(evidence); splitter->setSizes({330,140}); detailsLayout->addWidget(splitter); tabs->addTab(details,QStringLiteral("逐项证据")); layout->addWidget(tabs,1);
    auto exports = new QHBoxLayout;
    copy = new QPushButton(QStringLiteral("复制脱敏报告")); exportMd = new QPushButton(QStringLiteral("导出 Markdown")); exportJson = new QPushButton(QStringLiteral("导出 JSON"));
    logImport = new QPushButton(QStringLiteral("分析日志关键词")); baselineSave = new QPushButton(QStringLiteral("保存正常基线")); baselineCompare = new QPushButton(QStringLiteral("对比基线"));
    for (auto button : {copy,exportMd,exportJson,logImport,baselineSave,baselineCompare}) { exports->addWidget(button); button->setEnabled(false); } layout->addLayout(exports);
    auto footer = new QLabel(QStringLiteral("0.1.2 · 蓝色为信息/已响应，灰色为未检查；警告与失败请结合具体路径判断，不代表应用一定不可用。")); footer->setWordWrap(true); footer->setObjectName("footer"); layout->addWidget(footer);
    setStyleSheet("QMainWindow{background:#f3f6fa;} QWidget{font-family:'Microsoft YaHei UI';font-size:13px;color:#213047;} QLabel#title{font-size:25px;font-weight:600;} QLabel#footer{color:#65758b;font-size:12px;} QGroupBox{background:white;border:1px solid #dce3ec;border-radius:8px;margin-top:10px;padding:14px 8px 8px;} QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 6px;} QPushButton{background:white;border:1px solid #ccd6e3;border-radius:5px;padding:8px 12px;} QPushButton:hover{background:#e8f0fd;} QPushButton:disabled{color:#8d99aa;background:#edf0f4;} QPushButton#primary{background:#2463db;color:white;border:none;font-weight:600;} QPushButton#primary:disabled{background:#8fa9d9;} QLineEdit,QComboBox,QSpinBox{background:white;border:1px solid #ccd6e3;border-radius:4px;padding:5px;} QPlainTextEdit,QTableWidget{background:white;border:1px solid #dce3ec;selection-background-color:#dae8fc;selection-color:#17325a;} QHeaderView::section{background:#edf2f8;padding:7px;border:0;} QTabBar::tab{padding:9px 18px;} QProgressBar{border:0;background:#e0e7f0;} QProgressBar::chunk{background:#2463db;}");
    connect(start,&QPushButton::clicked,this,&MainWindow::startDiagnosis);
    connect(cancel,&QPushButton::clicked,this,[this] { if (engine) { engine->requestInterruption(); state->setText(QStringLiteral("正在取消…")); cancel->setEnabled(false); } });
    connect(copy,&QPushButton::clicked,this,[this] { QApplication::clipboard()->setText(markdown(report)); state->setText(QStringLiteral("脱敏报告已复制，可粘贴给其他 AI 分析")); });
    connect(exportMd,&QPushButton::clicked,this,[this] { exportReport(false); }); connect(exportJson,&QPushButton::clicked,this,[this] { exportReport(true); });
    connect(baselineSave,&QPushButton::clicked,this,[this] { exportReport(true,true); }); connect(baselineCompare,&QPushButton::clicked,this,&MainWindow::compareBaseline);
    connect(logImport,&QPushButton::clicked,this,&MainWindow::importLog);
    connect(table,&QTableWidget::itemSelectionChanged,this,[this] {
        int row = table->currentRow(); if (row < 0) return;
        evidence->setPlainText(table->item(row,0)->data(Qt::UserRole).toString());
    });
}

MainWindow::~MainWindow() { if (engine) { engine->requestInterruption(); engine->wait(); } }

void MainWindow::setBusy(bool busy)
{
    start->setEnabled(!busy); cancel->setEnabled(busy);
    application->setEnabled(!busy); host->setEnabled(!busy); port->setEnabled(!busy); protocol->setEnabled(!busy); timeout->setEnabled(!busy);
    for (auto button : {copy,exportMd,exportJson,logImport,baselineSave,baselineCompare}) button->setEnabled(!busy && !report.isEmpty());
    baselineSave->setEnabled(!busy && report["run_status"] == QStringLiteral("已完成"));
    progress->setRange(0,busy ? 0 : 1); progress->setValue(busy ? 0 : 1);
}

void MainWindow::startDiagnosis()
{
    if (engine) return;
    const QString h = host->text().trimmed();
    QHostAddress ip;
    bool valid = ip.setAddress(h) || QRegularExpression("^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$").match(h).hasMatch();
    if (!valid) { QMessageBox::warning(this,QStringLiteral("代理地址无效"),QStringLiteral("请填写主机名或 IP，不要包含协议、路径或账号密码。")); return; }
    Options o; o.application = application->currentText(); o.host = h; o.port = quint16(port->value()); o.socks = protocol->currentIndex() == 1; o.timeoutMs = timeout->value()*1000;
    QString configError;
    if (!loadTargets(QCoreApplication::applicationDirPath() + "/targets.json", &o.targets, &configError)) {
        QMessageBox::warning(this,QStringLiteral("检测目标配置错误"),configError); return;
    }
    report = QJsonObject(); table->setRowCount(0); evidence->clear(); summary->setPlainText(QStringLiteral("正在分层检测，尚未生成最终结论。可以切换到“逐项证据”查看进度。")); setBusy(true);
    engine = new Engine(o,this);
    connect(engine,&Engine::observed,this,&MainWindow::appendCheck);
    connect(engine,&Engine::progress,state,&QLabel::setText);
    connect(engine,&Engine::completed,this,[this](const QJsonObject &r) { report = r; refresh(); });
    connect(engine,&QThread::finished,this,[this] { engine->deleteLater(); engine = nullptr; setBusy(false); emit diagnosisFinished(); if (closing) close(); });
    engine->start();
}

void MainWindow::appendCheck(const QJsonObject &c)
{
    int row = table->rowCount(); table->insertRow(row);
    QStringList values = {c["id"].toString(),c["layer"].toString(),c["route"].toString(),c["target"].toString(),c["status"].toString(),QString::number(c["elapsed_ms"].toInt()),c["code"].toString()};
    for (int i=0;i<values.size();++i) table->setItem(row,i,new QTableWidgetItem(values[i]));
    auto status = c["status"].toString();
    QColor color("#65758b");
    if (status == QStringLiteral("通过")) color = QColor("#18724b");
    else if (status == QStringLiteral("失败")) color = QColor("#ba3434");
    else if (status == QStringLiteral("警告")) color = QColor("#816013");
    else if (status == QStringLiteral("信息") || status == QStringLiteral("已响应")) color = QColor("#2463db");
    table->item(row,4)->setForeground(color);
    table->item(row,0)->setData(Qt::UserRole,QStringLiteral("%1 · %2 / %3\n目标：%4\n开始：%5\n耗时：%6 ms；超时：%7 ms\n代码：%8\n\n%9")
        .arg(c["id"].toString(),c["layer"].toString(),c["route"].toString(),c["target"].toString(),c["started"].toString()).arg(c["elapsed_ms"].toInt()).arg(c["timeout_ms"].toInt()).arg(c["code"].toString(),c["detail"].toString()));
}

void MainWindow::refresh()
{
    QString text = report["run_status"].toString() + QStringLiteral(" · ") + report["application"].toString() + "\n\n";
    auto findings = conclusions(report["checks"].toArray()); report["conclusions"] = QJsonArray::fromStringList(findings);
    for (int i=0;i<findings.size();++i) text += QString::number(i+1) + ". " + findings[i] + "\n\n";
    if (report.contains("baseline_diff")) { text += QStringLiteral("基线对比\n\n"); for (const auto &v : report["baseline_diff"].toArray()) text += v.toString()+"\n\n"; }
    summary->setPlainText(text); state->setText(report["run_status"].toString() + QStringLiteral(" · 可导出脱敏报告"));
}

void MainWindow::exportReport(bool json, bool baseline)
{
    if (baseline && QMessageBox::question(this,QStringLiteral("保存正常基线"),QStringLiteral("请确认此时实际客户端可以正常使用。基础检测有响应并不等于实际应用正常。\n\n是否将本次结果保存为你确认的正常基线？")) != QMessageBox::Yes) return;
    auto path = QFileDialog::getSaveFileName(this,baseline ? QStringLiteral("保存正常基线") : QStringLiteral("导出脱敏报告"),
        (baseline ? "baseline-" : "diagnosis-") + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") + (json ? ".json" : ".md"),json ? "JSON (*.json)" : "Markdown (*.md)");
    if (path.isEmpty()) return;
    QString error; bool ok;
    auto output = report; if (baseline) output["user_confirmed_normal"] = true;
    if (json) ok = saveJson(path,output,&error);
    else { QSaveFile file(path); ok = file.open(QIODevice::WriteOnly); if (ok) { auto bytes = markdown(output).toUtf8(); ok = file.write(bytes) == bytes.size() && file.commit(); } if (!ok) error = file.errorString(); }
    if (!ok) QMessageBox::warning(this,QStringLiteral("保存失败"),error); else state->setText(QStringLiteral("已保存脱敏报告"));
}

void MainWindow::compareBaseline()
{
    auto path = QFileDialog::getOpenFileName(this,QStringLiteral("选择正常基线"),QString(),"JSON (*.json)"); if (path.isEmpty()) return;
    QFile file(path); if (!file.open(QIODevice::ReadOnly) || file.size()>4*1024*1024) { QMessageBox::warning(this,QStringLiteral("无法读取"),QStringLiteral("文件不可读或超过 4 MiB。")); return; }
    QJsonParseError error; auto value = QJsonDocument::fromJson(file.readAll(),&error);
    if (error.error != QJsonParseError::NoError || !value.isObject() || value.object()["schema_version"].toInt() != 1 || !value.object()["checks"].isArray() || !value.object()["user_confirmed_normal"].toBool()) {
        QMessageBox::warning(this,QStringLiteral("基线无效"),QStringLiteral("请选择本工具保存、由用户确认正常的基线 JSON。")); return;
    }
    auto diff = compareReports(value.object(),report); for (auto &line : diff) line = clean(line);
    report["baseline_diff"] = QJsonArray::fromStringList(diff); refresh();
}

void MainWindow::importLog()
{
    auto path = QFileDialog::getOpenFileName(this,QStringLiteral("选择日志，仅提取关键词计数"),QString(),"Logs (*.log *.txt *.jsonl);;All files (*)"); if (path.isEmpty()) return;
    auto c = summarizeLog(path); auto checks = report["checks"].toArray(); c.id = QString("E%1").arg(checks.size()+1,3,10,QChar('0')); checks.append(c.json()); report["checks"] = checks; appendCheck(c.json()); refresh();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (engine) { closing = true; engine->requestInterruption(); state->setText(QStringLiteral("正在停止检测并关闭…")); event->ignore(); }
    else event->accept();
}
