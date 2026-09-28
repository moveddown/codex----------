#pragma once
#include <QtWidgets>
#include "engine.h"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void startDiagnosis();
    QJsonObject currentReport() const { return report; }
signals:
    void diagnosisFinished();
protected:
    void closeEvent(QCloseEvent *event) override;
private:
    Engine *engine = nullptr;
    QComboBox *application, *protocol;
    QLineEdit *host;
    QSpinBox *port, *timeout;
    QPushButton *start, *cancel, *copy, *exportMd, *exportJson, *baselineSave, *baselineCompare, *logImport;
    QLabel *state;
    QProgressBar *progress;
    QTableWidget *table;
    QPlainTextEdit *summary, *evidence;
    QJsonObject report;
    bool closing = false;
    void setBusy(bool busy);
    void appendCheck(const QJsonObject &check);
    void refresh();
    void exportReport(bool json, bool baseline = false);
    void compareBaseline();
    void importLog();
};
