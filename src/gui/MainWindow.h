#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QProgressBar>
#include <QTextEdit>
#include <QTabWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include "core/CryptoEngine.h"

namespace SecureCrypt::Gui {

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void onEncryptClicked();
    void onDecryptClicked();
    void onBrowseClicked();
    void togglePasswordVisibility();

private:
    void setupUi();
    void setupStyles();
    void log(const QString &message, bool isError = false);

    // Core components
    QTabWidget *tabWidget;
    QWidget *encryptTab;
    QWidget *decryptTab;

    // UI Elements
    QLineEdit *fileInput;
    QLineEdit *passwordInput;
    QPushButton *visibilityToggle;
    QProgressBar *progressBar;
    QTextEdit *logArea;

    // State
    QString selectedFilePath;
    SecureCrypt::Core::CryptoEngine cryptoEngine;
};

} // namespace SecureCrypt::Gui
