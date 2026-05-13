#include "MainWindow.h"
#include "file/FileManager.h"
#include "utils/CompressionManager.h"
#include <QApplication>
#include <QStyle>
#include <QScreen>
#include <QDateTime>
#include <QUrl>
#include <QDir>

namespace SecureCrypt::Gui {

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUi();
    setupStyles();
    setAcceptDrops(true);
    
    setWindowTitle("SecureCrypt - Professional File Encryption");
    resize(800, 600);
}

MainWindow::~MainWindow() {}

void MainWindow::setupUi() {
    auto *centralWidget = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Header
    auto *headerLabel = new QLabel("SecureCrypt", this);
    headerLabel->setObjectName("headerLabel");
    mainLayout->addWidget(headerLabel);

    // File Selection Area
    auto *fileLayout = new QHBoxLayout();
    fileInput = new QLineEdit(this);
    fileInput->setPlaceholderText("Select a file or drag and drop here...");
    fileInput->setReadOnly(true);
    
    auto *browseBtn = new QPushButton("Browse", this);
    connect(browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseClicked);
    
    fileLayout->addWidget(fileInput);
    fileLayout->addWidget(browseBtn);
    mainLayout->addLayout(fileLayout);

    // Password Area
    auto *passLayout = new QHBoxLayout();
    passwordInput = new QLineEdit(this);
    passwordInput->setPlaceholderText("Enter secure password...");
    passwordInput->setEchoMode(QLineEdit::Password);
    
    visibilityToggle = new QPushButton(this);
    visibilityToggle->setFixedWidth(40);
    visibilityToggle->setText("👁");
    connect(visibilityToggle, &QPushButton::clicked, this, &MainWindow::togglePasswordVisibility);
    
    passLayout->addWidget(passwordInput);
    passLayout->addWidget(visibilityToggle);
    mainLayout->addLayout(passLayout);

    // Actions
    auto *actionLayout = new QHBoxLayout();
    auto *encryptBtn = new QPushButton("Encrypt File", this);
    encryptBtn->setObjectName("encryptBtn");
    connect(encryptBtn, &QPushButton::clicked, this, &MainWindow::onEncryptClicked);
    
    auto *decryptBtn = new QPushButton("Decrypt File", this);
    decryptBtn->setObjectName("decryptBtn");
    connect(decryptBtn, &QPushButton::clicked, this, &MainWindow::onDecryptClicked);
    
    actionLayout->addWidget(encryptBtn);
    actionLayout->addWidget(decryptBtn);
    mainLayout->addLayout(actionLayout);

    // Progress
    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
    mainLayout->addWidget(progressBar);

    // Logs
    logArea = new QTextEdit(this);
    logArea->setReadOnly(true);
    logArea->setPlaceholderText("System logs will appear here...");
    mainLayout->addWidget(logArea);

    setCentralWidget(centralWidget);
}

void MainWindow::setupStyles() {
    this->setStyleSheet(R"(
        QMainWindow {
            background-color: #121212;
        }
        #headerLabel {
            font-size: 32px;
            font-weight: bold;
            color: #BB86FC;
            margin-bottom: 10px;
        }
        QLineEdit {
            background-color: #1E1E1E;
            color: #FFFFFF;
            border: 1px solid #333333;
            border-radius: 5px;
            padding: 10px;
            font-size: 14px;
        }
        QLineEdit:focus {
            border: 1px solid #BB86FC;
        }
        QPushButton {
            background-color: #333333;
            color: #FFFFFF;
            border-radius: 5px;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #444444;
        }
        #encryptBtn {
            background-color: #03DAC6;
            color: #000000;
        }
        #encryptBtn:hover {
            background-color: #04f0d9;
        }
        #decryptBtn {
            background-color: #BB86FC;
            color: #000000;
        }
        #decryptBtn:hover {
            background-color: #d7b7fd;
        }
        QProgressBar {
            border: 1px solid #333333;
            border-radius: 5px;
            text-align: center;
            color: white;
            background-color: #1E1E1E;
        }
        QProgressBar::chunk {
            background-color: #BB86FC;
            width: 10px;
        }
        QTextEdit {
            background-color: #1E1E1E;
            color: #E0E0E0;
            border: 1px solid #333333;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
    )");
}

void MainWindow::onBrowseClicked() {
    QString path = QFileDialog::getOpenFileName(this, "Select File to Process", QDir::currentPath());
    if (!path.isEmpty()) {
        selectedFilePath = path;
        fileInput->setText(path);
        log("File selected: " + path);
    }
}

void MainWindow::togglePasswordVisibility() {
    if (passwordInput->echoMode() == QLineEdit::Password) {
        passwordInput->setEchoMode(QLineEdit::Normal);
        visibilityToggle->setText("🔒");
    } else {
        passwordInput->setEchoMode(QLineEdit::Password);
        visibilityToggle->setText("👁");
    }
}

void MainWindow::onEncryptClicked() {
    if (selectedFilePath.isEmpty() || passwordInput->text().isEmpty()) {
        log("Error: Please select a file and enter a password.", true);
        return;
    }

    progressBar->setValue(10);
    log("Starting encryption...");

    std::string path = selectedFilePath.toStdString();
    std::string pass = passwordInput->text().toStdString();

    auto plaintext = SecureCrypt::File::FileManager::readFile(path);
    progressBar->setValue(30);

    // Optional Compression (Advanced feature integration)
    std::vector<unsigned char> compressed;
    if (SecureCrypt::Utils::CompressionManager::compress(plaintext, compressed)) {
        log("Compression successful.");
        plaintext = compressed;
    }
    progressBar->setValue(50);

    auto salt = SecureCrypt::Core::CryptoEngine::generateRandomBytes(16);
    std::vector<unsigned char> key, iv;
    SecureCrypt::Core::CryptoEngine::deriveKey(pass, salt, key, iv);

    std::vector<unsigned char> ciphertext;
    if (cryptoEngine.encrypt(plaintext, key, iv, ciphertext)) {
        // Calculate Hashes
        std::string sha256Hex = SecureCrypt::Core::CryptoEngine::calculateSHA256(plaintext);
        std::string md5Hex = SecureCrypt::Core::CryptoEngine::calculateMD5(plaintext);
        
        log("Original File SHA-256: " + QString::fromStdString(sha256Hex));
        log("Original File MD5: " + QString::fromStdString(md5Hex));

        // Create human-readable header
        std::stringstream ss;
        ss << "--- SecureCrypt Encrypted File ---\n";
        ss << "Algorithm: AES-256-CBC\n";
        ss << "Original-SHA256: " << sha256Hex << "\n";
        ss << "Original-MD5: " << md5Hex << "\n";
        ss << "Salt-B64: " << SecureCrypt::Core::CryptoEngine::base64Encode(salt) << "\n";
        ss << "IV-B64: " << SecureCrypt::Core::CryptoEngine::base64Encode(iv) << "\n";
        
        // Calculate Checksum of plaintext
        std::vector<unsigned char> checksum;
        for (size_t i = 0; i < sha256Hex.length(); i += 2) {
            std::string byteString = sha256Hex.substr(i, 2);
            checksum.push_back(static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)));
        }
        ss << "Checksum-B64: " << SecureCrypt::Core::CryptoEngine::base64Encode(checksum) << "\n";
        ss << "Data-B64: " << SecureCrypt::Core::CryptoEngine::base64Encode(ciphertext) << "\n";
        ss << "--- End SecureCrypt File ---\n";

        std::string output = ss.str();
        std::vector<unsigned char> outputData(output.begin(), output.end());

        QString outPath = selectedFilePath + ".enc";
        if (SecureCrypt::File::FileManager::writeFile(outPath.toStdString(), outputData)) {
            progressBar->setValue(100);
            log("Encryption successful! Saved to: " + outPath);
            QMessageBox::information(this, "Success", "File encrypted successfully!");
        } else {
            log("Error: Failed to write output file.", true);
        }
    } else {
        log("Error: Encryption failed.", true);
    }
}

void MainWindow::onDecryptClicked() {
    if (selectedFilePath.isEmpty() || passwordInput->text().isEmpty()) {
        log("Error: Please select a file and enter a password.", true);
        return;
    }

    progressBar->setValue(10);
    log("Starting decryption...");

    std::string path = selectedFilePath.toStdString();
    std::string pass = passwordInput->text().toStdString();

    auto data = SecureCrypt::File::FileManager::readFile(path);
    std::string content(data.begin(), data.end());
    
    if (content.find("--- SecureCrypt Encrypted File ---") == std::string::npos) {
        log("Error: Not a valid SecureCrypt text-encrypted file.", true);
        return;
    }
    progressBar->setValue(30);

    // Parse the fields
    auto getField = [&](const std::string& key) -> std::string {
        size_t start = content.find(key + ": ");
        if (start == std::string::npos) return "";
        start += key.length() + 2;
        size_t end = content.find("\n", start);
        return content.substr(start, end - start);
    };

    std::string saltB64 = getField("Salt-B64");
    std::string ivB64 = getField("IV-B64");
    std::string checksumB64 = getField("Checksum-B64");
    std::string dataB64 = getField("Data-B64");

    if (saltB64.empty() || ivB64.empty() || dataB64.empty()) {
        log("Error: Missing required fields in encrypted file.", true);
        return;
    }

    std::vector<unsigned char> salt = SecureCrypt::Core::CryptoEngine::base64Decode(saltB64);
    std::vector<unsigned char> iv = SecureCrypt::Core::CryptoEngine::base64Decode(ivB64);
    std::vector<unsigned char> storedChecksum = SecureCrypt::Core::CryptoEngine::base64Decode(checksumB64);
    std::vector<unsigned char> ciphertext = SecureCrypt::Core::CryptoEngine::base64Decode(dataB64);

    std::vector<unsigned char> key, derivedIv;
    SecureCrypt::Core::CryptoEngine::deriveKey(pass, salt, key, derivedIv);

    std::vector<unsigned char> plaintext;
    if (cryptoEngine.decrypt(ciphertext, key, iv, plaintext)) {
        // Verify Integrity
        std::string currentChecksumHex = SecureCrypt::Core::CryptoEngine::calculateSHA256(plaintext);
        std::string currentMD5Hex = SecureCrypt::Core::CryptoEngine::calculateMD5(plaintext);
        
        log("Decrypted File SHA-256: " + QString::fromStdString(currentChecksumHex));
        log("Decrypted File MD5: " + QString::fromStdString(currentMD5Hex));

        std::vector<unsigned char> currentChecksum;
        for (size_t i = 0; i < currentChecksumHex.length(); i += 2) {
            std::string byteString = currentChecksumHex.substr(i, 2);
            currentChecksum.push_back(static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)));
        }

        if (currentChecksum != storedChecksum) {
            log("Error: Integrity check failed! File may be corrupted or tampered with.", true);
            return;
        }
        log("Integrity check passed.");

        // Optional Decompression
        std::vector<unsigned char> decompressed;
        if (SecureCrypt::Utils::CompressionManager::decompress(plaintext, decompressed)) {
            log("Decompression successful.");
            plaintext = decompressed;
        }
        progressBar->setValue(80);

        QString outPath = selectedFilePath;
        if (outPath.endsWith(".enc")) outPath.remove(outPath.length() - 4, 4);
        else outPath += ".dec";

        if (SecureCrypt::File::FileManager::writeFile(outPath.toStdString(), plaintext)) {
            progressBar->setValue(100);
            log("Decryption successful! Saved to: " + outPath);
            QMessageBox::information(this, "Success", "File decrypted successfully!");
        } else {
            log("Error: Failed to write output file.", true);
        }
    } else {
        log("Error: Decryption failed. Wrong password?", true);
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event) {
    const QMimeData *mimeData = event->mimeData();
    if (mimeData->hasUrls()) {
        QList<QUrl> urlList = mimeData->urls();
        if (!urlList.isEmpty()) {
            QString path = urlList.at(0).toLocalFile();
            selectedFilePath = path;
            fileInput->setText(path);
            log("File dropped: " + path);
        }
    }
}

void MainWindow::log(const QString &message, bool isError) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString formatted = QString("[%1] %2").arg(timestamp, message);
    if (isError) {
        logArea->append("<font color='#CF6679'>" + formatted + "</font>");
    } else {
        logArea->append(formatted);
    }
}

} // namespace SecureCrypt::Gui
