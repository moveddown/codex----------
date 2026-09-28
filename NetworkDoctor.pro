QT += core gui widgets network
CONFIG += c++11
TARGET = NetworkDoctor
TEMPLATE = app
SOURCES += src/main.cpp src/model.cpp src/platform.cpp src/engine.cpp src/mainwindow.cpp
HEADERS += src/model.h src/platform.h src/engine.h src/mainwindow.h
win32:LIBS += -lwinhttp
QMAKE_CXXFLAGS += -Wall -Wextra

# Qt Creator shadow builds need the same TLS DLLs as the release bundle.
# Deploy on every build, even when the executable itself is already up to date.
win32 {
    CONFIG(debug, debug|release): DESTDIR = $$OUT_PWD/debug
    else: DESTDIR = $$OUT_PWD/release
    isEmpty(OPENSSL_RUNTIME_DIR): OPENSSL_RUNTIME_DIR = $$clean_path($$[QT_INSTALL_PREFIX]/../../Tools/QtCreator/bin)
    TLS_DLLS = libcrypto-1_1-x64.dll libssl-1_1-x64.dll
    for(dll, TLS_DLLS) {
        !exists($$OPENSSL_RUNTIME_DIR/$$dll): error(Missing $$dll in $$OPENSSL_RUNTIME_DIR. Set OPENSSL_RUNTIME_DIR to a compatible x64 OpenSSL 1.1 directory.)
    }
    tls_runtime.target = tls_runtime
    tls_runtime.CONFIG += phony
    tls_runtime.commands = if not exist $$shell_quote($$shell_path($$DESTDIR)) $$QMAKE_MKDIR $$shell_quote($$shell_path($$DESTDIR))
    for(dll, TLS_DLLS) {
        tls_runtime.commands += $$escape_expand(\\n\\t) $$QMAKE_COPY $$shell_quote($$shell_path($$OPENSSL_RUNTIME_DIR/$$dll)) $$shell_quote($$shell_path($$DESTDIR/$$dll))
    }
    QMAKE_EXTRA_TARGETS += tls_runtime
    PRE_TARGETDEPS += tls_runtime
}
