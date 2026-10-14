#pragma once

// ============================================================
// FileWatcher.h - Windows File System Monitor
// ============================================================
// Uses ReadDirectoryChangesW (Windows API) to detect file
// creation, deletion, modification, and renames in real time.
//
// HOW IT WORKS:
//   1. Open a directory HANDLE with CreateFileW()
//   2. Call ReadDirectoryChangesW() with overlapped (async) I/O
//   3. Windows fills a buffer with FILE_NOTIFY_INFORMATION
//      structs whenever files change inside that directory
//   4. WaitForMultipleObjects() waits (with timeout) for any
//      directory to signal a change
//   5. We process the buffer and emit Qt signals
//
// WHY A SEPARATE THREAD?
//   Waiting for changes blocks the caller. Running in a QThread
//   keeps the UI responsive. Qt signal/slot (QueuedConnection)
//   safely passes events back to the main (UI) thread.
//
// LIMITATION: ReadDirectoryChangesW does NOT report which
//   process caused a file change. For that you need ETW
//   (Event Tracing for Windows) which requires admin rights.
// ============================================================

#include "ActivityEvent.h"
#include "MonitorSettings.h"

#include <QThread>
#include <QStringList>
#include <QMutex>
#include <QAtomicInt>

// ============================================================
// class FileWatcher
// ============================================================
// Inherits QThread. We override run() to define what runs
// in the background thread. Call start() to launch it.
class FileWatcher : public QThread
{
    Q_OBJECT

public:
    explicit FileWatcher(QObject* parent = nullptr);
    ~FileWatcher();

    // Call these BEFORE start()-ing the thread
    void setWatchedDirectories(const QStringList& dirs);
    void setSettings(const MonitorSettings& settings);

    // Signal the background thread to exit gracefully
    void requestStop();

signals:
    // Emitted when a file system event is detected
    void fileEventDetected(ActivityEvent event);

    // Emitted for informational status messages
    void statusMessage(QString message);

    // Emitted when a non-fatal error occurs
    void errorOccurred(QString message);

protected:
    // This is called by Qt when start() is invoked.
    // EVERYTHING inside run() executes in the background thread.
    void run() override;

private:
    MonitorSettings  m_settings;        // What events to track
    QStringList      m_watchedDirs;     // Directories to monitor
    QAtomicInt       m_stopRequested;   // Thread-safe stop flag (0=run, 1=stop)
    mutable QMutex   m_mutex;           // Protects m_settings and m_watchedDirs
};
