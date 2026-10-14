// ============================================================
// FileWatcher.cpp  —  Windows file-system monitoring
// Uses ReadDirectoryChangesW with overlapped (async) I/O
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "FileWatcher.h"
#include <QDir>
#include <QFileInfo>
#include <QMutexLocker>
#include <QDateTime>
#include <QVector>

FileWatcher::FileWatcher(QObject* parent)
    : QThread(parent), m_stopRequested(0) {}

FileWatcher::~FileWatcher() { requestStop(); wait(3000); }

void FileWatcher::setWatchedDirectories(const QStringList& dirs)
{ QMutexLocker l(&m_mutex); m_watchedDirs = dirs; }

void FileWatcher::setSettings(const MonitorSettings& s)
{ QMutexLocker l(&m_mutex); m_settings = s; }

void FileWatcher::requestStop() { m_stopRequested.storeRelease(1); }

// ============================================================
// run()  —  background thread
// ============================================================
void FileWatcher::run()
{
    emit statusMessage("File watcher starting…");

    QStringList dirs;
    { QMutexLocker l(&m_mutex); dirs = m_watchedDirs; }

    // ---- Per-directory state ----
    // One of these structs is created for each watched directory.
    struct DirWatch
    {
        HANDLE     hDir;        // Directory handle (must stay open)
        HANDLE     hEvent;      // Signalled when data is ready
        OVERLAPPED overlapped;  // Required for async ReadDirectoryChangesW
        char       buffer[65536]; // Receive buffer — 64 KB per directory
                                  // (larger buffer = fewer overflow events)
        QString    path;
    };

    QVector<DirWatch*> watches;

    for (const QString& raw : dirs)
    {
        // Normalise to backslashes (QFileDialog may return forward slashes)
        QString dirPath = QDir::toNativeSeparators(raw);

        if (!QFileInfo(dirPath).isDir())
        {
            emit errorOccurred(
                QString("'%1' is not a valid directory — skipped.").arg(dirPath));
            continue;
        }

        // Open the directory handle.
        // FILE_FLAG_BACKUP_SEMANTICS is required to open directories.
        // FILE_FLAG_OVERLAPPED enables async I/O.
        HANDLE hDir = CreateFileW(
            reinterpret_cast<LPCWSTR>(dirPath.utf16()),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);

        if (hDir == INVALID_HANDLE_VALUE)
        {
            emit errorOccurred(
                QString("Cannot open '%1': error %2")
                    .arg(dirPath).arg(GetLastError()));
            continue;
        }

        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!hEvent) { CloseHandle(hDir); continue; }

        DirWatch* w = new DirWatch();
        w->hDir  = hDir;
        w->hEvent= hEvent;
        w->path  = dirPath;
        ZeroMemory(&w->overlapped, sizeof(w->overlapped));
        ZeroMemory(w->buffer, sizeof(w->buffer));
        w->overlapped.hEvent = hEvent;

        // ---- Which changes should trigger a notification? ----
        //
        // We intentionally OMIT FILE_NOTIFY_CHANGE_LAST_ACCESS.
        // That flag fires on every single file read (even just opening
        // a file to check its attributes). On busy directories this
        // generates thousands of events per second and causes the
        // notification buffer to overflow, losing real events.
        //
        // FILE_NOTIFY_CHANGE_FILE_NAME covers: created, deleted, renamed.
        // FILE_NOTIFY_CHANGE_LAST_WRITE covers: content modified.
        // FILE_NOTIFY_CHANGE_SIZE       covers: file grew or shrank.
        const DWORD FLAGS =
            FILE_NOTIFY_CHANGE_FILE_NAME   |  // Create / delete / rename files
            FILE_NOTIFY_CHANGE_DIR_NAME    |  // Create / delete / rename dirs
            FILE_NOTIFY_CHANGE_SIZE        |  // File size changed
            FILE_NOTIFY_CHANGE_LAST_WRITE;    // File content changed

        BOOL ok = ReadDirectoryChangesW(
            w->hDir, w->buffer, sizeof(w->buffer),
            TRUE,       // Watch all subdirectories recursively
            FLAGS,
            nullptr,    // lpBytesReturned = NULL for async mode
            &w->overlapped,
            nullptr     // No APC routine (we use event-based signalling)
        );

        if (!ok && GetLastError() != ERROR_IO_PENDING)
        {
            emit errorOccurred(
                QString("ReadDirectoryChangesW failed for '%1': error %2")
                    .arg(dirPath).arg(GetLastError()));
            CloseHandle(hEvent); CloseHandle(hDir); delete w;
            continue;
        }

        watches.append(w);
        emit statusMessage(QString("Now watching: %1").arg(dirPath));
    }

    if (watches.isEmpty())
    {
        emit errorOccurred(
            "No directories could be opened.\n"
            "Check that the paths exist and you have read permission.");
        return;
    }

    // Collect all event handles so WaitForMultipleObjects can watch them
    QVector<HANDLE> events;
    for (DirWatch* w : watches) events.append(w->hEvent);

    emit statusMessage(
        QString("File watcher active — %1 folder(s). "
                "Make changes inside a watched folder to see events.")
            .arg(watches.size()));

    // ============================================================
    // Main loop
    // ============================================================
    while (m_stopRequested.loadAcquire() == 0)
    {
        // Wait up to 500 ms for any directory to report a change.
        // WAIT_TIMEOUT = no changes — loop again to check stop flag.
        DWORD res = WaitForMultipleObjects(
            static_cast<DWORD>(events.size()),
            events.constData(), FALSE, 500);

        if (res == WAIT_TIMEOUT)  continue;
        if (res == WAIT_FAILED)   break;

        DWORD idx = res - WAIT_OBJECT_0;
        if (idx >= static_cast<DWORD>(watches.size())) continue;

        DirWatch* w = watches[static_cast<int>(idx)];

        DWORD bytesTransferred = 0;
        BOOL  got = GetOverlappedResult(
            w->hDir, &w->overlapped, &bytesTransferred, FALSE);

        if (!got || bytesTransferred == 0)
        {
            // ---- Buffer overflow ----
            // The notification buffer filled faster than we could drain it.
            // Some file events were lost. We warn and immediately re-issue
            // the read so monitoring continues without any further gap.
            // To reduce overflows: use a larger buffer (already 64 KB here)
            // or watch fewer/less-busy directories at once.
            emit statusMessage(
                QString("Note: some events in '%1' were missed (buffer overflow).")
                    .arg(w->path));
        }
        else
        {
            // ---- Parse the buffer ----
            // The buffer contains one or more FILE_NOTIFY_INFORMATION records
            // packed back-to-back. Walk them using NextEntryOffset.
            MonitorSettings settings;
            { QMutexLocker l(&m_mutex); settings = m_settings; }

            // FIX (Bug 3 — non-admin path): Track the pending old name so that
            // when FILE_ACTION_RENAMED_OLD_NAME and FILE_ACTION_RENAMED_NEW_NAME
            // arrive as consecutive records in the same buffer notification, we
            // emit a single "old → new" event instead of two separate events
            // (one showing only the old name, another showing only the new name).
            // Per the ReadDirectoryChangesW contract, OLD_NAME is always
            // immediately followed by NEW_NAME in the same buffer batch.
            QString pendingRenameOldPath;

            const char* ptr = w->buffer;
            do
            {
                const FILE_NOTIFY_INFORMATION* fni =
                    reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(ptr);

                // FileName is NOT null-terminated.
                // FileNameLength is in BYTES (each wchar_t = 2 bytes).
                QString name = QString::fromWCharArray(
                    fni->FileName,
                    static_cast<int>(fni->FileNameLength / sizeof(WCHAR)));

                QString fullPath = w->path + "\\" + name;

                auto emitEv = [&](ActivityEvent::Type t, const QString& details)
                {
                    ActivityEvent ev;
                    ev.type        = t;
                    ev.pid         = 0;
                    ev.processName = "?";  // ReadDirectoryChangesW gives no PID
                    ev.details     = details;
                    ev.timestamp   = QDateTime::currentDateTime();
                    emit fileEventDetected(ev);
                };

                switch (fni->Action)
                {
                    case FILE_ACTION_ADDED:
                        if (settings.trackFileWrite)
                            emitEv(ActivityEvent::Type::FileWrite, fullPath + " (new file)");
                        break;
                    case FILE_ACTION_REMOVED:
                        if (settings.trackFileDelete)
                            emitEv(ActivityEvent::Type::FileDelete, fullPath);
                        break;
                    case FILE_ACTION_MODIFIED:
                        if (settings.trackFileWrite)
                            emitEv(ActivityEvent::Type::FileWrite, fullPath);
                        break;

                    case FILE_ACTION_RENAMED_OLD_NAME:
                        // Store the old path; wait for the paired NEW_NAME record.
                        pendingRenameOldPath = fullPath;
                        break;

                    case FILE_ACTION_RENAMED_NEW_NAME:
                        // Pair with the previously stored old path and emit once.
                        if (settings.trackFileRename)
                        {
                            QString detail;
                            if (!pendingRenameOldPath.isEmpty())
                                detail = pendingRenameOldPath + " \u2192 " + fullPath;
                            else
                                detail = fullPath; // old name lost (shouldn't happen)
                            emitEv(ActivityEvent::Type::FileRename, detail);
                        }
                        pendingRenameOldPath.clear();
                        break;

                    default: break;
                }

                if (fni->NextEntryOffset == 0) break;
                ptr += fni->NextEntryOffset;
            } while (true);
        }

        // Always re-issue immediately after completion:
        // Re-issue ReadDirectoryChangesW immediately after each completion
        // so we never miss events that arrive while we process the buffer.
        ResetEvent(w->hEvent);
        ZeroMemory(&w->overlapped, sizeof(w->overlapped));
        w->overlapped.hEvent = w->hEvent;

        const DWORD FLAGS2 =
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME  |
            FILE_NOTIFY_CHANGE_SIZE      | FILE_NOTIFY_CHANGE_LAST_WRITE;

        ReadDirectoryChangesW(w->hDir, w->buffer, sizeof(w->buffer),
                              TRUE, FLAGS2, nullptr, &w->overlapped, nullptr);
    }

    // ---- Cleanup ----
    for (DirWatch* w : watches)
    {
        CancelIo(w->hDir);
        CloseHandle(w->hEvent);
        CloseHandle(w->hDir);
        delete w;
    }
    emit statusMessage("File watcher stopped.");
}
