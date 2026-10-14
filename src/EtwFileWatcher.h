#pragma once

// EtwFileWatcher.h — Kernel-File ETW file monitor (system-wide, with PID)
// MOC-safe: no Windows types in this header.
//
// Hybrid design:
//   * Microsoft-Windows-Kernel-File (ETW) reports file operations WITH the
//     PID, but cannot see everything (memory-mapped writes, cache-manager
//     flushes, handles opened before start, lossy real-time delivery).
//   * The NTFS USN journal cannot miss a change, but has no PID.
// So the USN journal is the detector and ETW is the attribution source:
// each USN change is matched against recent ETW activity on the same path
// (who wrote / closed / still has it open) to fill in PID + process name.
// Changes that ETW already reported are not duplicated.

#include "ActivityEvent.h"
#include "MonitorSettings.h"

#include <QThread>
#include <QMutex>
#include <QAtomicInt>
#include <QString>

class EtwFileWatcher : public QThread
{
    Q_OBJECT

public:
    explicit EtwFileWatcher(QObject* parent = nullptr);
    ~EtwFileWatcher();

    void setSettings(const MonitorSettings& settings);
    void requestStop();
    static bool isRunningAsAdmin();

    // Called from the ETW consumer callback (ProcessTrace thread).
    void handleEventRecord(void* pEventRecord);

signals:
    void fileEventDetected(ActivityEvent event);
    void statusMessage(QString message);
    void errorOccurred(QString message);

protected:
    void run() override;

private:
    void usnWatcherMain();
    void processUsnBuffer(void* hVol, const QString& volumeRoot, void* frnMap,
                          void* renameOldMap, const char* buffer, unsigned int bytes);
    void flushPendingUsn(bool force);

    struct Impl;                 // all ETW state lives in the .cpp
    Impl* m_d = nullptr;

    MonitorSettings m_settings;
    mutable QMutex  m_settingsMutex;
    // Guards m_sessionHandle / m_consumerHandle. They are written by the
    // worker thread (run) and cleared by requestStop() on the UI thread.
    mutable QMutex  m_handleMutex;

    void* m_sessionHandle  = nullptr;
    void* m_consumerHandle = nullptr;

    QAtomicInt m_stopRequested;
    QAtomicInt m_usnStop{0};
};
