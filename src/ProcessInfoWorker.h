#pragma once

// ============================================================
// ProcessInfoWorker.h  —  Background process metadata fetcher
// ============================================================
// For each process event, this class fetches extra details
// in a background thread so the UI never freezes:
//
//   Path        — Full path to the .exe file
//   Publisher   — Company name from the file's version resource
//   Version     — File version string (e.g., "10.0.19041.1")
//   Service     — Windows service name if this PID is a service
//   CmdLine     — Full command line used to start the process
//
// DESIGN (same queue/cache pattern as DnsResolver):
//   • A cache (QMap<pid, ProcInfo>) stores results so the same
//     PID is never looked up twice in one session.
//   • A queue holds PIDs waiting to be processed.
//   • The thread sleeps (zero CPU) when the queue is empty.
//   • When a result is ready, infoReady(pid, info) is emitted.
//   • MainWindow searches the table for rows with that PID
//     and fills in the optional extra columns.
//
// WHY COMMAND LINE IS COMPLEX ON WINDOWS:
//   Windows stores a process's command line inside its own
//   memory — specifically in the Process Environment Block (PEB).
//   To read it we must:
//     1. Call NtQueryInformationProcess() to find the PEB address.
//     2. Use ReadProcessMemory() to read bytes from the PEB.
//     3. Follow a pointer to RTL_USER_PROCESS_PARAMETERS.
//     4. Read the UNICODE_STRING CommandLine field.
//   This requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
//   access, which works for processes of the same user.
//   System processes (running as SYSTEM) will be skipped.
//
// REQUIRED LIBRARIES (add to CMakeLists):
//   advapi32  — OpenSCManager, EnumServicesStatusExW (service detection)
//   version   — GetFileVersionInfoW, VerQueryValueW (publisher/version)
//   psapi     — QueryFullProcessImageNameW (path)
// ============================================================

#include <QThread>
#include <QQueue>
#include <QSet>
#include <QMap>
#include <QMutex>
#include <QWaitCondition>
#include <QAtomicInt>
#include <QString>
#include <QHash>

// ============================================================
// struct ProcInfo  —  all metadata we collect for one process
// ============================================================
struct ProcInfo
{
    QString path;       // "C:\Windows\System32\notepad.exe"
    QString publisher;  // "Microsoft Corporation" — CompanyName string from the version
                        // resource. NOT verified: any file can put any text here.
    QString signatureStatus;  // "Verified" / "Unsigned" / "Untrusted" / "Expired" / ...
                        // A REAL Authenticode check via WinVerifyTrust — see
                        // ProcessInfoWorker::getSignatureInfo(). Empty if the fetch
                        // itself failed for some reason (couldn't open the file, etc.)
                        // rather than a verification outcome.
    QString version;    // "10.0.22621.1"
    QString service;    // "WSearch"  (empty if not a service)
    QString cmdLine;    // "notepad.exe C:\Users\a\test.txt"
    QString user;       // Account that owns the process, "DOMAIN\name"
                        // (e.g. "NT AUTHORITY\\SYSTEM"). Empty when not read;
                        // "(access denied)" when the token could not be opened.
};

// ============================================================
// class ProcessInfoWorker
// ============================================================
class ProcessInfoWorker : public QThread
{
    Q_OBJECT

public:
    explicit ProcessInfoWorker(QObject* parent = nullptr);
    ~ProcessInfoWorker();

    // Queue a PID for metadata lookup.
    // If this PID was already fetched, emits infoReady() immediately
    // from the cache (no background work needed).
    // Thread-safe — callable from the UI thread.
    void queueFetch(int pid);

    void requestStop();

signals:
    // Emitted when all metadata for one PID has been collected.
    // pid  — the process ID that was looked up
    // info — the collected metadata struct
    void infoReady(int pid, ProcInfo info);

protected:
    void run() override;

private:
    // ---- Individual fetch helpers (all blocking, called from run()) ----

    // Collect everything for one PID and return a filled ProcInfo.
    ProcInfo fetchOne(int pid) const;

    // Get the full executable path (e.g., "C:\Windows\notepad.exe")
    QString getPath(int pid) const;
    QString getProcessUser(int pid) const;   // "DOMAIN\name" of the process owner

    // Read CompanyName and FileVersion from the PE version resource.
    // Returns a pair {publisher, version}.
    QPair<QString, QString> getVersionInfo(const QString& exePath) const;

    // Verify the file's Authenticode signature via WinVerifyTrust — a real
    // cryptographic check, unlike the CompanyName string above. Checked
    // OFFLINE only (no revocation/network lookups), so it can't hang on a
    // slow or unreachable CRL/OCSP server; this means a revoked-but-not-yet-
    // known-locally certificate may still show as "Verified". Returns a
    // short status string (see ProcInfo::signatureStatus).
    QString getSignatureInfo(const QString& exePath) const;

    // A verified binary running from a temp/downloads/recycle-bin style
    // folder is a classic "living off the land" pattern — flagged
    // separately from signature validity itself. See the .cpp for the
    // exact (deliberately narrow) folder list.
    bool isUnusualLocation(const QString& path) const;

    // Check whether this PID belongs to a Windows service.
    // Returns the service name (e.g., "WSearch") or empty string.
    // Caches the full service list internally for efficiency.
    QString getServiceName(int pid) const;

    // Read the command line from the process's own memory (PEB).
    // Requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ access.
    QString getCommandLine(int pid) const;

    // ---- Thread-shared state (guarded by m_mutex) ----
    QQueue<int>          m_queue;    // PIDs waiting to be fetched
    QSet<int>            m_queued;   // Dedup: which PIDs are already queued
    QMap<int, ProcInfo>  m_cache;    // pid -> result cache

    // PID -> service display name, refreshed at most every few seconds
    mutable QMutex       m_serviceCacheMutex;
    mutable QHash<int, QString> m_serviceCache;
    mutable quint64      m_serviceCacheAt = 0;   // GetTickCount64() value, 0 = never

    QMutex         m_mutex;
    QWaitCondition m_condition;
    QAtomicInt     m_stopRequested;
};
