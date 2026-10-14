#pragma once

// ============================================================
// SystemMonitor.h  —  Process and network monitoring (Windows)
// ============================================================
// Polls two Windows APIs on a timer:
//
// 1. PROCESS MONITORING — Toolhelp32 API:
//    CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
//      Takes an instant snapshot of all running processes.
//    PROCESSENTRY32W.th32ParentProcessID
//      Tells us which process CREATED each process — the parent.
//    We compare snapshots to detect starts and stops.
//
// 2. NETWORK MONITORING — IP Helper API (iphlpapi.dll):
//    GetExtendedTcpTable()  → every TCP connection + PID
//    GetExtendedUdpTable()  → every UDP endpoint   + PID
//    We compare tables to detect new connections.
//
// Runs entirely in a background QThread so the UI stays smooth.
// Results are emitted as Qt signals and received by MainWindow.
// ============================================================

#include "ActivityEvent.h"
#include "MonitorSettings.h"

#include <QThread>
#include <QSet>
#include <QMap>
#include <QList>
#include <QMutex>
#include <QAtomicInt>
#include <QString>


// ============================================================
// struct ProcessSnapshot  —  info about ONE process at a moment
// ============================================================
// We keep a map of these to track the process list between polls.
// When a PID appears in the current snapshot but not the previous
// one, a new process started.  When it disappears, it stopped.
struct ProcessSnapshot
{
    int     pid;          // Process ID (unique number per running program)
    int     parentPid;    // PID of the process that launched this one
    QString name;         // Executable name, e.g. "chrome.exe"
};


// ============================================================
// struct NetConn  —  one TCP or UDP connection entry
// ============================================================
struct NetConn
{
    QString localAddr;    // e.g. "127.0.0.1:8080"
    QString remoteAddr;   // e.g. "93.184.216.34:443"  or "-" for UDP
    QString remoteIP;     // Just the IP part, e.g. "93.184.216.34"
    int     pid;
    QString processName;
    QString protocol;     // "TCP" or "UDP"
    QString state;        // "ESTABLISHED", "LISTEN", "BOUND", etc.

    // Unique key used in a QSet to detect duplicates across polls
    // Includes the owning PID: two processes on the same local address (common
    // for UDP, whose remote is always "-") must not collapse into one entry.
    QString key() const { return QString::number(pid) + "|" + protocol + "|" + localAddr + "|" + remoteAddr; }
};


// ============================================================
// class SystemMonitor
// ============================================================
class SystemMonitor : public QThread
{
    Q_OBJECT

public:
    explicit SystemMonitor(QObject* parent = nullptr);
    ~SystemMonitor();

    void setSettings(const MonitorSettings& settings);
    void requestStop();

signals:
    void processEventDetected(ActivityEvent event);
    void networkEventDetected(ActivityEvent event);
    void statusMessage(QString message);
    void errorOccurred(QString message);

protected:
    void run() override;

private:
    // ---- Process helpers ---
    // Returns a map of  pid -> ProcessSnapshot  for ALL running processes.
    // Using a map instead of a plain set lets us look up parent PIDs.
    QMap<int, ProcessSnapshot> getAllProcesses() const;

    // Get the .exe name for a PID (uses QueryFullProcessImageNameW)
    QString getProcessName(int pid) const;

    void checkProcesses(const MonitorSettings& s);

    // ---- Network helpers ---
    QList<NetConn> getTcpConnections() const;
    QList<NetConn> getUdpEndpoints()   const;
    void           checkNetwork(const MonitorSettings& s);

    // Convert Windows MIB table IP (DWORD, network-byte-order) + port
    // to a human-readable string like "127.0.0.1:80"
    static QString ipPortToString(unsigned long ip, unsigned int port);

    // Extract just the IP part from "1.2.3.4:80" → "1.2.3.4"
    static QString extractIP(const QString& addrPort);

    // MIB TCP state integer → "ESTABLISHED" / "LISTEN" / …
    static QString tcpStateString(int state);

    // ---- State between polls ---
    MonitorSettings            m_settings;
    QMap<int, ProcessSnapshot> m_knownProcesses;  // Processes seen last poll
    QSet<QString>              m_knownConnKeys;   // Connection keys seen last poll

    QAtomicInt     m_stopRequested;
    mutable QMutex m_mutex;
};
