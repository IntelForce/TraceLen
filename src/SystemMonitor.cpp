// ============================================================
// SystemMonitor.cpp  —  Process & network monitoring (Windows)
// ============================================================

// winsock2.h MUST come before windows.h
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#include <QHash>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>   // Toolhelp32: snapshots of processes
#include <iphlpapi.h>   // IP Helper API: TCP/UDP tables
#include <psapi.h>      // Process status: QueryFullProcessImageNameW

#include <vector>       // std::vector for heap-allocated buffers

#include <QMutexLocker>
#include <QDateTime>
#include <QFileInfo>

#include "SystemMonitor.h"

// ============================================================
// Constructor / Destructor
// ============================================================
SystemMonitor::SystemMonitor(QObject* parent)
    : QThread(parent), m_stopRequested(0) {}

SystemMonitor::~SystemMonitor()
{
    requestStop();
    wait(3000);
}

void SystemMonitor::setSettings(const MonitorSettings& s)
{
    QMutexLocker lock(&m_mutex);
    m_settings = s;
}

void SystemMonitor::requestStop()
{
    m_stopRequested.storeRelease(1);
}

// ============================================================
// ipPortToString()  —  "raw DWORD ip + port" → "A.B.C.D:PORT"
// ============================================================
// Windows MIB tables store IP addresses in network byte order
// (big-endian).  On a little-endian x86/x64 PC this means reading
// the address byte-by-byte gives the correct A.B.C.D order.
// The port also needs byte-swapping via ntohs().
QString SystemMonitor::ipPortToString(unsigned long ip, unsigned int port)
{
    // Cast to byte array and read each byte individually
    const unsigned char* b = reinterpret_cast<const unsigned char*>(&ip);

    // ntohs = "network to host short" — swaps the 2 bytes of the port
    // so "0x5000" (network byte order for port 80) becomes 80.
    unsigned short p = ntohs(static_cast<u_short>(port));

    return QString("%1.%2.%3.%4:%5").arg(b[0]).arg(b[1]).arg(b[2]).arg(b[3]).arg(p);
}

// ============================================================
// extractIP()  —  "1.2.3.4:80" → "1.2.3.4"
// ============================================================
QString SystemMonitor::extractIP(const QString& addrPort)
{
    // QString::section(delimiter, start, end) splits by the delimiter
    // and returns sections [start..end].  Section 0 before ':' = the IP.
    return addrPort.section(':', 0, 0);
}

// ============================================================
// tcpStateString()  —  MIB state number → readable text
// ============================================================
QString SystemMonitor::tcpStateString(int s)
{
    switch (s)
    {
        case  1: return "CLOSED";
        case  2: return "LISTEN";
        case  3: return "SYN_SENT";
        case  4: return "SYN_RCVD";
        case  5: return "ESTABLISHED";
        case  6: return "FIN_WAIT1";
        case  7: return "FIN_WAIT2";
        case  8: return "CLOSE_WAIT";
        case  9: return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE_TCB";
        default: return QString("STATE_%1").arg(s);
    }
}

// ============================================================
// getProcessName()  —  get .exe filename for a PID
// ============================================================
// PROCESS_QUERY_LIMITED_INFORMATION is the minimum privilege needed
// and works on more processes than PROCESS_ALL_ACCESS (some system
// processes refuse higher access levels).
QString SystemMonitor::getProcessName(int pid) const
{
    if (pid <= 0) return "System";

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, static_cast<DWORD>(pid));
    if (!h) return QString("pid-%1").arg(pid);

    wchar_t path[MAX_PATH] = {};
    DWORD   sz = MAX_PATH;
    BOOL    ok = QueryFullProcessImageNameW(h, 0, path, &sz);
    CloseHandle(h);

    if (!ok) return QString("pid-%1").arg(pid);

    // QFileInfo::fileName() strips the directory portion:
    // "C:\Windows\System32\notepad.exe"  →  "notepad.exe"
    return QFileInfo(QString::fromWCharArray(path)).fileName();
}

// ============================================================
// getAllProcesses()  —  snapshot every running process
// ============================================================
// Returns a QMap<pid, ProcessSnapshot> so we can:
//   • detect new/gone PIDs (by comparing with the previous map)
//   • look up the parent PID of any new process
//
// HOW TOOLHELP32 WORKS:
//   CreateToolhelp32Snapshot takes an atomic picture of the
//   process table.  Process32FirstW/NextW iterate through it.
//   The snapshot is independent of real-time changes, so it's
//   consistent — no half-updated entries.
QMap<int, ProcessSnapshot> SystemMonitor::getAllProcesses() const
{
    QMap<int, ProcessSnapshot> result;

    // TH32CS_SNAPPROCESS = include processes in the snapshot
    // 0 = snapshot the WHOLE system (not just one process)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);  // REQUIRED before first call

    if (Process32FirstW(snap, &entry))
    {
        do
        {
            ProcessSnapshot ps;
            ps.pid       = static_cast<int>(entry.th32ProcessID);
            ps.parentPid = static_cast<int>(entry.th32ParentProcessID);
            // szExeFile is a wide-char (UTF-16) string — convert to Qt
            ps.name      = QString::fromWCharArray(entry.szExeFile);

            result.insert(ps.pid, ps);
        }
        while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);  // Always release snapshot handles
    return result;
}

// ============================================================
// checkProcesses()  —  diff current vs previous process list
// ============================================================
void SystemMonitor::checkProcesses(const MonitorSettings& s)
{
    QMap<int, ProcessSnapshot> current = getAllProcesses();

    // ---- Detect NEW processes ----------------------------------------
    // Any PID in 'current' that is not in 'm_knownProcesses' is new.
    if (s.trackProcStart)
    {
        for (auto it = current.constBegin(); it != current.constEnd(); ++it)
        {
            int pid = it.key();
            const ProcessSnapshot& ps = it.value();
            // Known PID with the same executable is the same process. A PID
            // reused by a different program (same number, different name)
            // is treated as a new start, so it is not silently merged.
            auto known = m_knownProcesses.constFind(pid);
            if (known != m_knownProcesses.constEnd() &&
                known.value().name.compare(ps.name, Qt::CaseInsensitive) == 0)
                continue;  // Already known

            // Apply name filter
            if (!s.processNameFilter.isEmpty() &&
                !ps.name.contains(s.processNameFilter, Qt::CaseInsensitive))
                continue;

            // Look up the parent process name
            // The parent might still be in the current snapshot
            QString parentName = "?";
            if (current.contains(ps.parentPid))
                parentName = current[ps.parentPid].name;
            else if (ps.parentPid > 0)
                parentName = getProcessName(ps.parentPid);  // Try OS query

            ActivityEvent ev;
            ev.type              = ActivityEvent::Type::ProcStart;
            ev.pid               = pid;
            ev.processName       = ps.name;
            ev.parentPid         = ps.parentPid;
            ev.parentProcessName = parentName;
            ev.details           = QString("Started by: %1 (PID %2)")
                                       .arg(parentName).arg(ps.parentPid);
            ev.timestamp         = QDateTime::currentDateTime();
            emit processEventDetected(ev);
        }
    }

    // ---- Detect STOPPED processes ------------------------------------
    // Any PID in 'm_knownProcesses' not in 'current' has exited.
    if (s.trackProcStop)
    {
        for (auto it = m_knownProcesses.constBegin();
             it != m_knownProcesses.constEnd(); ++it)
        {
            int pid = it.key();
            const ProcessSnapshot& ps = it.value();
            // Still running as the same program. If the PID now belongs to a
            // different executable it was reused: the old one has stopped.
            auto now = current.constFind(pid);
            if (now != current.constEnd() &&
                now.value().name.compare(ps.name, Qt::CaseInsensitive) == 0)
                continue;  // Still running

            ActivityEvent ev;
            ev.type        = ActivityEvent::Type::ProcStop;
            ev.pid         = pid;
            ev.processName = ps.name;
            ev.parentPid   = ps.parentPid;
            ev.details     = QString("Process exited (PID %1)").arg(pid);
            ev.timestamp   = QDateTime::currentDateTime();
            emit processEventDetected(ev);
        }
    }

    // Save for next poll
    m_knownProcesses = current;
}

// ============================================================
// getTcpConnections()  —  all IPv4 TCP connections + owner PID
// ============================================================
// GetExtendedTcpTable returns a MIB_TCPTABLE_OWNER_PID struct:
//   dwNumEntries           — how many connections
//   table[i].dwOwningPid   — which process owns this socket
//   table[i].dwLocalAddr   — local  IP  (network byte order)
//   table[i].dwLocalPort   — local  port(network byte order)
//   table[i].dwRemoteAddr  — remote IP
//   table[i].dwRemotePort  — remote port
//   table[i].dwState       — TCP state (ESTABLISHED, LISTEN, …)
QList<NetConn> SystemMonitor::getTcpConnections() const
{
    QList<NetConn> result;

    // First call with NULL buffer to find out how large a buffer we need.
    // Windows fills 'bufSize' with the required byte count.
    DWORD bufSize = 0;
    GetExtendedTcpTable(nullptr, &bufSize, FALSE,
                        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!bufSize) return result;

    // Allocate the buffer on the heap (stack might be too small)
    std::vector<BYTE> buf(bufSize);
    if (GetExtendedTcpTable(buf.data(), &bufSize, FALSE,
                            AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;

    // Interpret the raw bytes as the structured table
    const auto* table =
        reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());

    QHash<int, QString> nameMemo;   // one OpenProcess per PID per poll
    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const MIB_TCPROW_OWNER_PID& row = table->table[i];
        int pid = static_cast<int>(row.dwOwningPid);

        NetConn c;
        c.pid         = pid;
        auto it = nameMemo.find(pid);
        if (it == nameMemo.end())
            it = nameMemo.insert(pid, getProcessName(pid));
        c.processName = it.value();
        c.protocol    = "TCP";
        c.state       = tcpStateString(static_cast<int>(row.dwState));
        c.localAddr   = ipPortToString(row.dwLocalAddr,  row.dwLocalPort);
        c.remoteAddr  = ipPortToString(row.dwRemoteAddr, row.dwRemotePort);
        c.remoteIP    = extractIP(c.remoteAddr);
        result.append(c);
    }
    return result;
}

// ============================================================
// getUdpEndpoints()  —  all IPv4 UDP endpoints + owner PID
// ============================================================
// UDP is connectionless — there is no "remote address" in the
// usual sense, only a local address that the process has bound.
QList<NetConn> SystemMonitor::getUdpEndpoints() const
{
    QList<NetConn> result;

    DWORD bufSize = 0;
    GetExtendedUdpTable(nullptr, &bufSize, FALSE,
                        AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (!bufSize) return result;

    std::vector<BYTE> buf(bufSize);
    if (GetExtendedUdpTable(buf.data(), &bufSize, FALSE,
                            AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        return result;

    const auto* table =
        reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());

    QHash<int, QString> nameMemo;   // one OpenProcess per PID per poll
    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const MIB_UDPROW_OWNER_PID& row = table->table[i];
        int pid = static_cast<int>(row.dwOwningPid);

        NetConn c;
        c.pid         = pid;
        auto it = nameMemo.find(pid);
        if (it == nameMemo.end())
            it = nameMemo.insert(pid, getProcessName(pid));
        c.processName = it.value();
        c.protocol    = "UDP";
        c.state       = "BOUND";
        c.localAddr   = ipPortToString(row.dwLocalAddr, row.dwLocalPort);
        c.remoteAddr  = "-";
        c.remoteIP    = "";
        result.append(c);
    }
    return result;
}

// ============================================================
// checkNetwork()  —  detect NEW connections since last poll
// ============================================================
void SystemMonitor::checkNetwork(const MonitorSettings& s)
{
    if (!s.trackNetConnect && !s.trackNetListen) return;

    QList<NetConn> all = getTcpConnections();
    all += getUdpEndpoints();

    QSet<QString> currentKeys;
    for (const auto& c : all) currentKeys.insert(c.key());

    for (const auto& conn : all)
    {
        if (m_knownConnKeys.contains(conn.key())) continue;  // Not new

        if (!s.processNameFilter.isEmpty() &&
            !conn.processName.contains(s.processNameFilter, Qt::CaseInsensitive))
            continue;

        bool isListen = (conn.state == "LISTEN" || conn.state == "BOUND");
        if ( isListen && !s.trackNetListen)  continue;
        if (!isListen && !s.trackNetConnect) continue;

        ActivityEvent ev;
        ev.type        = isListen ? ActivityEvent::Type::NetListen
                                  : ActivityEvent::Type::NetConnect;
        ev.pid         = conn.pid;
        ev.processName = conn.processName;
        // Use plain ASCII -> to avoid any Unicode encoding issues
        ev.details     = QString("%1  %2 -> %3  [%4]")
                             .arg(conn.protocol, conn.localAddr,
                                  conn.remoteAddr, conn.state);
        ev.timestamp   = QDateTime::currentDateTime();
        emit networkEventDetected(ev);
    }

    m_knownConnKeys = currentKeys;
}

// ============================================================
// run()  —  main polling loop (runs in background thread)
// ============================================================
void SystemMonitor::run()
{
    emit statusMessage("System monitor started.");

    // Take an initial snapshot so we don't flood events at startup.
    // We want to report CHANGES from this point forward, not everything
    // that already existed before the user clicked Start.
    m_knownProcesses = getAllProcesses();
    {
        auto tcp = getTcpConnections();
        auto udp = getUdpEndpoints();
        for (const auto& c : tcp) m_knownConnKeys.insert(c.key());
        for (const auto& c : udp) m_knownConnKeys.insert(c.key());
    }

    while (m_stopRequested.loadAcquire() == 0)
    {
        MonitorSettings s;
        {
            QMutexLocker lock(&m_mutex);
            s = m_settings;
        }

        checkProcesses(s);
        checkNetwork(s);

        // Sleep in 100 ms increments so the thread responds quickly
        // to stop requests (max delay = 100 ms, not the full interval).
        int steps = qMax(1, s.pollIntervalMs / 100);
        for (int i = 0; i < steps && m_stopRequested.loadAcquire() == 0; ++i)
            QThread::msleep(100);
    }

    emit statusMessage("System monitor stopped.");
}
