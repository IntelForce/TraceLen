#include "NetworkBehaviorMonitor.h"

#include <QFileInfo>
#include <algorithm>
#include <vector>

#ifdef Q_OS_WIN
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <tcpmib.h>
#  include <tcpestats.h>
#  include <psapi.h>
#endif

#ifdef Q_OS_WIN
static QString pidExeName(int pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, DWORD(pid));
    if (!h) return {};
    wchar_t buf[MAX_PATH * 4];
    DWORD n = DWORD(sizeof(buf) / sizeof(buf[0]));
    QString name;
    if (QueryFullProcessImageNameW(h, 0, buf, &n))
        name = QFileInfo(QString::fromWCharArray(buf)).fileName();
    CloseHandle(h);
    return name;
}

static QString ipv4ToString(DWORD addrNetOrder)
{
    IN_ADDR a{};
    a.S_un.S_addr = addrNetOrder;
    char ipBuf[INET_ADDRSTRLEN] = {};
    if (!InetNtopA(AF_INET, &a, ipBuf, sizeof(ipBuf)))
        return {};
    return QString::fromLatin1(ipBuf);
}

static QString ipv6ToString(const UCHAR addr[16])
{
    char ipBuf[INET6_ADDRSTRLEN] = {};
    if (!InetNtopA(AF_INET6, addr, ipBuf, sizeof(ipBuf)))
        return {};
    return QString::fromLatin1(ipBuf);
}
#endif

NetworkBehaviorMonitor::NetworkBehaviorMonitor(QObject* parent)
    : QObject(parent)
{
    m_timer = new QTimer(this);
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &NetworkBehaviorMonitor::sample);
}

void NetworkBehaviorMonitor::start()
{
    if (!m_timer->isActive()) {
        m_timer->start();
        sample();
    }
}

void NetworkBehaviorMonitor::stop()
{
    m_timer->stop();
}

void NetworkBehaviorMonitor::clear()
{
    QMutexLocker lock(&m_mutex);
    m_flows.clear();
    m_lastSample.clear();
    m_connHistory.clear();
    m_listeners.clear();
    // Do not emit updated() — caller refreshes UI once. Emitting here caused
    // a double full-window rebuild and UI stalls.
}

void NetworkBehaviorMonitor::setHostname(const QString& ip, const QString& host)
{
    if (ip.isEmpty() || host.isEmpty()) return;
    QMutexLocker lock(&m_mutex);
    m_hostnames.insert(ip, host);
    for (auto it = m_flows.begin(); it != m_flows.end(); ++it) {
        if (it->remoteIP == ip)
            it->remoteHost = host;
    }
    for (auto it = m_connHistory.begin(); it != m_connHistory.end(); ++it) {
        if (it->row.remoteIP == ip)
            it->row.remoteHost = host;
    }
}

QString NetworkBehaviorMonitor::formatKey(int pid, const QString& protocol,
                                         const QString& remoteIP, quint16 remotePort,
                                         const QString& localExtra)
{
    return QString::number(pid) + QLatin1Char('|') + protocol + QLatin1Char('|')
         + remoteIP + QLatin1Char('|') + QString::number(remotePort)
         + QLatin1Char('|') + localExtra;
}

QString NetworkBehaviorMonitor::classify(const BehaviorFlow& f, qint64 durationSec)
{
    if (f.protocol == QLatin1String("UDP"))
        return QStringLiteral("UDP endpoint (no byte stats)");

    if (!f.hasByteStats) {
        if (durationSec >= 15)
            return QStringLiteral("Active TCP (bytes unavailable)");
        return QStringLiteral("TCP connected");
    }

    const quint64 minBytes = 16ull * 1024ull;
    const quint64 inB = f.totalIn;
    const quint64 outB = f.totalOut;
    const quint64 total = inB + outB;

    if (total < minBytes) {
        if (durationSec >= 20)
            return QStringLiteral("Active TCP (light)");
        return QStringLiteral("Idle / light");
    }

    const double ratioInOut = (outB > 0) ? (double(inB) / double(outB)) : (inB > 0 ? 999.0 : 1.0);

    if (durationSec >= 12 && total >= minBytes * 2) {
        if (ratioInOut >= 0.15 && ratioInOut <= 8.0 && durationSec >= 15)
            return QStringLiteral("Streaming (likely)");
        if (durationSec >= 20 && inB > outB * 3 && inB >= minBytes * 4)
            return QStringLiteral("Streaming (likely)");
    }

    if (inB >= minBytes && inB > outB * 2)
        return QStringLiteral("Download (likely)");
    if (outB >= minBytes && outB > inB * 2)
        return QStringLiteral("Upload (likely)");
    if (inB > outB)
        return QStringLiteral("Mostly download");
    if (outB > inB)
        return QStringLiteral("Mostly upload");
    return QStringLiteral("Mixed");
}

void NetworkBehaviorMonitor::sample()
{
#ifdef Q_OS_WIN
    const QDateTime now = QDateTime::currentDateTime();
    QMutexLocker lock(&m_mutex);

    auto ensureName = [&](int pid) -> QString {
        if (pid <= 0) return {};
        auto it = m_pidNames.find(pid);
        if (it != m_pidNames.end() && !it.value().isEmpty())
            return it.value();
        const QString nm = pidExeName(pid);
        if (!nm.isEmpty())
            m_pidNames.insert(pid, nm);
        return nm;
    };

    auto touchFlow = [&](int pid, const QString& protocol, const QString& remoteIP,
                         quint16 remotePort, const QString& localExtra,
                         quint64 dIn, quint64 dOut, bool gotBytes) {
        const QString key = formatKey(pid, protocol, remoteIP, remotePort, localExtra);
        BehaviorFlow& f = m_flows[key];
        if (f.pid == 0) {
            f.pid = pid;
            f.processName = ensureName(pid);
            f.protocol = protocol;
            f.remoteIP = remoteIP;
            f.remotePort = remotePort;
            f.remoteHost = m_hostnames.value(remoteIP);
            f.firstSeen = now;
        }
        if (f.processName.isEmpty())
            f.processName = ensureName(pid);
        if (gotBytes) {
            f.totalIn += dIn;
            f.totalOut += dOut;
            f.hasByteStats = true;
        }
        f.lastActive = now;
        if (m_hostnames.contains(remoteIP))
            f.remoteHost = m_hostnames.value(remoteIP);
    };

    auto touchConn = [&](int pid, const QString& protocol,
                         const QString& localIP, quint16 localPort,
                         const QString& remoteIP, quint16 remotePort,
                         quint64 dIn, quint64 dOut, bool gotBytes) {
        const QString key = QStringLiteral("%1|%2|%3:%4|%5:%6")
                                .arg(pid).arg(protocol)
                                .arg(localIP).arg(localPort)
                                .arg(remoteIP).arg(remotePort);
        ConnRec& c = m_connHistory[key];
        if (c.row.pid == 0) {
            c.key = key;
            c.row.pid = pid;
            c.row.processName = ensureName(pid);
            c.row.protocol = protocol;
            c.row.localIP = localIP;
            c.row.localPort = localPort;
            c.row.remoteIP = remoteIP;
            c.row.remotePort = remotePort;
            c.row.remoteHost = m_hostnames.value(remoteIP);
            c.row.firstSeen = now;
        }
        if (c.row.processName.isEmpty())
            c.row.processName = ensureName(pid);
        c.row.live = true;
        c.row.lastSeen = now;
        if (gotBytes) {
            c.row.bytesIn += dIn;
            c.row.bytesOut += dOut;
        }
        if (m_hostnames.contains(remoteIP))
            c.row.remoteHost = m_hostnames.value(remoteIP);
    };

    auto touchListen = [&](int pid, const QString& protocol,
                           const QString& localIP, quint16 localPort) {
        const QString key = QStringLiteral("%1|%2|%3:%4")
                                .arg(pid).arg(protocol).arg(localIP).arg(localPort);
        ListenRec& L = m_listeners[key];
        if (L.row.pid == 0) {
            L.key = key;
            L.row.pid = pid;
            L.row.processName = ensureName(pid);
            L.row.protocol = protocol;
            L.row.localIP = localIP;
            L.row.localPort = localPort;
            L.row.firstSeen = now;
        }
        if (L.row.processName.isEmpty())
            L.row.processName = ensureName(pid);
        L.row.live = true;
        L.row.lastSeen = now;
    };

    for (auto it = m_connHistory.begin(); it != m_connHistory.end(); ++it)
        it->row.live = false;
    for (auto it = m_listeners.begin(); it != m_listeners.end(); ++it)
        it->row.live = false;

    // ---- IPv4 TCP ----
    {
        DWORD bufSize = 0;
        GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufSize) {
            std::vector<BYTE> buf(bufSize);
            if (GetExtendedTcpTable(buf.data(), &bufSize, FALSE,
                                    AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                const auto* table =
                    reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_TCPROW_OWNER_PID& ownerRow = table->table[i];
                    const int pid = int(ownerRow.dwOwningPid);
                    if (pid <= 0) continue;

                    const QString localIP = ipv4ToString(ownerRow.dwLocalAddr);
                    const quint16 localPort = quint16(ntohs(quint16(ownerRow.dwLocalPort)));
                    const QString remoteIP = ipv4ToString(ownerRow.dwRemoteAddr);
                    const quint16 remotePort = quint16(ntohs(quint16(ownerRow.dwRemotePort)));

                    if (ownerRow.dwState == MIB_TCP_STATE_LISTEN) {
                        touchListen(pid, QStringLiteral("TCP"), localIP, localPort);
                        continue;
                    }
                    if (ownerRow.dwState != MIB_TCP_STATE_ESTAB)
                        continue;
                    if (ownerRow.dwRemoteAddr == 0)
                        continue;

                    MIB_TCPROW row{};
                    row.dwState      = ownerRow.dwState;
                    row.dwLocalAddr  = ownerRow.dwLocalAddr;
                    row.dwLocalPort  = ownerRow.dwLocalPort;
                    row.dwRemoteAddr = ownerRow.dwRemoteAddr;
                    row.dwRemotePort = ownerRow.dwRemotePort;

                    const QString tuple = QStringLiteral("4|%1:%2-%3:%4|%5")
                                              .arg(row.dwLocalAddr).arg(row.dwLocalPort)
                                              .arg(row.dwRemoteAddr).arg(row.dwRemotePort)
                                              .arg(pid);

                    quint64 dIn = 0, dOut = 0;
                    bool gotBytes = false;

                    // Without Admin, EStats often fails or returns jumps that make
                    // totals look random. Skip byte sampling in that mode.
                    if (m_collectByteStats) {
                        // Enable collection once; ignore failure (common non-admin).
                        TCP_ESTATS_DATA_RW_v0 rw{};
                        rw.EnableCollection = TRUE;
                        SetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&row), TcpConnectionEstatsData,
                            reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), FALSE);

                        TCP_ESTATS_DATA_ROD_v0 rod{};
                        const DWORD st = GetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&row), TcpConnectionEstatsData,
                            nullptr, 0, 0, nullptr, 0, 0,
                            reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod));
                        if (st == NO_ERROR) {
                            ConnSample& prev = m_lastSample[tuple];
                            if (prev.valid) {
                                // Counter reset / re-baseline → do not apply huge negative wrap
                                if (rod.DataBytesIn  >= prev.bytesIn)
                                    dIn  = rod.DataBytesIn  - prev.bytesIn;
                                if (rod.DataBytesOut >= prev.bytesOut)
                                    dOut = rod.DataBytesOut - prev.bytesOut;
                                // Reject absurd 1-second jumps (EStats just enabled or wrong row)
                                static const quint64 kMaxDeltaPerSample = 256ull * 1024ull * 1024ull;
                                if (dIn > kMaxDeltaPerSample || dOut > kMaxDeltaPerSample) {
                                    dIn = 0;
                                    dOut = 0;
                                    gotBytes = false; // re-baseline only
                                } else {
                                    gotBytes = true;
                                }
                            }
                            prev.bytesIn  = rod.DataBytesIn;
                            prev.bytesOut = rod.DataBytesOut;
                            prev.valid    = true;
                        } else {
                            // Failed read — drop previous sample so a later success
                            // does not invent a giant delta from stale counters.
                            m_lastSample.remove(tuple);
                        }
                    }

                    touchFlow(pid, QStringLiteral("TCP"), remoteIP, remotePort, {},
                              dIn, dOut, gotBytes);
                    touchConn(pid, QStringLiteral("TCP"), localIP, localPort,
                              remoteIP, remotePort, dIn, dOut, gotBytes);
                }
            }
        }
    }

    // ---- IPv6 TCP ----
    {
        DWORD bufSize = 0;
        GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufSize) {
            std::vector<BYTE> buf(bufSize);
            if (GetExtendedTcpTable(buf.data(), &bufSize, FALSE,
                                    AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                const auto* table =
                    reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_TCP6ROW_OWNER_PID& row = table->table[i];
                    const int pid = int(row.dwOwningPid);
                    if (pid <= 0) continue;

                    const QString localIP = ipv6ToString(row.ucLocalAddr);
                    const quint16 localPort = quint16(ntohs(quint16(row.dwLocalPort)));
                    const QString remoteIP = ipv6ToString(row.ucRemoteAddr);
                    const quint16 remotePort = quint16(ntohs(quint16(row.dwRemotePort)));

                    if (row.dwState == MIB_TCP_STATE_LISTEN) {
                        touchListen(pid, QStringLiteral("TCP"), localIP, localPort);
                        continue;
                    }
                    if (row.dwState != MIB_TCP_STATE_ESTAB)
                        continue;
                    bool any = false;
                    for (int b = 0; b < 16; ++b) {
                        if (row.ucRemoteAddr[b]) { any = true; break; }
                    }
                    if (!any) continue;

                    touchFlow(pid, QStringLiteral("TCP"), remoteIP, remotePort,
                              QStringLiteral("v6"), 0, 0, false);
                    touchConn(pid, QStringLiteral("TCP"), localIP, localPort,
                              remoteIP, remotePort, 0, 0, false);
                }
            }
        }
    }

    // ---- UDP IPv4 ----
    {
        DWORD bufSize = 0;
        GetExtendedUdpTable(nullptr, &bufSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (bufSize) {
            std::vector<BYTE> buf(bufSize);
            if (GetExtendedUdpTable(buf.data(), &bufSize, FALSE,
                                    AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                const auto* table =
                    reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_UDPROW_OWNER_PID& row = table->table[i];
                    const int pid = int(row.dwOwningPid);
                    if (pid <= 0) continue;
                    const QString localIP = ipv4ToString(row.dwLocalAddr);
                    const quint16 localPort = quint16(ntohs(quint16(row.dwLocalPort)));
                    const QString extra = localIP + QLatin1Char('/') + QString::number(localPort);
                    touchFlow(pid, QStringLiteral("UDP"), localIP, localPort, extra, 0, 0, false);
                    touchConn(pid, QStringLiteral("UDP"), localIP, localPort,
                              QString(), 0, 0, 0, false);
                    touchListen(pid, QStringLiteral("UDP"), localIP, localPort);
                }
            }
        }
    }

    // ---- UDP IPv6 ----
    {
        DWORD bufSize = 0;
        GetExtendedUdpTable(nullptr, &bufSize, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (bufSize) {
            std::vector<BYTE> buf(bufSize);
            if (GetExtendedUdpTable(buf.data(), &bufSize, FALSE,
                                    AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                const auto* table =
                    reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_UDP6ROW_OWNER_PID& row = table->table[i];
                    const int pid = int(row.dwOwningPid);
                    if (pid <= 0) continue;
                    const QString localIP = ipv6ToString(row.ucLocalAddr);
                    const quint16 localPort = quint16(ntohs(quint16(row.dwLocalPort)));
                    const QString extra = localIP + QLatin1Char('/') + QString::number(localPort);
                    touchFlow(pid, QStringLiteral("UDP"), localIP, localPort, extra, 0, 0, false);
                    touchConn(pid, QStringLiteral("UDP"), localIP, localPort,
                              QString(), 0, 0, 0, false);
                    touchListen(pid, QStringLiteral("UDP"), localIP, localPort);
                }
            }
        }
    }

    if (m_connHistory.size() > kMaxHistory) {
        QVector<QPair<QDateTime, QString>> byAge;
        byAge.reserve(m_connHistory.size());
        for (auto it = m_connHistory.constBegin(); it != m_connHistory.constEnd(); ++it) {
            if (!it->row.live)
                byAge.append({it->row.lastSeen, it.key()});
        }
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        int need = m_connHistory.size() - kMaxHistory;
        for (int i = 0; i < byAge.size() && need > 0; ++i, --need)
            m_connHistory.remove(byAge[i].second);
    }

    lock.unlock();
    emit updated();
#else
    Q_UNUSED(this);
#endif
}

QVector<BehaviorRow> NetworkBehaviorMonitor::snapshotByProcessHost() const
{
    QMutexLocker lock(&m_mutex);
    QVector<BehaviorRow> rows;
    rows.reserve(m_flows.size());
    const QDateTime now = QDateTime::currentDateTime();
    for (const BehaviorFlow& f : m_flows) {
        BehaviorRow r;
        r.pid = f.pid;
        r.processName = f.processName.isEmpty() ? QStringLiteral("pid %1").arg(f.pid) : f.processName;
        r.protocol = f.protocol;
        r.remoteIP = f.remoteIP;
        r.remotePort = f.remotePort;
        r.remoteHost = f.remoteHost;
        r.bytesIn = f.totalIn;
        r.bytesOut = f.totalOut;
        r.hasByteStats = f.hasByteStats;
        r.durationSec = f.firstSeen.isValid()
                            ? f.firstSeen.secsTo(f.lastActive.isValid() ? f.lastActive : now)
                            : 0;
        r.classification = classify(f, r.durationSec);
        rows.append(r);
    }
    std::sort(rows.begin(), rows.end(), [](const BehaviorRow& a, const BehaviorRow& b) {
        return (a.bytesIn + a.bytesOut) > (b.bytesIn + b.bytesOut);
    });
    return rows;
}

QVector<BehaviorRow> NetworkBehaviorMonitor::snapshotByProcess() const
{
    QMutexLocker lock(&m_mutex);
    struct Agg {
        BehaviorRow row;
        BehaviorFlow fake;
    };
    QHash<int, Agg> byPid;
    const QDateTime now = QDateTime::currentDateTime();
    for (const BehaviorFlow& f : m_flows) {
        Agg& a = byPid[f.pid];
        if (a.row.pid == 0) {
            a.row.pid = f.pid;
            a.row.processName = f.processName.isEmpty()
                                    ? QStringLiteral("pid %1").arg(f.pid)
                                    : f.processName;
            a.fake.protocol = QStringLiteral("TCP");
            a.fake.firstSeen = f.firstSeen;
        }
        if ((a.row.processName.isEmpty() || a.row.processName.startsWith(QLatin1String("pid ")))
            && !f.processName.isEmpty())
            a.row.processName = f.processName;
        a.row.bytesIn += f.totalIn;
        a.row.bytesOut += f.totalOut;
        if (f.hasByteStats)
            a.row.hasByteStats = true;
        a.fake.totalIn = a.row.bytesIn;
        a.fake.totalOut = a.row.bytesOut;
        a.fake.hasByteStats = a.row.hasByteStats;
        if (f.protocol == QLatin1String("UDP") && !a.fake.hasByteStats)
            a.fake.protocol = QStringLiteral("UDP");
        const qint64 d = f.firstSeen.isValid()
                             ? f.firstSeen.secsTo(f.lastActive.isValid() ? f.lastActive : now)
                             : 0;
        if (d > a.row.durationSec)
            a.row.durationSec = d;
    }
    QVector<BehaviorRow> rows;
    rows.reserve(byPid.size());
    for (auto it = byPid.begin(); it != byPid.end(); ++it) {
        if (it->row.hasByteStats)
            it->fake.protocol = QStringLiteral("TCP");
        it->row.classification = classify(it->fake, it->row.durationSec);
        if (!it->row.hasByteStats && it->row.durationSec >= 5)
            it->row.classification = QStringLiteral("Active (see host tab)");
        rows.append(it->row);
    }
    std::sort(rows.begin(), rows.end(), [](const BehaviorRow& a, const BehaviorRow& b) {
        return (a.bytesIn + a.bytesOut) > (b.bytesIn + b.bytesOut);
    });
    return rows;
}

QVector<ConnHistoryRow> NetworkBehaviorMonitor::snapshotConnectionHistory() const
{
    QMutexLocker lock(&m_mutex);
    QVector<ConnHistoryRow> rows;
    rows.reserve(m_connHistory.size());
    for (const ConnRec& c : m_connHistory)
        rows.append(c.row);
    std::sort(rows.begin(), rows.end(), [](const ConnHistoryRow& a, const ConnHistoryRow& b) {
        if (a.live != b.live) return a.live > b.live;
        if (a.processName != b.processName) return a.processName < b.processName;
        if (a.pid != b.pid) return a.pid < b.pid;
        return a.lastSeen > b.lastSeen;
    });
    return rows;
}

QVector<ListenRow> NetworkBehaviorMonitor::snapshotListeners() const
{
    QMutexLocker lock(&m_mutex);
    QVector<ListenRow> rows;
    rows.reserve(m_listeners.size());
    for (const ListenRec& L : m_listeners)
        rows.append(L.row);
    std::sort(rows.begin(), rows.end(), [](const ListenRow& a, const ListenRow& b) {
        if (a.live != b.live) return a.live > b.live;
        if (a.processName != b.processName) return a.processName < b.processName;
        if (a.pid != b.pid) return a.pid < b.pid;
        return a.localPort < b.localPort;
    });
    return rows;
}
