// ============================================================
// DnsResolver.cpp  —  Background IP-to-hostname resolution
// ============================================================
// FIX: Uses Qt's QHostInfo::fromName() instead of raw getnameinfo().
// QHostInfo is cross-platform, handles all Winsock init internally,
// and correctly does reverse DNS (PTR record lookup) when given
// a numeric IP address string.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#include <winsock2.h>   // Kept for any Winsock types used elsewhere
#include <ws2tcpip.h>

#include "DnsResolver.h"
#include <QHostInfo>     // Qt's cross-platform DNS lookup class
#include <QMutexLocker>

// Bound the cache so a long session that sees many distinct remote
// IPs does not grow without limit. Cleared wholesale when full.
static const int kMaxCacheEntries = 20000;

// ============================================================
DnsResolver::DnsResolver(QObject* parent)
    : QThread(parent), m_stopRequested(0) {}

DnsResolver::~DnsResolver()
{
    requestStop();
    wait(6000);
}

void DnsResolver::requestStop()
{
    { QMutexLocker lock(&m_mutex); m_stopRequested.storeRelease(1); }
    m_condition.wakeAll();
}

// ============================================================
// queueResolution()  —  called from the UI thread
// ============================================================
// ============================================================
// shouldSkipResolution — returns true for addresses that have
// no meaningful public hostname and should not be queried.
// ============================================================
static bool shouldSkipResolution(const QString& ip)
{
    if (ip.isEmpty() || ip == "-") return true;

    // ---- IPv4 checks ----

    // Null / any address
    if (ip == "0.0.0.0")        return true;

    // Broadcast
    if (ip == "255.255.255.255") return true;

    // Loopback — entire 127.0.0.0/8 range (not just 127.0.0.1)
    if (ip.startsWith("127."))   return true;

    // Link-local (APIPA) — 169.254.0.0/16
    if (ip.startsWith("169.254.")) return true;

    // ---- IPv6 checks ----

    // Loopback
    if (ip == "::1")             return true;

    // Any / unspecified
    if (ip == "::")              return true;

    // Link-local fe80::/10
    if (ip.startsWith("fe80:", Qt::CaseInsensitive)) return true;
    if (ip.startsWith("FE80:", Qt::CaseInsensitive)) return true;

    return false;
}

void DnsResolver::queueResolution(const QString& ip)
{
    if (shouldSkipResolution(ip)) return;

    QMutexLocker lock(&m_mutex);

    // Already cached? Emit immediately (no need to wake the thread).
    if (m_cache.contains(ip))
    {
        QString cached = m_cache[ip];
        lock.unlock();
        emit hostnameResolved(ip, cached);
        return;
    }

    // Already in queue? Skip duplicate.
    if (m_queued.contains(ip)) return;

    m_queue.enqueue(ip);
    m_queued.insert(ip);
    m_condition.wakeOne();
}

// ============================================================
// resolveOne()  —  blocking reverse-DNS lookup
// ============================================================
// QHostInfo::fromName() is a BLOCKING call — it waits for the
// DNS server to reply.  This is why we call it only from the
// background thread, never from the UI thread.
//
// When you pass an IP address string to fromName(), Qt internally
// calls getaddrinfo() / GetNameInfoW() which performs a reverse
// DNS (PTR record) lookup — exactly what we need.
//
// Results:
//   "8.8.8.8"        → "dns.google"          (has PTR)
//   "192.168.1.1"    → "192.168.1.1"         (no PTR, returns same IP)
//   "142.250.80.46"  → "lga34s19-in-f14..."  (has PTR)
QString DnsResolver::resolveOne(const QString& ip, bool& definitive) const
{
    // QHostInfo::fromName blocks until the lookup completes or times out.
    // It uses the system's configured DNS servers.
    QHostInfo info = QHostInfo::fromName(ip);

    // NoError: the server answered. A missing PTR record is a real answer
    // and is worth caching. HostNotFound is also a definitive "no name".
    // Anything else (timeout, server failure) is transient: do not cache it,
    // so a later event for this IP retries.
    definitive = (info.error() == QHostInfo::NoError ||
                  info.error() == QHostInfo::HostNotFound);

    if (info.error() == QHostInfo::NoError)
    {
        QString hostname = info.hostName();
        if (!hostname.isEmpty() && hostname != ip)
            return hostname;
    }
    return ip;   // no name known: show the IP
}

// ============================================================
// run()  —  background thread main loop
// ============================================================
void DnsResolver::run()
{
    while (m_stopRequested.loadAcquire() == 0)
    {
        QString ip;
        bool    hasWork = false;

        {
            QMutexLocker lock(&m_mutex);
            if (m_queue.isEmpty())
                m_condition.wait(&m_mutex, 500); // Sleep 500ms if idle

            if (!m_queue.isEmpty())
            {
                ip      = m_queue.dequeue();
                hasWork = true;
            }
        }

        if (!hasWork) continue;

        // This may block for several seconds — that is fine here
        bool definitive = false;
        QString hostname = resolveOne(ip, definitive);

        {
            QMutexLocker lock(&m_mutex);
            m_queued.remove(ip);
            if (definitive) {
                if (m_cache.size() >= kMaxCacheEntries) m_cache.clear();
                m_cache[ip] = hostname;
            }
        }

        // Deliver the result (even a transient fallback) so the row stops
        // showing "resolving…". A later event for this IP will re-queue it.
        emit hostnameResolved(ip, hostname);
    }
}
