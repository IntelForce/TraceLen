#pragma once

// ============================================================
// DnsResolver.h  —  Background IP-to-hostname resolution
// ============================================================
// "Reverse DNS" converts an IP address like "142.250.80.46"
// into a readable hostname like "lga34s32-in-f14.1e100.net".
//
// WHY RUN THIS IN A SEPARATE THREAD?
//   A DNS lookup can freeze your program for several seconds
//   if the DNS server is slow.  By doing it in a background
//   thread, the UI stays responsive — the user sees "resolving…"
//   in the table, then it updates automatically when done.
//
// HOW THE DESIGN WORKS:
//   1.  A "cache" stores already-resolved IPs so we never look
//       up the same address twice.
//   2.  A "queue" holds IPs waiting to be looked up.
//   3.  The thread sleeps (costs zero CPU) when the queue is empty.
//   4.  When the UI calls queueResolution("1.2.3.4"), the IP is
//       added to the queue and the thread is woken up.
//   5.  The thread resolves the IP, then emits hostnameResolved()
//       with BOTH the original IP and the hostname.
//   6.  MainWindow finds every table row that has that IP and
//       updates the "Hostname" column — no row-index tracking needed.
// ============================================================

#include <QThread>
#include <QQueue>
#include <QSet>
#include <QMap>
#include <QMutex>
#include <QWaitCondition>
#include <QAtomicInt>
#include <QString>

class DnsResolver : public QThread
{
    Q_OBJECT

public:
    explicit DnsResolver(QObject* parent = nullptr);
    ~DnsResolver();

    // ---- Public interface (call from UI thread — thread-safe) --------

    // Queue an IP for resolution.
    //   • If the IP is already in the cache, emits hostnameResolved()
    //     immediately (from this call, on the calling thread).
    //   • If it's already queued, does nothing (no duplicates).
    //   • Otherwise, adds it to the queue and wakes the worker thread.
    void queueResolution(const QString& ipAddress);

    // Ask the background thread to stop after it finishes any
    // in-progress lookup.
    void requestStop();

signals:
    // Emitted when resolution completes (or fails).
    // ip       = the original IP address that was queued
    // hostname = the hostname found, e.g. "example.com"
    //            OR the original IP again if resolution failed
    //
    // Qt delivers this to the UI thread via a queued connection,
    // so the slot that updates the table always runs safely there.
    void hostnameResolved(QString ip, QString hostname);

protected:
    // QThread calls run() in the new OS thread when start() is invoked
    void run() override;

private:
    // Perform the actual blocking reverse-DNS lookup.
    // May take several seconds — only called from the background thread.
    QString resolveOne(const QString& ip, bool& definitive) const;

    // ---- Thread-shared state (guarded by m_mutex) --------------------
    QQueue<QString>        m_queue;    // IPs waiting to be looked up
    QSet<QString>          m_queued;   // Tracks which IPs are already queued
    QMap<QString, QString> m_cache;    // ip -> hostname (never look up twice)

    QMutex         m_mutex;      // Protects queue, queued, and cache
    QWaitCondition m_condition;  // Lets thread sleep when queue is empty
    QAtomicInt     m_stopRequested; // 0=run, 1=stop
};
