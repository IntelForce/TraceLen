#pragma once

// ============================================================
// EtwRegistryDnsWatcher.h — Kernel-Registry + DNS-Client + Kernel-Network
// ETW (admin only). Name kept for history; it now also covers real-time
// TCP/UDP connect/disconnect (Microsoft-Windows-Kernel-Network).
// ============================================================
// Same technique as EtwFileWatcher: one real-time ETW session, providers
// enabled with EnableTraceEx2, events decoded through TDH. Kept as its own
// class/session (rather than folded into EtwFileWatcher's session) so this
// new, less battle-tested code can't destabilize the existing file-watching
// path — if this watcher misbehaves, file/process monitoring is unaffected.
//
// Providers:
//   * Microsoft-Windows-Kernel-Registry — registry key/value operations,
//     WITH PID. Requires Administrator, same as Kernel-File.
//   * Microsoft-Windows-DNS-Client      — the actual domain name a process
//     asked to resolve (+ the result, when the lookup finishes before we
//     stop listening). This is NOT the same as DnsResolver.cpp, which only
//     does our own reverse lookups on IPs already seen in Net Connect
//     events; this is a tap on real outgoing DNS query traffic.
//
// Design note on keywords / classification:
// Providers are enabled with MatchAnyKeyword = ~0 and TRACE_LEVEL_VERBOSE
// so nothing is silently dropped by the kernel. Classification uses the
// stable EventDescriptor.Id first (Kernel-Registry: 1=Create, 2=Open,
// 5=SetValue…; DNS-Client: 3008/3018/3020 = completed query) with a
// Task-name substring fallback for older manifests. DNS additionally
// suppresses the common dual-stack AAAA "invalid parameter" / empty-result
// noise that otherwise makes every `ping` look like a failure.
//
// MOC-safe: no Windows types in this header.

#include "ActivityEvent.h"
#include "MonitorSettings.h"

#include <QThread>
#include <QMutex>
#include <QAtomicInt>
#include <QString>

class EtwRegistryDnsWatcher : public QThread
{
    Q_OBJECT

public:
    explicit EtwRegistryDnsWatcher(QObject* parent = nullptr);
    ~EtwRegistryDnsWatcher();

    void setSettings(const MonitorSettings& settings);
    void requestStop();

    // Called from the ETW consumer callback (ProcessTrace thread).
    void handleEventRecord(void* pEventRecord);

signals:
    void eventDetected(ActivityEvent event);
    void statusMessage(QString message);
    void errorOccurred(QString message);

protected:
    void run() override;

private:
    void handleRegistryRecord(void* pEventRecord);
    void handleDnsRecord(void* pEventRecord);
    void handleNetworkRecord(void* pEventRecord);

    struct Impl;                 // all ETW state lives in the .cpp
    Impl* m_d = nullptr;

    MonitorSettings m_settings;
    mutable QMutex  m_settingsMutex;
    // Guards m_sessionHandle / m_consumerHandle, which the worker thread writes
    // and requestStop() on the UI thread clears.
    mutable QMutex  m_handleMutex;

    void* m_sessionHandle  = nullptr;
    void* m_consumerHandle = nullptr;

    QAtomicInt m_stopRequested;
};
