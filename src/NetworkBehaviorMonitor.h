#pragma once
// Samples TCP (IPv4/IPv6) and UDP endpoints. Tracks:
//   • traffic classification (download / upload / streaming)
//   • connection history (live vs disconnected) per process
//   • listening ports per process

#include <QObject>
#include <QHash>
#include <QString>
#include <QDateTime>
#include <QMutex>
#include <QTimer>
#include <QVector>
#include <QSet>

struct BehaviorFlow
{
    int     pid = 0;
    QString processName;
    QString protocol;      // "TCP" or "UDP"
    QString remoteIP;
    quint16 remotePort = 0;
    QString remoteHost;
    quint64 totalIn  = 0;
    quint64 totalOut = 0;
    bool    hasByteStats = false;
    QDateTime firstSeen;
    QDateTime lastActive;
};

struct BehaviorRow
{
    int     pid = 0;
    QString processName;
    QString protocol;
    QString remoteIP;
    quint16 remotePort = 0;
    QString remoteHost;
    quint64 bytesIn  = 0;
    quint64 bytesOut = 0;
    bool    hasByteStats = false;
    qint64  durationSec = 0;
    QString classification;
};

// One TCP/UDP connection observed during the session (history).
struct ConnHistoryRow
{
    int     pid = 0;
    QString processName;
    QString protocol;       // TCP / UDP
    QString localIP;
    quint16 localPort = 0;
    QString remoteIP;
    quint16 remotePort = 0;
    QString remoteHost;
    bool    live = false;   // seen in the last sample
    QDateTime firstSeen;
    QDateTime lastSeen;
    quint64 bytesIn = 0;
    quint64 bytesOut = 0;
};

// Listening / bound local endpoint.
struct ListenRow
{
    int     pid = 0;
    QString processName;
    QString protocol;       // TCP / UDP
    QString localIP;
    quint16 localPort = 0;
    bool    live = false;
    QDateTime firstSeen;
    QDateTime lastSeen;
};

class NetworkBehaviorMonitor : public QObject
{
    Q_OBJECT
public:
    explicit NetworkBehaviorMonitor(QObject* parent = nullptr);

    void start();
    void stop();
    void clear();
    bool isRunning() const { return m_timer && m_timer->isActive(); }

    QVector<BehaviorRow> snapshotByProcess() const;
    QVector<BehaviorRow> snapshotByProcessHost() const;
    QVector<ConnHistoryRow> snapshotConnectionHistory() const;
    QVector<ListenRow> snapshotListeners() const;

    void setHostname(const QString& ip, const QString& host);
    // Per-connection byte counters need Admin on most systems; without it
    // values jump/zeros and totals look wrong. MainWindow disables this
    // when not elevated.
    void setCollectByteStats(bool on) { m_collectByteStats = on; }
    bool collectByteStats() const { return m_collectByteStats; }

signals:
    void updated();

private slots:
    void sample();

private:
    static QString classify(const BehaviorFlow& f, qint64 durationSec);
    static QString formatKey(int pid, const QString& protocol,
                             const QString& remoteIP, quint16 remotePort,
                             const QString& localExtra = {});

    struct ConnSample {
        quint64 bytesIn = 0;
        quint64 bytesOut = 0;
        bool    valid = false;
    };

    struct ConnRec {
        ConnHistoryRow row;
        QString key;
    };

    struct ListenRec {
        ListenRow row;
        QString key;
    };

    QTimer* m_timer = nullptr;
    mutable QMutex m_mutex;
    QHash<QString, BehaviorFlow> m_flows;
    QHash<QString, ConnSample> m_lastSample;
    bool m_collectByteStats = true;
    QHash<QString, QString> m_hostnames;
    QHash<int, QString> m_pidNames;

    // Session history (survives disconnect); key = full 5-tuple-ish id
    QHash<QString, ConnRec> m_connHistory;
    QHash<QString, ListenRec> m_listeners;
    static constexpr int kMaxHistory = 8000;
};
