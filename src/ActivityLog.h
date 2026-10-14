#pragma once
// ============================================================
// ActivityLog.h  —  Event storage + JSON persistence
// ============================================================
#include "ActivityEvent.h"
#include <QObject>
#include <QVector>
#include <QHash>
#include <QString>
#include <QDateTime>

class ActivityLog : public QObject
{
    Q_OBJECT
public:
    explicit ActivityLog(QObject* parent = nullptr);

    void addEvent(const ActivityEvent& event);
    void clear();
    int  count() const;
    const ActivityEvent& getEvent(int index) const;
    const QVector<ActivityEvent>& getAllEvents() const;

    // Update process metadata for ALL events belonging to this PID.
    // Called when ProcessInfoWorker finishes fetching metadata.
    void updateProcessInfo(int pid,
                           const QString& path,
                           const QString& publisher,
                           const QString& signatureStatus,
                           const QString& version,
                           const QString& service,
                           const QString& cmdLine,
                           const QString& user);

    // Update hostname for ALL events whose details contain this IP.
    void updateHostname(const QString& ip, const QString& hostname);

    // Incremented on every change (add, clear, load, metadata update). The UI
    // compares it to skip work when nothing has changed.
    quint64 revision() const { return m_revision; }

    // Apply many hostname results in ONE pass over the log. Entries of the form
    // ip -> hostname. The old per-IP call scanned the whole log per result.
    void updateHostnames(const QHash<QString, QString>& ipToHost);

    bool    saveToFile(const QString& filePath) const;
    bool    loadFromFile(const QString& filePath);
    QString lastError() const;

private:
    QVector<ActivityEvent> m_events;
    QString                m_lastError;
    quint64                m_revision = 0;
    static const int       MAX_EVENTS = 50000;
    static const int       TRIM_SLACK = 5000;   // trim in chunks: amortised O(1) per event
};
