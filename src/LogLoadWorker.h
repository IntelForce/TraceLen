#pragma once
// Background JSON log loader — runs off the UI thread.
// Emits progress while reading/parsing, then hands events to MainWindow
// which pumps them into the table in small batches.

#include "ActivityEvent.h"
#include <QObject>
#include <QString>
#include <QVector>

class LogLoadWorker : public QObject
{
    Q_OBJECT
public:
    explicit LogLoadWorker(QObject* parent = nullptr) : QObject(parent) {}

    // Take ownership of the parsed events (call from UI thread after finished).
    QVector<ActivityEvent> takeEvents() { return std::move(m_events); }
    int skipped() const { return m_skipped; }

public slots:
    void loadFile(const QString& path);

signals:
    // percent: 0–100 overall estimate; message for status bar
    void progress(int percent, const QString& message);
    void finished(bool ok, const QString& error);

private:
    QVector<ActivityEvent> m_events;
    int m_skipped = 0;
};
