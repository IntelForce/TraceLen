#include "LogLoadWorker.h"
#include "ActivityEvent.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>
#include <QDateTime>
#include <utility>

void LogLoadWorker::loadFile(const QString& path)
{
    m_events.clear();
    m_skipped = 0;

    emit progress(1, QStringLiteral("Opening log file…"));

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        emit finished(false, QStringLiteral("Cannot open for reading: ") + file.errorString());
        return;
    }

    const qint64 totalBytes = file.size();
    emit progress(5, QStringLiteral("Reading %1 MB…")
                         .arg(totalBytes / (1024.0 * 1024.0), 0, 'f', 1));

    // Read in chunks so we can report progress on large files
    QByteArray raw;
    raw.reserve(int(qMin(totalBytes, qint64(256 * 1024 * 1024))));
    constexpr qint64 kChunk = 1024 * 1024; // 1 MB
    while (!file.atEnd()) {
        raw.append(file.read(kChunk));
        if (totalBytes > 0) {
            const int pct = 5 + int(35.0 * double(raw.size()) / double(totalBytes));
            emit progress(qMin(pct, 40),
                          QStringLiteral("Reading… %1%")
                              .arg(int(100.0 * double(raw.size()) / double(totalBytes))));
        }
    }
    file.close();

    emit progress(42, QStringLiteral("Parsing JSON…"));

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    raw.clear(); // free memory before building events
    if (doc.isNull()) {
        emit finished(false, QStringLiteral("Invalid JSON: ") + err.errorString());
        return;
    }

    const QJsonObject root = doc.object();
    if (!root.contains(QLatin1String("events")) ||
        !root.value(QLatin1String("events")).isArray()) {
        emit finished(false, QStringLiteral("File is missing the 'events' array."));
        return;
    }

    const QJsonArray arr = root.value(QLatin1String("events")).toArray();
    const int n = arr.size();
    m_events.reserve(n);

    emit progress(50, QStringLiteral("Decoding %1 events…").arg(n));

    for (int i = 0; i < n; ++i) {
        const QJsonValue& val = arr.at(i);
        if (!val.isObject()) {
            ++m_skipped;
            continue;
        }
        const QJsonObject o = val.toObject();

        ActivityEvent::Type type;
        if (!ActivityEvent::tryTypeFromString(
                o.value(QLatin1String("type")).toString(), type)) {
            ++m_skipped;
            continue;
        }

        ActivityEvent ev;
        ev.type              = type;
        ev.pid               = o.value(QLatin1String("pid")).toInt();
        ev.parentPid         = o.value(QLatin1String("parent_pid")).toInt();
        ev.processName       = o.value(QLatin1String("process")).toString();
        ev.parentProcessName = o.value(QLatin1String("parent_process")).toString();
        ev.details           = o.value(QLatin1String("details")).toString();
        ev.timestamp         = QDateTime::fromString(
            o.value(QLatin1String("timestamp")).toString(),
            QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        ev.hostname          = o.value(QLatin1String("hostname")).toString();
        ev.dnsServer         = o.value(QLatin1String("dns_server")).toString();
        ev.operationStatus   = o.value(QLatin1String("operation_status")).toString();
        ev.fullPath          = o.value(QLatin1String("full_path")).toString();
        ev.publisher         = o.value(QLatin1String("publisher")).toString();
        ev.signatureStatus   = o.value(QLatin1String("signature_status")).toString();
        ev.fileVersion       = o.value(QLatin1String("file_version")).toString();
        ev.serviceName       = o.value(QLatin1String("service_name")).toString();
        ev.commandLine       = o.value(QLatin1String("command_line")).toString();
        ev.userName          = o.value(QLatin1String("user_name")).toString();

        m_events.append(std::move(ev));

        // Progress ~50% → 95% during decode
        if ((i & 0x3FF) == 0 || i + 1 == n) {
            const int pct = 50 + int(45.0 * double(i + 1) / double(qMax(n, 1)));
            emit progress(qMin(pct, 95),
                          QStringLiteral("Decoding events… %1 / %2 (%3%)")
                              .arg(i + 1).arg(n)
                              .arg(int(100.0 * double(i + 1) / double(qMax(n, 1)))));
        }
    }

    if (m_events.isEmpty() && m_skipped > 0) {
        emit finished(false,
                      QStringLiteral("No recognisable events in file (%1 skipped).")
                          .arg(m_skipped));
        return;
    }

    emit progress(98, QStringLiteral("Parsed %1 events — filling table…").arg(m_events.size()));
    emit finished(true, QString());
}
