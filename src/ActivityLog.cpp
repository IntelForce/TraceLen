// ============================================================
// ActivityLog.cpp  —  Event storage + JSON persistence
// ============================================================
// ALL fields of ActivityEvent are saved and loaded, including
// the metadata fields (fullPath, publisher, commandLine, etc.)
// that are filled in later by ProcessInfoWorker/DnsResolver.
// ============================================================

#include "ActivityLog.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <utility>

// True when `ip` occurs in `details` as a whole address, not as a substring
// of a longer address. "1.2.3.4" matches "-> 1.2.3.4:443" but not
// "-> 11.2.3.45:443", "-> 21.2.3.4:443" or "-> 1.2.3.4.5".
// A ':' is a port separator for IPv4 candidates, but part of the address
// for IPv6 candidates (which contain ':' themselves).
static bool ipAppearsInDetails(const QString& details, const QString& ip)
{
    if (ip.isEmpty()) return false;
    const bool isV6 = ip.contains(QLatin1Char(':'));
    auto addrChar = [isV6](QChar c) {
        if (c.isDigit() || c.isLetter() || c == QLatin1Char('.')) return true;
        return c == QLatin1Char(':') && isV6;
    };
    int from = 0;
    while (true) {
        const int at = details.indexOf(ip, from, Qt::CaseInsensitive);
        if (at < 0) return false;
        const int end = at + ip.size();
        const bool leftOk = (at == 0) || !addrChar(details.at(at - 1));
        // A '.' followed by a digit continues the address ("1.2.3.4.5").
        const bool dotContinues = end + 1 < details.size() &&
                                  details.at(end) == QLatin1Char('.') &&
                                  details.at(end + 1).isDigit();
        const bool rightOk = (end >= details.size()) ||
                             (!addrChar(details.at(end)) && !dotContinues);
        if (leftOk && rightOk) return true;
        from = at + 1;
    }
}

ActivityLog::ActivityLog(QObject* parent) : QObject(parent)
{ m_events.reserve(1000); }

void ActivityLog::addEvent(const ActivityEvent& ev)
{
    // removeFirst() on a 50k-element vector is O(n) per event; drop a chunk instead.
    if (m_events.size() >= MAX_EVENTS + TRIM_SLACK)
        m_events.remove(0, m_events.size() - MAX_EVENTS);
    m_events.append(ev);
    ++m_revision;
}
void ActivityLog::clear()            { m_events.clear(); ++m_revision; }
int  ActivityLog::count()     const  { return m_events.size(); }
QString ActivityLog::lastError() const { return m_lastError; }

const ActivityEvent& ActivityLog::getEvent(int i) const { return m_events[i]; }
const QVector<ActivityEvent>& ActivityLog::getAllEvents() const { return m_events; }

// ============================================================
// saveToFile — write all events to a JSON file
// ============================================================
// Every field of ActivityEvent is saved, including the extra
// metadata fields (fullPath, publisher, commandLine, etc.).
// These may be empty strings for events where ProcessInfoWorker
// has not yet completed its lookup — that is fine; they will
// appear empty when the log is reloaded.
bool ActivityLog::saveToFile(const QString& path) const
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        const_cast<ActivityLog*>(this)->m_lastError =
            "Cannot open for writing: " + file.errorString();
        return false;
    }

    QJsonObject root;
    root["version"]     = QStringLiteral(PM_LOG_FORMAT_VERSION);  // log file format
    root["saved_at"]    = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    root["event_count"] = m_events.size();

    QJsonArray arr;
    for (const auto& ev : m_events)
    {
        QJsonObject o;

        // ---- Core fields ----
        o["type"]           = ActivityEvent::typeToString(ev.type);
        o["pid"]            = ev.pid;
        o["parent_pid"]     = ev.parentPid;
        o["process"]        = ev.processName;
        o["parent_process"] = ev.parentProcessName;
        o["details"]        = ev.details;
        o["timestamp"]      = ev.timestamp.toString("yyyy-MM-dd HH:mm:ss.zzz");

        // ---- Network metadata ----
        o["hostname"]       = ev.hostname;
        o["dns_server"]     = ev.dnsServer;
        o["operation_status"] = ev.operationStatus;

        // ---- Process metadata (may be empty if fetch was pending) ----
        o["full_path"]      = ev.fullPath;
        o["publisher"]      = ev.publisher;
        o["signature_status"] = ev.signatureStatus;
        o["file_version"]   = ev.fileVersion;
        o["service_name"]   = ev.serviceName;
        o["command_line"]   = ev.commandLine;
        o["user_name"]      = ev.userName;

        arr.append(o);
    }
    root["events"] = arr;

        // Compact JSON: much smaller/faster for multi‑MB logs than Indented.
    file.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
    return true;
}

// ============================================================
// loadFromFile — read events back from a JSON file
// ============================================================
bool ActivityLog::loadFromFile(const QString& path)
{
    QFile file(path);
    // Binary mode is fine for UTF-8 JSON and avoids extra text translation cost.
    if (!file.open(QIODevice::ReadOnly))
    {
        m_lastError = "Cannot open for reading: " + file.errorString();
        return false;
    }

    const QByteArray raw = file.readAll();
    file.close();

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (doc.isNull())
    {
        m_lastError = "Invalid JSON: " + err.errorString();
        return false;
    }

    const QJsonObject root = doc.object();
    if (!root.contains(QLatin1String("events")) || !root.value(QLatin1String("events")).isArray())
    {
        m_lastError = "File is missing the 'events' array.";
        return false;
    }

    // One array materialization (not twice via root["events"].toArray() in a loop).
    const QJsonArray arr = root.value(QLatin1String("events")).toArray();

    // Parse into a temporary vector first, so a bad file never leaves the
    // current in-memory log half-replaced.
    QVector<ActivityEvent> loaded;
    loaded.reserve(arr.size());
    int skipped = 0;

    for (const QJsonValue& val : arr)
    {
        if (!val.isObject()) { ++skipped; continue; }
        const QJsonObject o = val.toObject();

        ActivityEvent::Type type;
        if (!ActivityEvent::tryTypeFromString(o.value(QLatin1String("type")).toString(), type)) {
            ++skipped;             // unknown or corrupt type: do not guess
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
        // Network metadata
        ev.hostname          = o.value(QLatin1String("hostname")).toString();
        ev.dnsServer         = o.value(QLatin1String("dns_server")).toString();
        ev.operationStatus   = o.value(QLatin1String("operation_status")).toString();
        // Process metadata (may be empty for older log files)
        ev.fullPath          = o.value(QLatin1String("full_path")).toString();
        ev.publisher         = o.value(QLatin1String("publisher")).toString();
        ev.signatureStatus   = o.value(QLatin1String("signature_status")).toString();
        ev.fileVersion       = o.value(QLatin1String("file_version")).toString();
        ev.serviceName       = o.value(QLatin1String("service_name")).toString();
        ev.commandLine       = o.value(QLatin1String("command_line")).toString();
        ev.userName          = o.value(QLatin1String("user_name")).toString();

        loaded.append(std::move(ev));
    }

    if (loaded.isEmpty() && skipped > 0) {
        m_lastError = QString("No recognisable events in file (%1 skipped).").arg(skipped);
        return false;
    }

    m_events = std::move(loaded);
    ++m_revision;
    if (skipped > 0)
        m_lastError = QString("Loaded %1 events; %2 unrecognised entries were skipped.")
                          .arg(m_events.size()).arg(skipped);
    else
        m_lastError.clear();
    return true;
}

// ============================================================
// updateProcessInfo — backfill metadata for all events of a PID
// ============================================================
void ActivityLog::updateProcessInfo(int pid,
                                    const QString& path,
                                    const QString& publisher,
                                    const QString& signatureStatus,
                                    const QString& version,
                                    const QString& service,
                                    const QString& cmdLine,
                                    const QString& user)
{
    // Only fill fields that are still empty. A later lookup that failed
    // (access denied, process already gone) returns empty strings, and must
    // not erase metadata an earlier successful lookup already stored.
    for (auto& ev : m_events)
    {
        if (ev.pid != pid) continue;
        if (ev.fullPath.isEmpty())        ev.fullPath        = path;
        if (ev.publisher.isEmpty())       ev.publisher       = publisher;
        if (ev.signatureStatus.isEmpty()) ev.signatureStatus = signatureStatus;
        if (ev.fileVersion.isEmpty())     ev.fileVersion     = version;
        if (ev.serviceName.isEmpty())     ev.serviceName     = service;
        if (ev.commandLine.isEmpty())     ev.commandLine     = cmdLine;
        if (ev.userName.isEmpty())        ev.userName        = user;
    }
    ++m_revision;
}

// ============================================================
// updateHostname — backfill hostname for all network events
// ============================================================
// Remote address of a network event, from its "... -> host:port ..." details.
// Returns empty when the text does not follow that shape.
static QString remoteIpOfDetails(const QString& details)
{
    const int arrow = details.indexOf(QStringLiteral("-> "));
    if (arrow < 0) return {};
    int i = arrow + 3;
    const int n = details.size();
    if (i < n && details.at(i) == QLatin1Char('[')) {          // [IPv6]:port
        const int close = details.indexOf(QLatin1Char(']'), i);
        return close < 0 ? QString() : details.mid(i + 1, close - i - 1);
    }
    int j = i;
    while (j < n && !details.at(j).isSpace()) {
        if (details.at(j) == QLatin1Char(':') && details.indexOf(QLatin1Char(':'), i) == j)
            break;                                              // IPv4 host:port
        ++j;
    }
    return details.mid(i, j - i);
}

void ActivityLog::updateHostnames(const QHash<QString, QString>& ipToHost)
{
    if (ipToHost.isEmpty()) return;
    bool changed = false;
    for (auto& ev : m_events)
    {
        if (!ev.isNetworkEvent()) continue;
        const QString remote = remoteIpOfDetails(ev.details);
        if (remote.isEmpty()) continue;
        auto it = ipToHost.constFind(remote);
        if (it != ipToHost.constEnd() && ev.hostname != it.value()) {
            ev.hostname = it.value();
            changed = true;
        }
    }
    if (changed) ++m_revision;
}

void ActivityLog::updateHostname(const QString& ip, const QString& hostname)
{
    for (auto& ev : m_events)
    {
        if (!ev.isNetworkEvent()) continue;
        if (ipAppearsInDetails(ev.details, ip))
            ev.hostname = hostname;
    }
    ++m_revision;
}
