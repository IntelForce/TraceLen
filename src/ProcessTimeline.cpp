// ============================================================
// ProcessTimeline.cpp  —  per-process activity timeline (pure logic)
// ============================================================
#include "ProcessTimeline.h"

#include <algorithm>

ProcessTimeline ProcessTimelineBuilder::build(const QVector<ActivityEvent>& all, int pid)
{
    ProcessTimeline t;
    if (pid <= 0) return t;
    t.pid = pid;

    // Pass 1: this PID's own events, plus the child PIDs it spawned.
    QMap<int, TimelineChild> childMap;     // child pid -> info
    for (const ActivityEvent& ev : all)
    {
        if (ev.pid == pid)
        {
            t.events.append(ev);

            // Learn the name and parent from the best available event.
            if (t.processName.isEmpty() && !ev.processName.isEmpty())
                t.processName = ev.processName;
            // The owner is filled per PID by the process-info lookup, so any event
            // of this PID that has it is enough. Take the first non-empty one.
            if (t.userName.isEmpty() && !ev.userName.isEmpty())
                t.userName = ev.userName;
            if (ev.type == ActivityEvent::Type::ProcStart && ev.parentPid > 0)
            {
                t.parentPid  = ev.parentPid;
                t.parentName = ev.parentProcessName;
            }
            if (ev.type == ActivityEvent::Type::ProcStop)
            {
                t.exited = ev.timestamp;
            }
        }

        // A child is any process whose ProcStart names this PID as parent.
        if (ev.type == ActivityEvent::Type::ProcStart && ev.parentPid == pid &&
            ev.pid != pid)
        {
            TimelineChild c;
            c.pid         = ev.pid;
            c.processName = ev.processName;
            c.started     = ev.timestamp;
            childMap.insert(ev.pid, c);
        }
    }

    if (t.events.isEmpty() && childMap.isEmpty())
        return ProcessTimeline{};           // nothing known about this PID

    // Oldest first. Stable sort keeps same-timestamp events in log order.
    std::stable_sort(t.events.begin(), t.events.end(),
                     [](const ActivityEvent& a, const ActivityEvent& b) {
                         return a.timestamp < b.timestamp;
                     });

    // Summary counts and the time span.
    for (const ActivityEvent& ev : t.events)
    {
        t.countsByType[ActivityEvent::typeToString(ev.type)] += 1;
    }
    if (!t.events.isEmpty())
    {
        t.firstSeen = t.events.first().timestamp;
        t.lastSeen  = t.events.last().timestamp;
    }

    // Lifetime: running unless a ProcStop was recorded for this PID.
    t.stillRunning = !t.exited.isValid();
    if (!t.stillRunning && t.lastSeen < t.exited)
        t.lastSeen = t.exited;

    // Pass 2: per-child details in ONE scan of the log. (The earlier version
    // rescanned the whole log for every child, which is quadratic.)
    for (const ActivityEvent& ev : all)
    {
        auto it = childMap.find(ev.pid);
        if (it == childMap.end()) continue;
        TimelineChild& c = it.value();
        c.eventCount += 1;
        if (ev.type == ActivityEvent::Type::ProcStop)
            c.stillRunning = false;
        if (c.processName.isEmpty() && !ev.processName.isEmpty())
            c.processName = ev.processName;
    }

    t.children = childMap.values().toVector();
    std::stable_sort(t.children.begin(), t.children.end(),
                     [](const TimelineChild& a, const TimelineChild& b) {
                         return a.started < b.started;
                     });
    return t;
}

QString ProcessTimelineBuilder::lifetimeText(const ProcessTimeline& t)
{
    if (!t.firstSeen.isValid()) return QStringLiteral("no activity recorded");

    const QString start = t.firstSeen.toString(QStringLiteral("HH:mm:ss"));
    if (t.stillRunning)
        return QStringLiteral("running since %1").arg(start);

    const qint64 ms = t.firstSeen.msecsTo(t.exited);
    const qint64 totalSec = ms / 1000;
    const qint64 m = totalSec / 60;
    const qint64 s = totalSec % 60;
    QString span;
    if (m > 0)      span = QStringLiteral("%1m %2s").arg(m).arg(s);
    else            span = QStringLiteral("%1s").arg(s);
    return QStringLiteral("ran %1 (%2 – %3)")
        .arg(span)
        .arg(start)
        .arg(t.exited.toString(QStringLiteral("HH:mm:ss")));
}
