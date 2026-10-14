// ============================================================
// ProcessTimeline.h  —  per-process activity timeline (pure logic)
// ============================================================
// Builds "what did this process do" from the event log. This file has NO GUI
// and NO Windows dependency: it only reads ActivityEvent records. That keeps the
// grouping, counting and lifetime rules testable on their own, and keeps them
// separate from how the window draws them.
//
// Inputs : the full event list, and the PID to inspect.
// Output : a ProcessTimeline describing that process, its lifetime, a count per
//          activity type, its own events in time order, and its child processes.
#pragma once

#include "ActivityEvent.h"

#include <QDateTime>
#include <QMap>
#include <QSet>
#include <QString>
#include <QVector>

struct TimelineChild
{
    int       pid = 0;
    QString   processName;
    QDateTime started;        // ProcStart of the child, if seen
    bool      stillRunning = true;
    int       eventCount = 0; // events the child produced
};

struct ProcessTimeline
{
    int      pid = 0;
    QString  processName;      // best known name for the PID
    int      parentPid = 0;
    QString  parentName;
    QString  userName;         // owner account, DOMAIN\name (empty = not read)

    QDateTime firstSeen;       // earliest event for this PID
    QDateTime lastSeen;        // latest event for this PID
    QDateTime exited;          // ProcStop time, invalid if still running
    bool      stillRunning = true;

    // Count per activity type, for the summary strip. Keyed by the type's
    // display string so the GUI does not need the enum.
    QMap<QString, int> countsByType;

    // This process's own events, oldest first. These are the timeline rows.
    QVector<ActivityEvent> events;

    // Child processes, oldest start first.
    QVector<TimelineChild> children;

    int totalEvents() const { return events.size(); }
};

class ProcessTimelineBuilder
{
public:
    // Builds the timeline for `pid` from `all`. Returns a timeline with
    // pid == 0 and no events when the PID never appears in the log.
    static ProcessTimeline build(const QVector<ActivityEvent>& all, int pid);

    // Lifetime text for display, e.g. "running since 10:02:11" or
    // "ran 4m 12s (10:02:11 – 10:06:23)". Pure formatting, no Qt widgets.
    static QString lifetimeText(const ProcessTimeline& t);
};
