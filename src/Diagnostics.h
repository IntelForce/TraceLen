// ============================================================
// Diagnostics.h  —  crash evidence and session logging
// ============================================================
// When the app crashes, Windows closes it and nothing is written anywhere. This
// module makes sure there is evidence to look at afterwards:
//
//   logs\session_YYYYMMDD_HHMMSS.log   Qt warnings/errors with source location,
//                                      and every breadcrumb, flushed per line.
//   logs\crash_YYYYMMDD_HHMMSS.txt     Written by the crash handler: exception
//                                      code and name, faulting address and
//                                      module, thread, recent actions, versions.
//   logs\crash_YYYYMMDD_HHMMSS.dmp     Minidump. Open in Visual Studio (File ->
//                                      Open -> File) to see the exact stack.
//
// Folder: %LOCALAPPDATA%\TraceLen\logs\ (kept even when the app folder is
// read-only). Only the newest 10 session logs and 10 crash reports are kept.
//
// Honest limits: a crash handler runs after things have already gone wrong, so
// it is best-effort. If the heap is corrupted, the report may be incomplete,
// but the exception code and the last breadcrumbs are normally still written.
#pragma once

#include <QString>

namespace Diagnostics {

// Call first in main(), before QApplication is created.
void install();

// Call once the window is up. Reports whether the previous session ended
// without a clean exit, and returns the crash report path when one exists.
// Returns an empty string when the last session was clean.
QString previousCrashReport();

// Record a user action. Cheap; safe from the UI thread. The last 200 are kept
// and written into any crash report.
void breadcrumb(const QString& text);

// Mark the session as ended normally. Call from aboutToQuit().
void markCleanExit();

// Folder holding logs and reports, for "Open log folder" buttons.
QString logDirectory();

} // namespace Diagnostics
