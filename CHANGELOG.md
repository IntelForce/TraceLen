# TraceLen — v2.3.0 changes

## Status
Source changes only. This build has NOT been compiled or run. Qt and the Windows
SDK are not available in the environment these changes were made in. Before
release, build with Qt 5.15 (or Qt 6) on Windows and run the manual checklist at
the end of this file.

## v2.3.0 — owner account, filter stability, crash diagnostics

### New: process owner ("user") in the details
- The account that runs each process is read from its access token and shown as
  `DOMAIN\name` (e.g. `NT AUTHORITY\SYSTEM`).
- Shown in: the process tree (new last column, "User"), the process events window
  (Timeline header), the CSV export (new `UserName` column), and the circular log.
- If the token can't be opened (protected or elevated processes), it shows
  `(access denied)`. A PID that has already exited shows `(process exited)`.
- Not added to the main flat table: that would shift every column index and the
  saved column-visibility settings. Available in the tree and the detail window.

### Fixed: lag and crash with many filters
- **Crash cause (likely):** the ✕ button on a filter tag destroyed itself from
  inside its own click handler. Removal is now deferred, and identified by the
  filter's content, not its list position, so a stale click cannot remove the
  wrong filter. The same fix applies to capture-condition tags.
- **Lag cause:** every filter's regular expression was looked up and copied for
  every row on every pass. Filters are now compiled once when added.
- **Lag cause:** capture conditions were compiled for every incoming event. Now
  compiled once when added.
- Adding or removing filters is now debounced into one pass.
- Limits: at most 64 column filters and 32 capture conditions, with a message
  when the limit is reached.

### Fixed: regression from v2.2 (process tree ignored filters)
- The v2.2 process-tree cache skipped rebuilds when the log had not changed. That
  also skipped rebuilds caused by filter changes and by switching to the grouped
  view. Both now force a rebuild.

### New: crash diagnostics (Diagnostics.cpp)
- Session log: `%LOCALAPPDATA%\TraceLen\logs\session_*.log`, with Qt
  warnings and errors (with source file and line) and every user action, flushed
  per line.
- Crash report and minidump on an unhandled Windows exception:
  `crash_*.txt` and `crash_*.dmp`. The text report names the exception, the
  faulting module and address, the thread, the recent actions, and versions.
- Uncaught C++ exceptions are logged before the program ends.
- Startup notice when the previous run did not exit cleanly (also covers End task
  and power loss, which look the same from inside).
- Only the newest 10 session logs and 10 crash reports are kept.
- See `CRASH_INVESTIGATION.md` for how to read these, and how to use Windows'
  own Event Viewer records with no code changes.

### Build
- `Diagnostics.cpp` added to the source list.
- `QRegularExpression` now included explicitly in `MainWindow.h`.

### Verification status
- Pure logic tested against Python ports (not the C++ itself):
  owner selection rule, content-keyed filter removal, clean-exit marker sequences,
  precompiled-vs-cached filter results (identical), remote-IP parsing, regex guard.
- Structural checks on every edited file: brace/parenthesis balance, every member
  used is declared, every `Diagnostics::` call exists, no duplicate `case` values.
- Windows exception codes checked against the SDK headers. `0xE06D7363` (the C++
  exception code) is set by the MSVC runtime, not the SDK headers, and is **not**
  verified.
- **Not compiled and not run.** Build on Windows before release.

### Manual checks to add to the v2.2 list
10. Open the process tree: a "User" column shows the owner for each process.
11. Add 20 column filters quickly, then remove them by clicking ✕ rapidly. The window
    stays responsive and removes exactly the filter clicked.
12. Force a crash in a test build (for example, call `abort()` from a debug menu) and
    confirm `crash_*.txt`, `crash_*.dmp` and the startup notice appear.
13. Check `session_*.log` contains the actions you performed before the crash.

## Build and version
- CMake: Qt 5 is the default (matches the documentation); Qt 6 is the fallback.
  `-DPM_FORCE_QT6=ON` prefers Qt 6. A missing Qt is now a clear configure error.
- Version comes from `project(VERSION)` in one place. The app and the saved-log
  format version (`2.2`) are both generated from that, so they can no longer
  disagree.

## Correctness fixes
- **Hostname matching:** an IP now matches only as a whole address. `1.2.3.4` no
  longer labels `11.2.3.45` or `21.2.3.4`. IPv4 port separators and IPv6 addresses
  are handled.
- **Registry hive:** a relative registry path with no known parent is shown as
  `(hive unknown) …` instead of being assumed to be HKCU. Machine-wide writes are
  no longer shown as per-user.
- **Port decoding:** the named-field fallback no longer byte-swaps ports that TDH
  has already converted. Port 53 is 53 on both decode paths.
- **USN renames:** a rename is reported as `old -> new` when both records are seen,
  paired by file reference number. Unpaired renames still show `(renamed to) …`.
- **Process metadata:** a later failed lookup no longer erases fields an earlier
  lookup filled in.
- **DNS:** transient failures (timeouts) are not cached; a later event retries.
  Definitive answers are cached, with a size bound.
- **Process info:** only useful results are cached, so an access-denied PID is
  retried. The 64-bit command-line offsets are used only for native 64-bit
  targets; 32-bit and WOW64 processes are skipped instead of read as garbage.
- **Service names:** the service list is cached for 5 s, as the header describes.
- **Watcher failures:** when a watcher thread stops on its own, the status shows a
  warning and the monitor state changes to "Failed" once every source has gone.
  A deliberate Stop is not reported as a failure.
- **Stop:** all watchers are asked to stop together, then waited on once, instead
  of sequentially (worst case was about 18 s of frozen UI).
- **Session handles:** the ETW session and consumer handles are guarded by a mutex
  shared by the worker thread and Stop, so each handle is closed exactly once.
- **Process reuse:** a PID that now belongs to a different executable is treated
  as one process stopping and another starting.
- **Connection dedupe:** the connection key includes the owning PID, so two
  processes on the same local address are both reported.
- **Log loading:** the file is parsed before the current log is replaced. Unknown
  event types are reported and skipped instead of being loaded as File Write.
- **Dead settings removed:** `maxEventsInMemory` (never read). `circularLogMaxBytes`
  is now honoured.

## Performance
- **Circular log:** one file handle is held open for the session, instead of
  opening and closing the file for every event. The size cap comes from settings.
- **Hostname and process-info results:** applied in one pass per 250 ms tick,
  instead of one full table scan per result.
- **Process tree:** rebuilt only when the log has changed (revision counter), not
  every 2 seconds regardless.
- **Process name lookups:** one lookup per PID per poll in the TCP and UDP tables,
  instead of one per row.

## Safety
- **Regex filters:** patterns with nested repetition, such as `(a+)+`, and very
  long patterns are refused, because they can freeze the UI on the GUI thread.
  This is a heuristic, not a full ReDoS guarantee. Validation and matching now use
  the same case-insensitivity.

## New feature: per-process timeline
Open a process's events window (double-click a process in the tree, or right-click
→ Open events window). The window now has two tabs:
- **Events** (unchanged): the flat list, with the optional sub-process view and CSV
  export.
- **Timeline**: lifetime ("ran 2m 10s (10:00:00 – 10:02:10)" or "running since …"),
  a count per activity type, every event in time order, a parent line in the
  tooltip, and the child processes (oldest first, with event counts and running
  state). Double-click a child to open its timeline.

The rules live in `ProcessTimeline.cpp`, which has no GUI or Windows dependency.
The timeline is rebuilt only while its tab is showing and the log has changed.

## Known limitations (not fixed)
- A DNS server that never answers can still hold up the single resolver thread,
  because the Qt lookup has no per-call timeout. Fixing this needs asynchronous
  Windows resolution (`GetAddrInfoExW` with a timeout).
- PID reuse is detected by executable name. A reuse that keeps the same name is
  still merged.
- Registry tracing at all keywords, verbose, system-wide is still expensive. It is
  off by default.
- Private and multicast addresses are still sent to DNS. This is a design choice
  and is not yet a setting.
- USN-only events (no PID) are excluded whenever a process-name filter is set.

## Manual verification checklist (Windows, Qt 5.15 and Qt 6)
1. Clean configure and build with no warnings, on both Qt versions.
2. Start as a standard user: file watching of a chosen folder still works.
3. Start as administrator: ETW capture starts; status reads "Monitoring started…"
   and then "ETW active…" only after a watcher reports in.
4. Force a watcher to fail (e.g. a second instance holding the session name). The
   status shows a WARNING and the monitor state shows "● Failed".
5. Stop: the window stays responsive; Stop completes in a few seconds at most.
6. Rename a file in a watched folder: the event reads `old -> new`.
7. Open a process's window → Timeline tab: lifetime, counts, events in order, and
   children appear; double-click a child opens its window.
8. Enter `(a+)+` as a column filter: it is refused with a clear message.
9. Load a log containing an unknown event type: the warning shows the skipped count.
