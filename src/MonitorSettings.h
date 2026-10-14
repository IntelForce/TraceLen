#pragma once
// ============================================================
// MonitorSettings.h  —  All user-configurable monitoring options
// ============================================================
#include <QStringList>

struct MonitorSettings
{
    // File event toggles
    // Note: trackFileOpen and trackFileRead require ETW (Event Tracing
    // for Windows) which needs Administrator rights. ReadDirectoryChangesW
    // cannot tell us WHO opened/read a file — only that it changed.
    bool trackFileOpen   = false;  // Disabled — requires ETW
    bool trackFileRead   = false;  // Disabled — requires ETW
    bool trackFileWrite  = true;
    bool trackFileDelete = true;
    bool trackFileRename = true;

    // Network event toggles
    bool trackNetConnect = true;
    bool trackNetListen  = true;

    // Process event toggles
    bool trackProcStart  = true;
    bool trackProcStop   = true;

    // DNS resolution (runs in DnsResolver background thread) — our OWN
    // reverse lookups on IPs already seen in Net Connect events.
    bool resolveIPs = false;

    // ---- Registry event toggles ----
    // ETW (Microsoft-Windows-Kernel-Registry), requires Administrator.
    // Default off: registry activity is very high-volume on a live system.
    bool trackRegistryCreateKey   = false;
    bool trackRegistrySetValue    = false;
    bool trackRegistryDeleteValue = false;
    bool trackRegistryDeleteKey   = false;
    bool trackRegistryRenameKey   = false;

    // ---- DNS query toggle ----
    // ETW (Microsoft-Windows-DNS-Client), requires Administrator. Captures
    // the DOMAIN NAME each process asks Windows to resolve (+ the result,
    // when available). This is a genuine query-content tap, unlike the
    // Net Connect/Net Listen events, which only ever see IP:port and cannot
    // see UDP/53 DNS traffic at all (GetExtendedUdpTable has no remote
    // address). Default off because every process makes DNS calls
    // constantly.
    bool trackDnsQuery = false;

    // ---- File existence / attribute query toggle ----
    // ETW (Microsoft-Windows-Kernel-File QueryInformation), requires
    // Administrator. CAVEAT: only catches queries made through an
    // already-open file handle (NtQueryInformationFile). Bare existence
    // checks like GetFileAttributesW()/PathFileExists(), which use
    // NtQueryAttributesFile without ever opening a handle, are invisible
    // to ETW entirely — only a kernel minifilter driver (what Sysinternals
    // TraceLen uses) can see those. Default off: very high-volume.
    bool trackFileQuery = false;

    // ---- Event-driven network toggle ----
    // ETW (Microsoft-Windows-Kernel-Network), requires Administrator.
    // The existing trackNetConnect/trackNetListen above come from
    // SystemMonitor polling GetExtendedTcpTable/GetExtendedUdpTable on a
    // timer — a SNAPSHOT of what's connected at each tick. A connection
    // that opens and closes entirely between two ticks (a single short
    // HTTP request, exactly what a lot of beaconing malware looks like)
    // is invisible to that approach; it never appears in either snapshot.
    // This is the real-time alternative: the kernel tells us the instant a
    // connection opens or closes, so nothing in between is missed, and we
    // get a genuine open/close pair with exact timestamps instead of just
    // "it was connected at the moment I happened to look."
    // Left as an independent opt-in rather than replacing the polling
    // path — SystemMonitor's polling needs no admin rights and is cheap,
    // so it stays the default; this is for when you need the extra
    // fidelity and are already running elevated for the other ETW
    // features. Running both at once will show the same connection twice
    // (once from each source) — that's expected, not a bug.
    bool trackNetConnectLive    = false;
    bool trackNetDisconnectLive = false;

    // Watched directories for ReadDirectoryChangesW.
    // GOOD directories to watch:
    //   C:\Users\YourName\Desktop      — see events when you work on Desktop
    //   C:\Users\YourName\Documents    — common file activity
    //   C:\Temp                        — many apps write temporary files here
    // AVOID for beginners:
    //   C:\Windows\System32            — too much system activity, buffer overflows
    QStringList watchedDirectories;   // Empty by default — user must add one

    // Show only events from processes whose name contains this string
    // (case-insensitive). Empty = show all processes.
    QString processNameFilter = "";

    // ---- Capture-time path filters (applied before the event is logged) ----
    // If pathIncludePrefixes is non-empty, a file/registry path must match
    // at least one prefix (case-insensitive startsWith) to be kept.
    // pathExcludePrefixes always drops matching paths.
    // Empty include list = allow all (then excludes still apply).
    QStringList pathIncludePrefixes;
    QStringList pathExcludePrefixes;

    // When true, file/registry events with Status == success are still shown;
    // when false is not used — prefer showing status in the Details text.
    // hideSuccessfulOps: if true, only emit ops whose status is non-zero (failures).
    bool hideSuccessfulOps = false;

    // Circular JSONL backup on disk (not a native .etl; same idea: loop file
    // so the UI can drop rows but history remains recoverable).
    bool circularLogEnabled = false;
    QString circularLogPath;          // empty → <appDir>/TraceLen_events.jsonl
    int circularLogMaxBytes = 50 * 1024 * 1024;  // 50 MB default

    // How often SystemMonitor checks for new processes + connections (ms)
    int pollIntervalMs = 1000;

    // (In-memory event caps are kept in ActivityLog::MAX_EVENTS and
    //  MainWindow kMaxTableRows; they are not user-configurable.)

    // Returns true if `path` should be kept given include/exclude prefixes.
    bool pathPassesCaptureFilter(const QString& path) const
    {
        if (path.isEmpty()) return true;
        const QString p = path;
        for (const QString& ex : pathExcludePrefixes) {
            if (!ex.isEmpty() && p.startsWith(ex, Qt::CaseInsensitive))
                return false;
        }
        if (pathIncludePrefixes.isEmpty()) return true;
        for (const QString& in : pathIncludePrefixes) {
            if (!in.isEmpty() && p.startsWith(in, Qt::CaseInsensitive))
                return true;
        }
        return false;
    }
};
