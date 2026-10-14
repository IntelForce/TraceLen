#pragma once

// ============================================================
// ActivityEvent.h  —  Core event data structure
// ============================================================
// IMPORTANT — Why PascalCase enum values?
// Windows SDK headers #define FILE_OPEN, FILE_WRITE, etc. as
// numeric macros.  The C preprocessor replaces those names in
// our enum BEFORE the compiler runs, turning enum values into
// raw numbers and causing compile errors.  PascalCase names
// (FileOpen, FileWrite…) never conflict with Windows macros.
// ============================================================

#include <QString>
#include <QDateTime>

struct ActivityEvent
{
    // ---- Event type ----
    enum class Type
    {
        FileOpen,       // A file was opened (ETW only, requires admin)
        FileRead,       // A file was read   (ETW only, requires admin)
        FileWrite,      // A file was written or created
        FileDelete,     // A file was deleted
        FileRename,     // A file was renamed or moved
        NetConnect,     // A TCP connection was established
        NetListen,      // A process is listening on a port
        ProcStart,      // A new process started
        ProcStop,       // A process exited

        // ---- Registry (ETW Kernel-Registry, requires admin) ----
        RegistryCreateKey,   // A registry key was created (or opened-and-created)
        RegistrySetValue,    // A registry value was written
        RegistryDeleteValue, // A registry value was deleted
        RegistryDeleteKey,   // A registry key was deleted
        RegistryRenameKey,   // A registry key was renamed

        // ---- DNS (ETW DNS-Client, requires admin) ----
        // NOTE: this is a resolved DOMAIN NAME a process asked Windows to look
        // up (via the DNS-Client ETW provider). It is unrelated to
        // `resolveIPs`/DnsResolver, which does our own reverse lookups on IPs
        // already seen in Net Connect events.
        DnsQuery,

        // ---- File existence / attribute query (ETW Kernel-File, requires admin) ----
        // CAVEAT: only sees queries made through an already-open file handle
        // (NtQueryInformationFile). Calls like GetFileAttributesW(), which use
        // NtQueryAttributesFile and never open a handle, are invisible here —
        // see FileWatcher.h and README for details.
        FileQuery,

        // ---- Event-driven network (ETW Kernel-Network, requires admin) ----
        // Unlike NetConnect/NetListen above (polled snapshots from
        // SystemMonitor — see the trackNetConnectLive comment in
        // MonitorSettings.h for why that misses short-lived connections),
        // these come from the kernel the instant a connection opens/closes.
        NetConnectLive,
        NetDisconnectLive,
    };

    // ---- Core fields (always populated) ----
    Type      type;
    int       pid         = 0;
    int       parentPid   = 0;
    QString   processName;
    QString   parentProcessName;
    QString   details;
    QDateTime timestamp;

    // ---- Network extra ----
    QString   hostname;     // Resolved hostname (filled by DnsResolver)

    // ---- DNS server (DNS-Client events 3010/3011 when available) ----
    QString   dnsServer;    // e.g. 8.8.8.8 — which resolver was queried

    // ---- Operation result (file / registry) when the provider reports it ----
    QString   operationStatus;  // "OK", "FAILED: ACCESS_DENIED", etc.

    // ---- Process metadata (filled by ProcessInfoWorker) ----
    QString   fullPath;     // C:\Windows\System32\notepad.exe
    QString   publisher;    // Microsoft Corporation (CompanyName string — NOT verified, just a text
                            // field embedded in the file; a forged binary can claim anything here)
    QString   signatureStatus;  // "Verified", "Unsigned", "Untrusted", etc. — a REAL Authenticode
                            // check via WinVerifyTrust, see ProcessInfoWorker::getSignatureInfo()
    QString   fileVersion;  // 10.0.22621.1
    QString   serviceName;  // WSearch  (empty if not a service)
    QString   commandLine;  // notepad.exe C:\Users\a\test.txt
    QString   userName;     // Account that owns the process: DOMAIN\name (empty = not read)

    // ---- Helpers ----
    bool isNetworkEvent() const
    { return type == Type::NetConnect || type == Type::NetListen; }

    static QString typeToString(Type t)
    {
        switch (t) {
            case Type::FileOpen:   return "File Open";
            case Type::FileRead:   return "File Read";
            case Type::FileWrite:  return "File Write";
            case Type::FileDelete: return "File Delete";
            case Type::FileRename: return "File Rename";
            case Type::NetConnect: return "Net Connect";
            case Type::NetListen:  return "Net Listen";
            case Type::ProcStart:  return "Proc Start";
            case Type::ProcStop:   return "Proc Stop";
            case Type::RegistryCreateKey:   return "Reg Create Key";
            case Type::RegistrySetValue:    return "Reg Set Value";
            case Type::RegistryDeleteValue: return "Reg Delete Value";
            case Type::RegistryDeleteKey:   return "Reg Delete Key";
            case Type::RegistryRenameKey:   return "Reg Rename Key";
            case Type::DnsQuery:            return "DNS Query";
            case Type::FileQuery:           return "File Query";
            case Type::NetConnectLive:      return "Net Connect (live)";
            case Type::NetDisconnectLive:   return "Net Disconnect (live)";
            default:               return "Unknown";
        }
    }

    static QString typeToColor(Type t)
    {
        switch (t) {
            case Type::FileOpen:   return "#E3F2FD";
            case Type::FileRead:   return "#E8F5E9";
            case Type::FileWrite:  return "#FFF3E0";
            case Type::FileDelete: return "#FFEBEE";
            case Type::FileRename: return "#F3E5F5";
            case Type::NetConnect: return "#E0F7FA";
            case Type::NetListen:  return "#E0F2F1";
            case Type::ProcStart:  return "#F1F8E9";
            case Type::ProcStop:   return "#FBE9E7";
            case Type::RegistryCreateKey:   return "#EDE7F6";
            case Type::RegistrySetValue:    return "#D1C4E9";
            case Type::RegistryDeleteValue: return "#E1BEE7";
            case Type::RegistryDeleteKey:   return "#F8BBD0";
            case Type::RegistryRenameKey:   return "#D7CCC8";
            case Type::DnsQuery:            return "#B2EBF2";
            case Type::FileQuery:           return "#FFF9C4";
            case Type::NetConnectLive:      return "#B3E5FC";
            case Type::NetDisconnectLive:   return "#CFD8DC";
            default:               return "#FAFAFA";
        }
    }

    // Returns false (and leaves `out` untouched) for an unrecognised string,
    // so a corrupt or newer log file is not silently reloaded as File Write.
    static bool tryTypeFromString(const QString& s, Type& out)
    {
        for (int i = 0; i <= static_cast<int>(Type::NetDisconnectLive); ++i) {
            const Type t = static_cast<Type>(i);
            if (typeToString(t) == s) { out = t; return true; }
        }
        return false;
    }

    // Lenient variant for display code: unknown strings fall back to FileWrite.
    static Type typeFromString(const QString& s)
    {
        Type t = Type::FileWrite;
        tryTypeFromString(s, t);
        return t;
    }

};
