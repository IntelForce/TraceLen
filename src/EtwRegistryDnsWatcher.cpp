// ============================================================
// EtwRegistryDnsWatcher.cpp — Kernel-Registry + DNS-Client ETW
// ============================================================
// See the header for the overall design. Summary:
//   * One real-time ETW session ("TraceLen_RegDns"), same mechanics
//     as EtwFileWatcher (StartTraceW / EnableTraceEx2 / OpenTraceW /
//     ProcessTrace), kept separate from the file watcher's session so a
//     bug here can't affect file/process monitoring.
//   * Providers enabled at VERBOSE + all keywords. Events classified
//     primarily by EventDescriptor.Id (registry 1/2/3/5/6, DNS 3008/…)
//     with Task-name fallback. DNS filters out dual-stack AAAA noise.
//   * Registry key paths are resolved the same way file paths are in
//     EtwFileWatcher: a KeyObject -> path table built from Create/Open
//     events, since most operation events only carry the KeyObject
//     pointer, not a ready-made path.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <wmistr.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "EtwRegistryDnsWatcher.h"
#include <QMutexLocker>
#include <QDateTime>
#include <QFileInfo>
#include <QHash>
#include <QString>
#include <vector>
#include <cstring>
#include <initializer_list>

static EtwRegistryDnsWatcher* g_regDnsInstance = nullptr;

// Microsoft-Windows-Kernel-Registry
static const GUID KernelRegistryProviderGuid =
    {0x70eb4f03, 0xc1de, 0x4f73, {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};
// Microsoft-Windows-DNS-Client
static const GUID DnsClientProviderGuid =
    {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
// Microsoft-Windows-Kernel-Network — real-time TCP/UDP connect/disconnect,
// with PID. Field names below (daddr/saddr/dport/sport) and the assumption
// that the address fields are network-byte-order are my best-documented
// understanding, NOT independently verified on-machine — this is the one
// part of this file most likely to need a tweak after testing. If
// addresses come out byte-reversed, the fix is flipping ipv4FieldToString
// between network- and host-byte-order interpretation.
static const GUID KernelNetworkProviderGuid =
    {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

static const wchar_t* SESSION_NAME = L"TraceLen_RegDns";

// Coalescing windows (ms) — registry SetValueKey in particular can be very
// chatty (MRU lists, cursor-position caches, etc.).
static const ULONGLONG kCoalesceRegMs = 500;
static const ULONGLONG kCoalesceDnsMs = 2000;

static const size_t kMaxTrackedKeys = 100000;

namespace {

// ------------------------------------------------------------
// TDH in-types (same numeric meanings as EtwFileWatcher.cpp; duplicated
// here so this file has no dependency on it).
// ------------------------------------------------------------
enum : USHORT {
    IT_USTR = 1, IT_ASTR = 2, IT_I8 = 3, IT_U8 = 4, IT_I16 = 5, IT_U16 = 6,
    IT_I32 = 7, IT_U32 = 8, IT_I64 = 9, IT_U64 = 10, IT_FLOAT = 11,
    IT_DOUBLE = 12, IT_BOOL = 13, IT_GUID = 15, IT_PTR = 16,
    IT_FILETIME = 17, IT_SYSTIME = 18, IT_HEX32 = 20, IT_HEX64 = 21,
    IT_SIZET = 30
};
const DWORD kComplexPropFlags = 0x1 | 0x2 | 0x4 | 0x10 | 0x20;

// Decodes one event's UserData into name->value maps using the provider's
// own manifest (TDH), plus the event's Task name (e.g. "SetValueKey").
// Returns false only if TDH has no schema for this event at all.
//
// Unlike the earlier version, this walker *skips* binary / complex /
// counted fields instead of aborting, so later simple fields (and a
// best-effort capture of CapturedData when it looks like a string) are
// still recovered. That is required for SetValueKey events, which place
// Type / DataSize / CapturedData after the key/value names.
bool decodeNamedFields(PEVENT_RECORD rec, QHash<QString, QString>& strOut,
                       QHash<QString, quint64>& intOut, QString& taskName,
                       QByteArray* binaryOut = nullptr,
                       QString* binaryFieldName = nullptr)
{
    ULONG size = 0;
    ULONG st = TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
    if (st != ERROR_INSUFFICIENT_BUFFER || size == 0) return false;
    std::vector<BYTE> buf(size);
    PTRACE_EVENT_INFO info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
    st = TdhGetEventInformation(rec, 0, nullptr, info, &size);
    if (st != ERROR_SUCCESS) return false;

    if (info->TaskNameOffset)
        taskName = QString::fromWCharArray(
            reinterpret_cast<const WCHAR*>(buf.data() + info->TaskNameOffset));

    const BYTE* p   = static_cast<const BYTE*>(rec->UserData);
    const BYTE* end = p + rec->UserDataLength;
    const size_t ptrSize =
        (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    // When a prior property named *Size / CapturedDataSize gave us a length,
    // use it to consume the following binary blob instead of stopping.
    quint64 pendingBinaryLen = 0;
    QString pendingBinaryName;

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        if (p >= end) break;
        const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        const WCHAR* nameW = reinterpret_cast<const WCHAR*>(buf.data() + prop.NameOffset);
        const QString name = QString::fromWCharArray(nameW).toLower();
        const bool isComplex = (prop.Flags & kComplexPropFlags) != 0 || prop.count > 1;
        const USHORT t = prop.nonStructType.InType;
        size_t sz = 0;

        // Binary / counted / struct fields: if we know the length from a
        // previous *Size property, consume that many bytes; otherwise try
        // a best-effort length from the property descriptor and skip.
        if (isComplex || t == 14 /* BINARY */ || t == 0 /* unknown */) {
            size_t binLen = 0;
            if (pendingBinaryLen > 0 &&
                (name.contains(QLatin1String("data")) ||
                 name.contains(QLatin1String("captured")))) {
                binLen = static_cast<size_t>(pendingBinaryLen);
            } else if (prop.length > 0 && prop.length < 0x10000) {
                binLen = prop.length;
            }
            if (binLen > 0 && static_cast<size_t>(end - p) >= binLen) {
                if (binaryOut && binaryOut->isEmpty() &&
                    (name.contains(QLatin1String("data")) ||
                     name.contains(QLatin1String("captured")))) {
                    *binaryOut = QByteArray(reinterpret_cast<const char*>(p),
                                            static_cast<int>(binLen));
                    if (binaryFieldName) *binaryFieldName = name;
                }
                p += binLen;
            }
            // Even if we couldn't size it, do not abort — later fields may
            // still be simple scalars we care about. Reset pending length.
            pendingBinaryLen = 0;
            pendingBinaryName.clear();
            continue;
        }

        if (t == IT_USTR) {
            const size_t maxc = static_cast<size_t>(end - p) / 2;
            const WCHAR* w = reinterpret_cast<const WCHAR*>(p);
            size_t n = 0;
            while (n < maxc && w[n]) ++n;
            strOut.insert(name, QString::fromWCharArray(w, static_cast<int>(n)));
            sz = (n < maxc) ? (n + 1) * 2 : n * 2;
            p += sz;
            pendingBinaryLen = 0;
            continue;
        }
        if (t == IT_ASTR) {
            const size_t maxc = static_cast<size_t>(end - p);
            size_t n = 0;
            while (n < maxc && p[n]) ++n;
            strOut.insert(name, QString::fromLatin1(
                reinterpret_cast<const char*>(p), static_cast<int>(n)));
            sz = (n < maxc) ? n + 1 : n;
            p += sz;
            pendingBinaryLen = 0;
            continue;
        }
        switch (t) {
        case IT_I8:  case IT_U8:                                   sz = 1; break;
        case IT_I16: case IT_U16:                                  sz = 2; break;
        case IT_I32: case IT_U32: case IT_HEX32:
        case IT_BOOL: case IT_FLOAT:                               sz = 4; break;
        case IT_I64: case IT_U64: case IT_HEX64:
        case IT_DOUBLE: case IT_FILETIME:                          sz = 8; break;
        case IT_PTR: case IT_SIZET:                                sz = ptrSize; break;
        case IT_GUID: case IT_SYSTIME:                             sz = 16; break;
        default:
            // Unknown in-type — try to keep going with a 4-byte guess rather
            // than aborting the whole event.
            sz = 4;
            break;
        }
        if (static_cast<size_t>(end - p) < sz) return true;
        if (t != IT_GUID && t != IT_SYSTIME) {
            quint64 v = 0;
            std::memcpy(&v, p, sz > 8 ? 8 : sz);
            intOut.insert(name, v);
            // Remember size fields so the following binary blob can be consumed.
            if (name.endsWith(QLatin1String("size")) ||
                name.contains(QLatin1String("captureddatasize")) ||
                name == QLatin1String("datasize") ||
                name == QLatin1String("length")) {
                pendingBinaryLen = v;
                pendingBinaryName = name;
            }
        }
        p += sz;
    }
    return true;
}

// REG_* type → short label for the details column.
QString regTypeToString(quint64 t)
{
    switch (t) {
    case 0:  return QStringLiteral("REG_NONE");
    case 1:  return QStringLiteral("REG_SZ");
    case 2:  return QStringLiteral("REG_EXPAND_SZ");
    case 3:  return QStringLiteral("REG_BINARY");
    case 4:  return QStringLiteral("REG_DWORD");
    case 5:  return QStringLiteral("REG_DWORD_BE");
    case 6:  return QStringLiteral("REG_LINK");
    case 7:  return QStringLiteral("REG_MULTI_SZ");
    case 8:  return QStringLiteral("REG_RESOURCE_LIST");
    case 11: return QStringLiteral("REG_QWORD");
    default: return QStringLiteral("type %1").arg(t);
    }
}

// Best-effort human-readable preview of a SetValue data blob.
// Truncates long values so the Activity table stays readable.
QString formatRegValueData(quint64 regType, const QByteArray& data)
{
    if (data.isEmpty()) return QString();
    const int kMaxChars = 120;

    auto trunc = [&](QString s) -> QString {
        if (s.size() > kMaxChars)
            return s.left(kMaxChars) + QStringLiteral("…");
        return s;
    };

    // REG_SZ / REG_EXPAND_SZ / REG_LINK — UTF-16LE, often null-terminated.
    if (regType == 1 || regType == 2 || regType == 6) {
        const int wcharCount = data.size() / 2;
        if (wcharCount > 0) {
            const WCHAR* w = reinterpret_cast<const WCHAR*>(data.constData());
            int n = 0;
            while (n < wcharCount && w[n]) ++n;
            return trunc(QString::fromWCharArray(w, n));
        }
    }
    // REG_MULTI_SZ — sequence of null-terminated UTF-16 strings.
    if (regType == 7) {
        QStringList parts;
        const WCHAR* w = reinterpret_cast<const WCHAR*>(data.constData());
        const int wcharCount = data.size() / 2;
        int i = 0;
        while (i < wcharCount) {
            if (w[i] == 0) { ++i; continue; }
            int start = i;
            while (i < wcharCount && w[i]) ++i;
            parts.append(QString::fromWCharArray(w + start, i - start));
            if (parts.join(QLatin1Char(';')).size() > kMaxChars) break;
        }
        return trunc(parts.join(QLatin1Char(';')));
    }
    // REG_DWORD
    if (regType == 4 && data.size() >= 4) {
        quint32 v = 0;
        std::memcpy(&v, data.constData(), 4);
        return QStringLiteral("0x%1 (%2)").arg(v, 8, 16, QLatin1Char('0')).arg(v);
    }
    // REG_QWORD
    if (regType == 11 && data.size() >= 8) {
        quint64 v = 0;
        std::memcpy(&v, data.constData(), 8);
        return QStringLiteral("0x%1").arg(v, 16, 16, QLatin1Char('0'));
    }
    // Binary / unknown — short hex dump.
    QString hex;
    const int show = qMin(data.size(), 24);
    for (int i = 0; i < show; ++i)
        hex += QString("%1").arg(static_cast<unsigned char>(data[i]), 2, 16, QLatin1Char('0'));
    if (data.size() > show) hex += QStringLiteral("…");
    return QStringLiteral("(%1 bytes) %2").arg(data.size()).arg(hex);
}

// First present key among a set of candidate field names.
QString firstOf(const QHash<QString, QString>& m, std::initializer_list<const char*> names)
{
    for (const char* n : names) {
        auto it = m.constFind(QString::fromLatin1(n));
        if (it != m.constEnd() && !it.value().isEmpty()) return it.value();
    }
    return QString();
}

// ------------------------------------------------------------
// Registry: \REGISTRY\MACHINE\... -> HKLM\...  (best effort, like
// EtwFileWatcher's ntPathToWin32 for files).
// Also promotes common relative paths (Software\..., SYSTEM\...) to a
// plausible hive so rows are not left looking like bare relative names.
// ------------------------------------------------------------
QString ntRegPathToWin32(const QString& in)
{
    static const QString kMachine = QStringLiteral("\\REGISTRY\\MACHINE");
    static const QString kUser    = QStringLiteral("\\REGISTRY\\USER");
    static const QString kRoot    = QStringLiteral("\\REGISTRY\\");
    if (in.startsWith(kMachine, Qt::CaseInsensitive))
        return QStringLiteral("HKLM") + in.mid(kMachine.length());
    if (in.startsWith(kUser, Qt::CaseInsensitive)) {
        // \REGISTRY\USER\<SID>\...  →  HKU\<SID>\...
        // Common case: current user SID → show as HKCU when possible is hard
        // without looking up the SID; keep HKU which is always correct.
        return QStringLiteral("HKU") + in.mid(kUser.length());
    }
    if (in.startsWith(kRoot, Qt::CaseInsensitive))
        return in.mid(kRoot.length());

    // Already a friendly hive prefix?
    if (in.startsWith(QLatin1String("HKLM"), Qt::CaseInsensitive) ||
        in.startsWith(QLatin1String("HKCU"), Qt::CaseInsensitive) ||
        in.startsWith(QLatin1String("HKU"),  Qt::CaseInsensitive) ||
        in.startsWith(QLatin1String("HKCR"), Qt::CaseInsensitive) ||
        in.startsWith(QLatin1String("HKCC"), Qt::CaseInsensitive))
        return in;

    // A relative name with no known parent key does NOT tell us which hive it
    // lives in: "Software\\X" could be HKLM\\SOFTWARE (machine-wide) or
    // HKCU\\Software (per-user). Guessing made machine-wide changes look like
    // single-user changes, so we no longer guess. The name is shown with an
    // explicit marker instead.
    return QStringLiteral("(hive unknown) ") + in;
}

enum class RegOp { Other, CreateKey, OpenKey, DeleteKey, SetValueKey, DeleteValueKey, RenameKey };

// Prefer Event ID (stable across Windows builds). Task-name fallback is kept
// for older manifests or when TDH reports a useful Task string.
// IDs from the Kernel-Registry provider (see Velociraptor / Message Analyzer):
//   1 CreateKey, 2 OpenKey, 3 DeleteKey, 4 QueryKey,
//   5 SetValueKey, 6 DeleteValueKey, 7 QueryValue, ...
RegOp classifyRegEvent(USHORT eventId, const QString& taskName)
{
    switch (eventId) {
    case 1:  return RegOp::CreateKey;
    case 2:  return RegOp::OpenKey;
    case 3:  return RegOp::DeleteKey;
    case 5:  return RegOp::SetValueKey;
    case 6:  return RegOp::DeleteValueKey;
    // 7 = QueryValue, 4 = QueryKey — intentionally ignored (too noisy)
    default: break;
    }
    const QString t = taskName.toLower();
    if (t.contains(QLatin1String("deletevalue"))) return RegOp::DeleteValueKey;
    if (t.contains(QLatin1String("setvalue")))    return RegOp::SetValueKey;
    if (t.contains(QLatin1String("rename")))      return RegOp::RenameKey;
    if (t.contains(QLatin1String("deletekey")) ||
        (t.contains(QLatin1String("delete")) && !t.contains(QLatin1String("value"))))
        return RegOp::DeleteKey;
    if (t.contains(QLatin1String("createkey")) || t == QLatin1String("create"))
        return RegOp::CreateKey;
    if (t.contains(QLatin1String("openkey")) || t == QLatin1String("open"))
        return RegOp::OpenKey;
    return RegOp::Other;
}

enum class NetOp { Other, Connect, Disconnect, UdpSend, UdpRecv };

// Prefer stable Event IDs from Microsoft-Windows-Kernel-Network:
//   10 DataSent (TCP), 11 DataReceived (TCP),
//   12 ConnectionAttempted, 13 Disconnect, 15 ConnectionAccepted,
//   42 DataSentOverUDPProtocol, 43 DataReceivedOverUDPProtocol
// Task-name fallback kept for older manifests.
NetOp classifyNetEvent(USHORT eventId, const QString& taskName)
{
    switch (eventId) {
    case 12: case 15: return NetOp::Connect;      // attempt / accept
    case 13:          return NetOp::Disconnect;
    case 42:          return NetOp::UdpSend;
    case 43:          return NetOp::UdpRecv;
    // 10/11 are per-packet TCP data — too noisy; ignore
    default: break;
    }
    const QString t = taskName.toLower();
    if (t.contains(QLatin1String("disconnect"))) return NetOp::Disconnect;
    if (t.contains(QLatin1String("connect")))    return NetOp::Connect;
    if (t.contains(QLatin1String("accept")))     return NetOp::Connect;
    if (t.contains(QLatin1String("udpsend")) ||
        t.contains(QLatin1String("datasentoverudp"))) return NetOp::UdpSend;
    if (t.contains(QLatin1String("udprecv")) ||
        t.contains(QLatin1String("datareceivedoverudp"))) return NetOp::UdpRecv;
    return NetOp::Other;
}

// Kernel-Network daddr/saddr are 32-bit IPv4 in network byte order
// (big-endian octets). Ports are also network byte order (uint16).
QString ipv4FieldToString(quint32 addr)
{
    return QString("%1.%2.%3.%4")
        .arg((addr >> 24) & 0xFF).arg((addr >> 16) & 0xFF)
        .arg((addr >> 8) & 0xFF).arg(addr & 0xFF);
}

// Port from a TDH-decoded named field. TDH converts UINT16 fields to host
// byte order before handing them to us, so the value is used as-is. (The
// raw MOF blob is different: it stores ports in network order, which
// parseKernelNetworkMof converts exactly once.) Do NOT swap here: that was
// the bug that turned port 53 into 13568 on the fallback path.
quint16 portFromField(quint64 raw)
{
    return static_cast<quint16>(raw & 0xFFFF);
}

// DNS-Client's QueryStatus is a Win32 error code (NOT an NTSTATUS — a
// completely different numbering scheme from the file-query status codes
// in EtwFileWatcher.cpp). Common ones, since the raw number alone isn't
// self-explanatory.
QString dnsStatusToString(quint64 status)
{
    switch (status) {
        case 87:    return QStringLiteral("invalid parameter");
        case 1223:  return QStringLiteral("cancelled");
        case 1460:  return QStringLiteral("timeout");
        case 9001:  return QStringLiteral("format error (RCODE)");
        case 9002:  return QStringLiteral("server failure (RCODE)");
        case 9003:  return QStringLiteral("name does not exist (NXDOMAIN)");
        case 9004:  return QStringLiteral("not implemented (RCODE)");
        case 9005:  return QStringLiteral("refused (RCODE)");
        case 9501:  return QStringLiteral("no records of the requested type");
        case 9701:  return QStringLiteral("record does not exist");
        case 9705:  return QStringLiteral("record timed out");
        case 10054: return QStringLiteral("connection reset by peer");
        case 11001: return QStringLiteral("host not found");
        case 11002: return QStringLiteral("nonauthoritative, try again");
        case 11003: return QStringLiteral("non-recoverable error");
        case 11004: return QStringLiteral("no data of the requested type");
        default:    return QString("error %1").arg(status);
    }
}

QString dnsTypeToString(quint64 t)
{
    switch (t) {
        case 1:  return QStringLiteral("A");
        case 2:  return QStringLiteral("NS");
        case 5:  return QStringLiteral("CNAME");
        case 6:  return QStringLiteral("SOA");
        case 12: return QStringLiteral("PTR");
        case 15: return QStringLiteral("MX");
        case 16: return QStringLiteral("TXT");
        case 28: return QStringLiteral("AAAA");
        case 33: return QStringLiteral("SRV");
        case 65: return QStringLiteral("HTTPS");
        default: return QStringLiteral("type %1").arg(t);
    }
}

// "Visible coalescing" suffix — see the comment on throttled() below.
QString coalesceSuffix(int suppressed)
{
    return suppressed > 0 ? QString("  (×%1 recently)").arg(suppressed + 1) : QString();
}

QString queryImageNameSimple(quint32 pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    const BOOL ok = QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    return ok ? QFileInfo(QString::fromWCharArray(buf)).fileName() : QString();
}

} // namespace

// ============================================================
// All mutable ETW state
// ============================================================
struct EtwRegistryDnsWatcher::Impl
{
    QHash<quint64, QString> keyObjectPath;   // KeyObject -> resolved Win32-ish path
    struct ThrottleState { ULONGLONG lastTick = 0; int suppressedCount = 0; };
    QHash<QString, ThrottleState> lastEmit;  // dedupe/coalesce key -> state

    QMutex nameMutex;
    QHash<quint32, QString> procNames;
    ULONGLONG lastSnapshot = 0;

    quint32 selfPid = GetCurrentProcessId();

    void reset()
    {
        keyObjectPath.clear();
        lastEmit.clear();
        QMutexLocker l(&nameMutex);
        procNames.clear();
        lastSnapshot = 0;
        selfPid = GetCurrentProcessId();
    }

    void refreshSnapshotLocked()
    {
        lastSnapshot = GetTickCount64();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                procNames.insert(pe.th32ProcessID, QString::fromWCharArray(pe.szExeFile));
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    QString procName(quint32 pid)
    {
        if (pid == 0) return QStringLiteral("System Idle");
        if (pid == 4) return QStringLiteral("System");
        QMutexLocker l(&nameMutex);
        auto it = procNames.constFind(pid);
        if (it != procNames.constEnd()) return it.value();

        QString n = queryImageNameSimple(pid);
        if (n.isEmpty() && GetTickCount64() - lastSnapshot > 2000) {
            refreshSnapshotLocked();
            it = procNames.constFind(pid);
            if (it != procNames.constEnd()) return it.value();
        }
        if (n.isEmpty()) return QString("pid-%1").arg(pid);
        if (procNames.size() > 16384) procNames.clear();
        procNames.insert(pid, n);
        return n;
    }

    // "Visible coalescing" — see the matching comment in EtwFileWatcher.cpp.
    // suppressedOut, when provided, receives how many identical events were
    // swallowed since the last one actually shown.
    bool throttled(const QString& key, ULONGLONG windowMs, int* suppressedOut = nullptr)
    {
        const ULONGLONG now = GetTickCount64();
        auto it = lastEmit.find(key);
        if (it != lastEmit.end() && now - it.value().lastTick < windowMs) {
            ++it.value().suppressedCount;
            return true;
        }
        if (lastEmit.size() > 20000) {
            for (auto i = lastEmit.begin(); i != lastEmit.end();) {
                if (now - i.value().lastTick > 5000) i = lastEmit.erase(i); else ++i;
            }
            if (lastEmit.size() > 20000) lastEmit.clear();
        }
        if (suppressedOut) *suppressedOut = (it != lastEmit.end()) ? it.value().suppressedCount : 0;
        lastEmit.insert(key, ThrottleState{now, 0});
        return false;
    }
};

// ============================================================
// Registry event handling
// ============================================================
void EtwRegistryDnsWatcher::handleRegistryRecord(void* pRaw)
{
    PEVENT_RECORD rec = static_cast<PEVENT_RECORD>(pRaw);
    Impl& d = *m_d;

    MonitorSettings settings;
    { QMutexLocker lock(&m_settingsMutex); settings = m_settings; }

    const bool wantAny = settings.trackRegistryCreateKey || settings.trackRegistrySetValue ||
                         settings.trackRegistryDeleteValue || settings.trackRegistryDeleteKey ||
                         settings.trackRegistryRenameKey;
    if (!wantAny) return;   // nothing to do — don't even pay for TDH decode

    QHash<QString, QString> strs;
    QHash<QString, quint64> ints;
    QString taskName;
    QByteArray capturedData;
    QString capturedFieldName;
    if (!decodeNamedFields(rec, strs, ints, taskName, &capturedData, &capturedFieldName))
        return;

    const USHORT eventId = rec->EventHeader.EventDescriptor.Id;
    const RegOp op = classifyRegEvent(eventId, taskName);
    if (op == RegOp::Other) return;

    const quint64 keyObject  = ints.value(QStringLiteral("keyobject"), 0);
    const quint64 baseObject = ints.value(QStringLiteral("baseobject"), 0);
    const quint32 pid = rec->EventHeader.ProcessId;
    if (pid == d.selfPid) return;

    // Build the best path we can:
    //   1. Prefer an already-known full path for this KeyObject.
    //   2. Else prepend known BaseObject path + RelativeName.
    //   3. Else combine BaseName + RelativeName when both present.
    //   4. Fall back to any single name field.
    //   5. Last resort: KeyObject pointer.
    const QString baseName     = firstOf(strs, {"basename", "base"});
    const QString relativeName = firstOf(strs, {"relativename", "relative"});
    const QString keyName      = firstOf(strs, {"keyname", "objectname", "fullname", "name"});
    const QString valueName    = firstOf(strs, {"valuename", "value"});

    QString rawPath;
    if (!baseName.isEmpty() && !relativeName.isEmpty()) {
        if (relativeName.startsWith(QLatin1Char('\\')))
            rawPath = baseName + relativeName;
        else
            rawPath = baseName + QLatin1Char('\\') + relativeName;
    } else if (!keyName.isEmpty()) {
        rawPath = keyName;
    } else if (!relativeName.isEmpty()) {
        // Try to expand via BaseObject's known path.
        if (baseObject) {
            const QString basePath = d.keyObjectPath.value(baseObject);
            if (!basePath.isEmpty()) {
                if (relativeName.startsWith(QLatin1Char('\\')))
                    rawPath = basePath + relativeName;
                else
                    rawPath = basePath + QLatin1Char('\\') + relativeName;
            } else {
                rawPath = relativeName;
            }
        } else {
            rawPath = relativeName;
        }
    } else if (!baseName.isEmpty()) {
        rawPath = baseName;
    }

    QString resolvedPath = rawPath.isEmpty() ? QString() : ntRegPathToWin32(rawPath);

    // If we still only have a relative path and BaseObject is known, prepend.
    if (baseObject && !resolvedPath.isEmpty() &&
        !resolvedPath.startsWith(QLatin1String("HK"), Qt::CaseInsensitive) &&
        !resolvedPath.startsWith(QLatin1Char('\\'))) {
        const QString basePath = d.keyObjectPath.value(baseObject);
        if (!basePath.isEmpty()) {
            resolvedPath = basePath.endsWith(QLatin1Char('\\'))
                ? basePath + resolvedPath
                : basePath + QLatin1Char('\\') + resolvedPath;
        }
    }

    // Prefer a previously learned full path for this KeyObject.
    if (keyObject) {
        const QString known = d.keyObjectPath.value(keyObject);
        if (!known.isEmpty()) {
            if (resolvedPath.isEmpty() ||
                (resolvedPath.length() < known.length() &&
                 !resolvedPath.contains(QLatin1Char('\\')))) {
                resolvedPath = known;
            } else if (resolvedPath.length() >= known.length()) {
                d.keyObjectPath.insert(keyObject, resolvedPath);
            }
        } else if (!resolvedPath.isEmpty()) {
            if (static_cast<size_t>(d.keyObjectPath.size()) > kMaxTrackedKeys)
                d.keyObjectPath.clear();
            d.keyObjectPath.insert(keyObject, resolvedPath);
        }
    }
    // Also remember BaseObject path when we learn a good one for the child
    // (helps later SetValue events that only carry KeyObject).
    if (baseObject && !resolvedPath.isEmpty() &&
        resolvedPath.contains(QLatin1Char('\\'))) {
        // Store the parent portion if we can strip the relative leaf.
        if (!relativeName.isEmpty() && resolvedPath.endsWith(relativeName, Qt::CaseInsensitive)) {
            QString parent = resolvedPath.left(resolvedPath.length() - relativeName.length());
            while (parent.endsWith(QLatin1Char('\\'))) parent.chop(1);
            if (!parent.isEmpty())
                d.keyObjectPath.insert(baseObject, parent);
        }
    }

    if (resolvedPath.isEmpty())
        resolvedPath = keyObject
            ? QString("(key object 0x%1)").arg(keyObject, 0, 16)
            : QStringLiteral("(unknown key)");

    if (op == RegOp::OpenKey) return;   // correlation only — far too noisy to show

    // Value data (SetValue only): Type + best-effort preview of CapturedData.
    const quint64 regType = ints.value(QStringLiteral("type"),
                            ints.value(QStringLiteral("datatype"), 0));
    QString valuePreview;
    if (op == RegOp::SetValueKey && !capturedData.isEmpty()) {
        valuePreview = formatRegValueData(regType, capturedData);
    } else if (op == RegOp::SetValueKey && regType != 0) {
        // We got a Type but no data blob — still show the type.
        valuePreview = regTypeToString(regType);
    }

    ActivityEvent::Type type;
    QString details;
    bool wanted;
    switch (op) {
    case RegOp::CreateKey:
        type = ActivityEvent::Type::RegistryCreateKey;
        details = resolvedPath;
        wanted = settings.trackRegistryCreateKey;
        break;
    case RegOp::SetValueKey:
        type = ActivityEvent::Type::RegistrySetValue;
        details = resolvedPath;
        if (!valueName.isEmpty())
            details += QStringLiteral("  [") + valueName + QLatin1Char(']');
        if (regType != 0)
            details += QStringLiteral("  (") + regTypeToString(regType) + QLatin1Char(')');
        if (!valuePreview.isEmpty() && valuePreview != regTypeToString(regType))
            details += QStringLiteral("  = ") + valuePreview;
        wanted = settings.trackRegistrySetValue;
        break;
    case RegOp::DeleteValueKey:
        type = ActivityEvent::Type::RegistryDeleteValue;
        details = resolvedPath;
        if (!valueName.isEmpty())
            details += QStringLiteral("  [") + valueName + QLatin1Char(']');
        wanted = settings.trackRegistryDeleteValue;
        break;
    case RegOp::DeleteKey:
        type = ActivityEvent::Type::RegistryDeleteKey;
        details = resolvedPath;
        wanted = settings.trackRegistryDeleteKey;
        d.keyObjectPath.remove(keyObject);
        break;
    case RegOp::RenameKey:
        type = ActivityEvent::Type::RegistryRenameKey;
        details = QStringLiteral("(renamed to) ") + resolvedPath;
        wanted = settings.trackRegistryRenameKey;
        break;
    default:
        return;
    }
    if (!wanted) return;

    // Capture-time path include/exclude (same rules as file paths).
    if (!settings.pathPassesCaptureFilter(resolvedPath))
        return;

    // Registry Status is an NTSTATUS (0 = success).
    const quint64 regStatus = ints.value(QStringLiteral("status"), 0);
    if (settings.hideSuccessfulOps && regStatus == 0)
        return;

    QString statusText;
    if (regStatus == 0) {
        statusText = QStringLiteral("OK");
    } else {
        // Common registry NTSTATUS values
        const quint32 st = static_cast<quint32>(regStatus);
        switch (st) {
        case 0xC0000022: statusText = QStringLiteral("FAILED: ACCESS_DENIED"); break;
        case 0xC0000034: statusText = QStringLiteral("FAILED: OBJECT_NAME_NOT_FOUND"); break;
        case 0xC0000035: statusText = QStringLiteral("FAILED: OBJECT_NAME_COLLISION"); break;
        case 0xC000000D: statusText = QStringLiteral("FAILED: INVALID_PARAMETER"); break;
        case 0xC0000005: statusText = QStringLiteral("FAILED: ACCESS_VIOLATION"); break;
        default:
            statusText = QStringLiteral("FAILED: 0x%1").arg(st, 8, 16, QLatin1Char('0'));
            break;
        }
        details += QStringLiteral("  [") + statusText + QLatin1Char(']');
    }

    const QString procName = d.procName(pid);
    if (!settings.processNameFilter.isEmpty() &&
        !procName.contains(settings.processNameFilter, Qt::CaseInsensitive))
        return;

    const QString dedupeKey = QString::number(pid) + QLatin1Char(':') +
                              QString::number(static_cast<int>(op)) + QLatin1Char(':') +
                              resolvedPath.toLower() + QLatin1Char('|') + valueName.toLower() +
                              QLatin1Char('|') + statusText;
    int sup = 0;
    if (d.throttled(dedupeKey, kCoalesceRegMs, &sup)) return;

    ActivityEvent ev;
    ev.type = type;
    ev.pid = static_cast<int>(pid);
    ev.processName = procName;
    ev.details = details + coalesceSuffix(sup);
    ev.operationStatus = statusText;
    ev.timestamp = QDateTime::currentDateTime();
    emit eventDetected(ev);
}

// ============================================================
// DNS-Client event handling
// ============================================================
void EtwRegistryDnsWatcher::handleDnsRecord(void* pRaw)
{
    PEVENT_RECORD rec = static_cast<PEVENT_RECORD>(pRaw);
    Impl& d = *m_d;

    MonitorSettings settings;
    { QMutexLocker lock(&m_settingsMutex); settings = m_settings; }
    if (!settings.trackDnsQuery) return;

    const quint32 pid = rec->EventHeader.ProcessId;
    if (pid == d.selfPid) return;

    const USHORT eventId = rec->EventHeader.EventDescriptor.Id;
    // 3008 = DNS query completed (name + results)
    // 3010 = query sent to a specific DNS server (includes server IP)
    // 3011 = response received from a DNS server
    // 3018 = cache lookup completed with results
    // 3020 = query response with results
    const bool isCompleted = (eventId == 3008 || eventId == 3018 || eventId == 3020);
    const bool isServerPath = (eventId == 3010 || eventId == 3011);
    if (!isCompleted && !isServerPath)
        return;

    QHash<QString, QString> strs;
    QHash<QString, quint64> ints;
    QString taskName;
    if (!decodeNamedFields(rec, strs, ints, taskName)) return;

    const QString name = firstOf(strs, {"queryname", "name"});
    if (name.isEmpty()) return;

    QString results = firstOf(strs, {"queryresults", "results", "answer"});
    const quint64 status = ints.value(QStringLiteral("querystatus"),
                           ints.value(QStringLiteral("status"),
                           ints.value(QStringLiteral("responsestatus"), 0)));
    const quint64 qtype  = ints.value(QStringLiteral("querytype"),
                           ints.value(QStringLiteral("type"), 0));
    // 3010/3011 carry the DNS server address under several possible names.
    const QString dnsServer = firstOf(strs, {
        "dnsserver", "server", "serveraddr", "serveraddress",
        "address", "destination", "destaddr"
    });

    if (isCompleted) {
        const bool isAaaa = (qtype == 28);
        const bool failedCommon = (status == 87 || status == 11001 || status == 9003 ||
                                   status == 9501 || status == 11004);
        if (isAaaa && results.isEmpty() && (status != 0 || failedCommon))
            return;
        if (results.isEmpty() && status == 87)
            return;
    }

    const QString procName = d.procName(pid);
    if (!settings.processNameFilter.isEmpty() &&
        !procName.contains(settings.processNameFilter, Qt::CaseInsensitive))
        return;

    const QString dedupeKey = QString::number(pid) + QLatin1Char('|') +
                              name.toLower() + QLatin1Char('|') +
                              QString::number(qtype) + QLatin1Char('|') +
                              QString::number(eventId) + QLatin1Char('|') +
                              dnsServer.toLower();
    int sup = 0;
    if (d.throttled(dedupeKey, kCoalesceDnsMs, &sup)) return;

    QString details = name;
    if (qtype) details += QStringLiteral("  (") + dnsTypeToString(qtype) + QLatin1Char(')');

    if (isServerPath) {
        // Show the DNS server this query was sent to / answered from.
        if (!dnsServer.isEmpty())
            details += (eventId == 3010)
                ? QStringLiteral("  -> server ") + dnsServer
                : QStringLiteral("  <- server ") + dnsServer;
        else
            details += (eventId == 3010)
                ? QStringLiteral("  -> (DNS server)")
                : QStringLiteral("  <- (DNS server)");
        if (status != 0)
            details += QStringLiteral("  (status ") + dnsStatusToString(status) + QLatin1Char(')');
    } else if (!results.isEmpty()) {
        while (results.endsWith(QLatin1Char(';')) || results.endsWith(QLatin1Char(' ')))
            results.chop(1);
        details += QStringLiteral("  ->  ") + results;
    } else if (status != 0) {
        details += QStringLiteral("  (failed: ") + dnsStatusToString(status) + QLatin1Char(')');
    } else {
        details += QStringLiteral("  (no results)");
    }

    ActivityEvent ev;
    ev.type = ActivityEvent::Type::DnsQuery;
    ev.pid = static_cast<int>(pid);
    ev.processName = procName;
    ev.details = details + coalesceSuffix(sup);
    ev.dnsServer = dnsServer;
    ev.timestamp = QDateTime::currentDateTime();
    emit eventDetected(ev);
}

// ============================================================
// Network (Kernel-Network) event handling
// ============================================================
// Classic MOF layout used by Microsoft-Windows-Kernel-Network for the
// IPv4 TCP/UDP events (Event IDs 10-16, 42-43). Fields are little-endian
// host storage of network-order values for addresses/ports.
//   offset 0:  uint32 PID
//   offset 4:  uint32 size
//   offset 8:  uint32 daddr   (network byte order)
//   offset 12: uint32 saddr   (network byte order)
//   offset 16: uint16 dport   (network byte order)
//   offset 18: uint16 sport   (network byte order)
// Named TDH decoding often fails on the IPAddrV4 / Port extension types,
// so this raw fallback is the reliable path.
static bool parseKernelNetworkMof(PEVENT_RECORD rec,
                                  quint32& pid, quint32& daddr, quint32& saddr,
                                  quint16& dport, quint16& sport)
{
    const BYTE* p = static_cast<const BYTE*>(rec->UserData);
    const USHORT len = rec->UserDataLength;
    if (!p || len < 20) return false;

    auto rd32 = [&](int off) -> quint32 {
        quint32 v = 0;
        std::memcpy(&v, p + off, 4);
        return v;
    };
    auto rd16 = [&](int off) -> quint16 {
        quint16 v = 0;
        std::memcpy(&v, p + off, 2);
        return v;
    };

    pid   = rd32(0);
    // size at 4 — unused
    daddr = rd32(8);
    saddr = rd32(12);
    // Ports are stored in network byte order in the MOF blob.
    dport = static_cast<quint16>((rd16(16) >> 8) | (rd16(16) << 8));
    sport = static_cast<quint16>((rd16(18) >> 8) | (rd16(18) << 8));
    return true;
}

void EtwRegistryDnsWatcher::handleNetworkRecord(void* pRaw)
{
    PEVENT_RECORD rec = static_cast<PEVENT_RECORD>(pRaw);
    Impl& d = *m_d;

    MonitorSettings settings;
    { QMutexLocker lock(&m_settingsMutex); settings = m_settings; }
    if (!settings.trackNetConnectLive && !settings.trackNetDisconnectLive) return;

    const USHORT eventId = rec->EventHeader.EventDescriptor.Id;

    // Classify by Event ID first (does not need TDH).
    QString taskName;
    NetOp op = classifyNetEvent(eventId, taskName);
    if (op == NetOp::Other) {
        // Fallback: try TDH task name for unknown IDs.
        QHash<QString, QString> strs;
        QHash<QString, quint64> ints;
        if (decodeNamedFields(rec, strs, ints, taskName))
            op = classifyNetEvent(eventId, taskName);
    }
    if (op == NetOp::Other) return;

    if ((op == NetOp::Connect || op == NetOp::UdpSend || op == NetOp::UdpRecv) &&
        !settings.trackNetConnectLive)
        return;
    if (op == NetOp::Disconnect && !settings.trackNetDisconnectLive)
        return;

    // Primary: raw MOF layout (reliable for this provider).
    quint32 pid = 0, daddr = 0, saddr = 0;
    quint16 dport = 0, sport = 0;
    bool got = parseKernelNetworkMof(rec, pid, daddr, saddr, dport, sport);

    // Secondary: named fields if MOF parse failed or looked empty.
    if (!got || (daddr == 0 && dport == 0)) {
        QHash<QString, QString> strs;
        QHash<QString, quint64> ints;
        QString tn;
        if (decodeNamedFields(rec, strs, ints, tn)) {
            auto intField = [&](std::initializer_list<const char*> names) -> quint64 {
                for (const char* n : names) {
                    auto it = ints.constFind(QString::fromLatin1(n));
                    if (it != ints.constEnd()) return it.value();
                }
                return 0;
            };
            if (pid == 0) pid = static_cast<quint32>(intField({"pid", "processid"}));
            if (daddr == 0) daddr = static_cast<quint32>(intField({"daddr", "remoteaddress", "remoteaddr"}));
            if (saddr == 0) saddr = static_cast<quint32>(intField({"saddr", "localaddress", "localaddr"}));
            if (dport == 0) dport = portFromField(intField({"dport", "remoteport"}));
            if (sport == 0) sport = portFromField(intField({"sport", "localport"}));
        }
    }
    if (pid == 0) pid = rec->EventHeader.ProcessId;
    if (pid == d.selfPid) return;
    if (daddr == 0 && dport == 0) return;

    // UDP: only interesting ports (DNS etc.) to avoid flooding.
    if (op == NetOp::UdpSend || op == NetOp::UdpRecv) {
        const bool interesting =
            dport == 53 || dport == 853 ||
            dport == 123 ||
            dport == 67 || dport == 68 ||
            dport == 137 || dport == 138 ||
            dport == 5353 || dport == 5355 ||
            sport == 53;
        if (!interesting) return;
    }

    const QString procName = d.procName(pid);
    if (!settings.processNameFilter.isEmpty() &&
        !procName.contains(settings.processNameFilter, Qt::CaseInsensitive))
        return;

    // Addresses in the MOF blob are network byte order (big-endian octets).
    // ipv4FieldToString expects that layout (shift from high byte).
    const QString local  = ipv4FieldToString(saddr) + QLatin1Char(':') + QString::number(sport);
    const QString remote = ipv4FieldToString(daddr) + QLatin1Char(':') + QString::number(dport);

    const char* opLabel = "CONNECT";
    if (op == NetOp::Disconnect) opLabel = "DISCONNECT";
    else if (op == NetOp::UdpSend) opLabel = "UDP-SEND";
    else if (op == NetOp::UdpRecv) opLabel = "UDP-RECV";

    QString dnsTag;
    if (dport == 53 || sport == 53 || dport == 853)
        dnsTag = QStringLiteral("  DNS");

    const QString dedupeKey = QString::number(pid) + QLatin1Char(':') +
                              QString::number(static_cast<int>(op)) + QLatin1Char(':') +
                              remote + QLatin1Char(':') + QString::number(sport);
    int sup = 0;
    if (d.throttled(dedupeKey, kCoalesceDnsMs, &sup)) return;

    ActivityEvent::Type type = (op == NetOp::Disconnect)
        ? ActivityEvent::Type::NetDisconnectLive
        : ActivityEvent::Type::NetConnectLive;

    ActivityEvent ev;
    ev.type = type;
    ev.pid = static_cast<int>(pid);
    ev.processName = procName;
    ev.details = QString("%1 -> %2  [%3%4, live]")
                    .arg(local, remote, QString::fromLatin1(opLabel), dnsTag)
                 + coalesceSuffix(sup);
    ev.timestamp = QDateTime::currentDateTime();
    emit eventDetected(ev);
}

// ============================================================
// Dispatch
// ============================================================
void EtwRegistryDnsWatcher::handleEventRecord(void* pRaw)
{
    if (!pRaw || !m_d) return;
    PEVENT_RECORD rec = static_cast<PEVENT_RECORD>(pRaw);
    if (IsEqualGUID(rec->EventHeader.ProviderId, KernelRegistryProviderGuid))
        handleRegistryRecord(pRaw);
    else if (IsEqualGUID(rec->EventHeader.ProviderId, DnsClientProviderGuid))
        handleDnsRecord(pRaw);
    else if (IsEqualGUID(rec->EventHeader.ProviderId, KernelNetworkProviderGuid))
        handleNetworkRecord(pRaw);
}

// ============================================================
// Class plumbing
// ============================================================
static void WINAPI regDnsEventRecordCallback(PEVENT_RECORD pRec)
{
    if (g_regDnsInstance)
        g_regDnsInstance->handleEventRecord(static_cast<void*>(pRec));
}

EtwRegistryDnsWatcher::EtwRegistryDnsWatcher(QObject* parent)
    : QThread(parent), m_d(new Impl), m_stopRequested(0)
{}

EtwRegistryDnsWatcher::~EtwRegistryDnsWatcher()
{
    requestStop();
    wait(10000);
    if (g_regDnsInstance == this) g_regDnsInstance = nullptr;
    delete m_d;
    m_d = nullptr;
}

void EtwRegistryDnsWatcher::setSettings(const MonitorSettings& s)
{
    QMutexLocker lock(&m_settingsMutex);
    m_settings = s;
}

void EtwRegistryDnsWatcher::requestStop()
{
    m_stopRequested.storeRelease(1);
    void* session = nullptr;
    void* consumer = nullptr;
    {
        QMutexLocker l(&m_handleMutex);
        session = m_sessionHandle;   m_sessionHandle  = nullptr;
        consumer = m_consumerHandle; m_consumerHandle = nullptr;
    }
    if (session) {
        struct { EVENT_TRACE_PROPERTIES p; WCHAR name[512]; } sp = {};
        sp.p.Wnode.BufferSize = sizeof(sp);
        sp.p.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(reinterpret_cast<TRACEHANDLE>(session),
                      SESSION_NAME, &sp.p, EVENT_TRACE_CONTROL_STOP);
    }
    if (consumer)
        CloseTrace(reinterpret_cast<TRACEHANDLE>(consumer));
}

// ============================================================
// Thread body: start session, enable providers, consume
// ============================================================
void EtwRegistryDnsWatcher::run()
{
    emit statusMessage(QStringLiteral("Starting Kernel-Registry + DNS-Client ETW…"));
    g_regDnsInstance = this;
    m_stopRequested.storeRelease(0);
    m_d->reset();

    struct SessionProps { EVENT_TRACE_PROPERTIES props; WCHAR name[256]; };
    auto initProps = [](SessionProps& sp) {
        ZeroMemory(&sp, sizeof(sp));
        sp.props.Wnode.BufferSize = sizeof(sp);
        sp.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sp.props.Wnode.ClientContext = 1;
        sp.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sp.props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        sp.props.BufferSize = 256;
        sp.props.MinimumBuffers = 32;
        sp.props.MaximumBuffers = 128;
        sp.props.FlushTimer = 1;
        wcscpy_s(sp.name, SESSION_NAME);
    };

    SessionProps sp;
    initProps(sp);
    TRACEHANDLE hSession = 0;
    ULONG result = StartTraceW(&hSession, SESSION_NAME, &sp.props);

    if (result == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        initProps(sp);
        result = StartTraceW(&hSession, SESSION_NAME, &sp.props);
    }
    if (result == ERROR_ACCESS_DENIED) {
        emit errorOccurred(QStringLiteral(
            "Access denied starting Registry/DNS ETW session — run as Administrator."));
        return;
    }
    if (result != ERROR_SUCCESS) {
        emit errorOccurred(QString("StartTrace (Registry/DNS) failed: %1").arg(result));
        return;
    }
    { QMutexLocker hl(&m_handleMutex); m_sessionHandle = reinterpret_cast<void*>(hSession); }

    // Registry + DNS-Client: all keywords. Kernel-Network only defines
    // KERNEL_NETWORK_KEYWORD_IPV4 (0x10) and IPV6 (0x20) — pass those
    // explicitly as well as ~0 so nothing is filtered out.
    const ULONGLONG kAllKeywords = ~0ULL;
    const ULONGLONG kNetKeywords = 0x10ULL | 0x20ULL | kAllKeywords;
    const ULONG regResult = EnableTraceEx2(hSession, &KernelRegistryProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, kAllKeywords, 0, 0, nullptr);
    const ULONG dnsResult = EnableTraceEx2(hSession, &DnsClientProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, kAllKeywords, 0, 0, nullptr);
    const ULONG netResult = EnableTraceEx2(hSession, &KernelNetworkProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, kNetKeywords, 0, 0, nullptr);

    if (regResult != ERROR_SUCCESS && dnsResult != ERROR_SUCCESS && netResult != ERROR_SUCCESS) {
        emit errorOccurred(QString(
            "EnableTraceEx2 failed for Kernel-Registry (%1), DNS-Client (%2) and "
            "Kernel-Network (%3).").arg(regResult).arg(dnsResult).arg(netResult));
        ControlTraceW(hSession, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = nullptr;
        return;
    }
    if (regResult != ERROR_SUCCESS)
        emit statusMessage(QString("Kernel-Registry provider failed to enable (%1) — "
                                   "the other providers are still active.").arg(regResult));
    if (dnsResult != ERROR_SUCCESS)
        emit statusMessage(QString("DNS-Client provider failed to enable (%1) — "
                                   "the other providers are still active.").arg(dnsResult));
    if (netResult != ERROR_SUCCESS)
        emit statusMessage(QString("Kernel-Network provider failed to enable (%1) — "
                                   "the other providers are still active.").arg(netResult));

    emit statusMessage(QStringLiteral("Kernel-Registry + DNS-Client + Kernel-Network ETW active."));

    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    logFile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = regDnsEventRecordCallback;

    TRACEHANDLE hConsumer = OpenTraceW(&logFile);
    if (hConsumer == reinterpret_cast<TRACEHANDLE>(INVALID_HANDLE_VALUE)) {
        emit errorOccurred(QString("OpenTrace (Registry/DNS) failed: %1").arg(GetLastError()));
        ControlTraceW(hSession, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = nullptr;
        return;
    }
    { QMutexLocker hl(&m_handleMutex); m_consumerHandle = reinterpret_cast<void*>(hConsumer); }

    ULONG pr = ProcessTrace(&hConsumer, 1, nullptr, nullptr);
    if (pr != ERROR_SUCCESS && pr != ERROR_CANCELLED)
        emit errorOccurred(QString("ProcessTrace (Registry/DNS) ended: %1").arg(pr));

    // Take the handles under the lock. If requestStop() already took them,
    // these are null and nothing is closed twice.
    void* ownConsumer = nullptr;
    void* ownSession  = nullptr;
    {
        QMutexLocker hl(&m_handleMutex);
        ownConsumer = m_consumerHandle; m_consumerHandle = nullptr;
        ownSession  = m_sessionHandle;  m_sessionHandle  = nullptr;
    }
    if (ownConsumer)
        CloseTrace(reinterpret_cast<TRACEHANDLE>(ownConsumer));
    if (ownSession)
        ControlTraceW(hSession, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
    m_d->reset();
    emit statusMessage(QStringLiteral("Registry/DNS ETW watcher stopped."));
}
