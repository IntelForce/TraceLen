// ============================================================
// EtwFileWatcher.cpp — Kernel-File ETW (system-wide, with PID)
//
// Replaces the old ETW + USN-journal hybrid.
//
// Why the old ETW path missed things (e.g. AutomaticDestinations):
//   * Event payloads were read at hard-coded byte offsets. The
//     Kernel-File manifest is tightly packed (no alignment padding),
//     so FileObject/FileKey were read from the wrong offsets. The
//     FileObject -> path table built from Create events therefore
//     never matched the FileObject in Write/Read events, and every
//     write was dropped as "path unknown".
//   * The path was found by scanning the payload for something that
//     "looks like a path".
//
// What this version does instead:
//   * Decodes each event through its own manifest schema (TDH) and
//     reads fields BY NAME (FileObject, FileKey, FileName, ...).
//     Falls back to a built-in layout if TDH is unavailable.
//   * Process names come from Microsoft-Windows-Kernel-Process start
//     events + an initial snapshot, so short-lived processes and
//     protected processes still get a name.
//   * Writes issued by the System process (lazy writer) are attributed
//     to the process that opened the file when we know it.
//   * Repeated writes/reads to the same file by the same process are
//     coalesced (see kCoalesce*Ms) so the UI is not flooded.
//   * NameDelete (name-cache eviction) is no longer reported as a
//     delete; real deletes come from DeletePath / Delete.
//   * Own-process I/O is ignored (avoids a log-file feedback loop).
//   * Lost events and unresolved writes are reported via statusMessage.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <wmistr.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <winioctl.h>

#include "EtwFileWatcher.h"
#include <QMutexLocker>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>
#include <QHash>
#include <QVector>
#include <QList>
#include <QStringList>
#include <QFile>
#include <QTextStream>
#include <algorithm>
#include <deque>
#include <thread>
#include <vector>
#include <cstring>

static EtwFileWatcher* g_etwInstance = nullptr;

// Microsoft-Windows-Kernel-File
static const GUID KernelFileProviderGuid =
    {0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}};
// Microsoft-Windows-Kernel-Process
static const GUID KernelProcessProviderGuid =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

static const wchar_t* SESSION_NAME = L"TraceLen_KernelFile";

// Kernel-File keywords
static const ULONGLONG KW_FILENAME            = 0x10ULL;
static const ULONGLONG KW_FILEIO              = 0x20ULL;
static const ULONGLONG KW_CREATE              = 0x80ULL;
static const ULONGLONG KW_READ                = 0x100ULL;
static const ULONGLONG KW_WRITE               = 0x200ULL;
static const ULONGLONG KW_DELETE_PATH         = 0x400ULL;
static const ULONGLONG KW_RENAME_SETLINK_PATH = 0x800ULL;
static const ULONGLONG KW_CREATE_NEW_FILE     = 0x1000ULL;
// Kernel-Process keyword
static const ULONGLONG KWP_PROCESS            = 0x10ULL;

// Kernel-File event ids
static const USHORT EID_NameCreate    = 10;
static const USHORT EID_NameDelete    = 11;
static const USHORT EID_Create        = 12;
static const USHORT EID_Cleanup       = 13;
static const USHORT EID_Close         = 14;
static const USHORT EID_Read          = 15;
static const USHORT EID_Write         = 16;
static const USHORT EID_SetInfo       = 17;
static const USHORT EID_Delete        = 18;
static const USHORT EID_QueryInfo     = 22;   // NtQueryInformationFile (requires an open handle)
static const USHORT EID_OperationEnd  = 24;   // completion of a previously-issued IRP (gives NTSTATUS)
static const USHORT EID_DeletePath    = 26;
static const USHORT EID_RenamePath    = 27;
static const USHORT EID_CreateNewFile = 30;
// Kernel-Process event ids
static const USHORT EID_ProcStart     = 1;

// Coalescing windows (ms): same process + same file + same kind.
static const ULONGLONG kCoalesceWriteMs = 1000;
static const ULONGLONG kCoalesceReadMs  = 1000;
static const ULONGLONG kCoalesceOtherMs = 250;

static const size_t kMaxTrackedObjects = 250000;
static const size_t kMaxPendingQueries = 20000;
// How long we'll hold a QueryInformation event waiting for its matching
// OperationEnd (completion) before giving up on showing a result for it.
static const qint64 kPendingQueryTimeoutMs = 3000;

// NtCreateFile option bits
static const quint32 kFileDirectoryFile = 0x00000001;
static const quint32 kDispOverwrite     = 4;   // FILE_OVERWRITE

// ------------------------------------------------------------
// TDH in-types we can decode sequentially (numeric values from tdh.h,
// spelled out so we do not depend on a particular header version).
// ------------------------------------------------------------
namespace {
enum : USHORT {
    IT_USTR = 1, IT_ASTR = 2, IT_I8 = 3, IT_U8 = 4, IT_I16 = 5, IT_U16 = 6,
    IT_I32 = 7, IT_U32 = 8, IT_I64 = 9, IT_U64 = 10, IT_FLOAT = 11,
    IT_DOUBLE = 12, IT_BOOL = 13, IT_GUID = 15, IT_PTR = 16,
    IT_FILETIME = 17, IT_SYSTIME = 18, IT_HEX32 = 20, IT_HEX64 = 21,
    IT_SIZET = 30
};

// Property flags that make a property non-trivially sized.
const DWORD kComplexPropFlags = 0x1 /*Struct*/ | 0x2 /*ParamLength*/ |
                                0x4 /*ParamCount*/ | 0x10 /*ParamFixedLength*/ |
                                0x20 /*ParamFixedCount*/;

struct Schema {
    std::vector<USHORT> types;
    int iFileObject = -1, iFileKey = -1, iPath = -1, iOptions = -1;
    int iPid = -1, iImage = -1;
    int iInfoClass = -1, iIrp = -1, iStatus = -1;
    bool valid = false;

    void addProp(const QString& lname, USHORT type) {
        const int idx = static_cast<int>(types.size());
        types.push_back(type);
        if      (lname == QLatin1String("fileobject"))   iFileObject = idx;
        else if (lname == QLatin1String("filekey"))      iFileKey    = idx;
        else if (lname == QLatin1String("createoptions")) iOptions   = idx;
        else if (lname == QLatin1String("processid"))    iPid        = idx;
        else if (lname == QLatin1String("imagename"))    iImage      = idx;
        else if (lname == QLatin1String("infoclass"))    iInfoClass  = idx;
        else if (lname == QLatin1String("irp"))          iIrp        = idx;
        else if (lname == QLatin1String("ntstatus") ||
                 lname == QLatin1String("status")   ||
                 lname == QLatin1String("iostatus"))      iStatus     = idx;
        else if (iPath < 0 && (lname == QLatin1String("filename") ||
                               lname == QLatin1String("openpath") ||
                               lname == QLatin1String("filepath") ||
                               lname == QLatin1String("path")))
            iPath = idx;
    }
};

struct Parsed {
    quint64 fileObject = 0, fileKey = 0, options = 0, pid = 0;
    quint64 infoClass = 0, irp = 0;
    quint64 status = 0;         // NTSTATUS, as the raw 32-bit bit pattern (0 = STATUS_SUCCESS)
    QString path;
    QString image;
};

// Preferred: ask the provider's manifest for the layout.
bool loadSchemaTdh(PEVENT_RECORD rec, Schema& sc)
{
    ULONG size = 0;
    ULONG st = TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
    if (st != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return false;
    std::vector<BYTE> buf(size);
    PTRACE_EVENT_INFO info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
    st = TdhGetEventInformation(rec, 0, nullptr, info, &size);
    if (st != ERROR_SUCCESS)
        return false;

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
        // Stop at the first property we cannot walk sequentially; everything
        // before it is still usable.
        if ((p.Flags & kComplexPropFlags) || p.count > 1)
            break;
        const WCHAR* name = reinterpret_cast<const WCHAR*>(buf.data() + p.NameOffset);
        sc.addProp(QString::fromWCharArray(name).toLower(), p.nonStructType.InType);
    }
    sc.valid = !sc.types.empty();
    return sc.valid;
}

// Fallback layouts for Microsoft-Windows-Kernel-File (used only if TDH fails).
bool builtinFileSchema(USHORT id, Schema& sc)
{
    auto A = [&](const char* n, USHORT t) { sc.addProp(QString::fromLatin1(n), t); };
    switch (id) {
    case EID_Create:
    case EID_CreateNewFile:
        A("irp", IT_PTR); A("threadid", IT_U32); A("fileobject", IT_PTR);
        A("createoptions", IT_U32); A("createattributes", IT_U32);
        A("shareaccess", IT_U32); A("filename", IT_USTR);
        break;
    case EID_Read:
    case EID_Write:
        A("offset", IT_U64); A("irp", IT_PTR); A("threadid", IT_U32);
        A("fileobject", IT_PTR); A("filekey", IT_PTR);
        A("iosize", IT_U32); A("ioflags", IT_U32);
        break;
    case EID_Cleanup:
    case EID_Close:
        A("irp", IT_PTR); A("threadid", IT_U32);
        A("fileobject", IT_PTR); A("filekey", IT_PTR);
        break;
    case EID_NameCreate:
    case EID_NameDelete:
        A("filekey", IT_PTR); A("filename", IT_USTR);
        break;
    case EID_SetInfo:
    case EID_Delete:
    case EID_QueryInfo:   // same shape as SetInfo in the built-in (non-TDH) layout
        A("irp", IT_PTR); A("threadid", IT_U32);
        A("fileobject", IT_PTR); A("filekey", IT_PTR);
        A("extrainformation", IT_PTR); A("infoclass", IT_U32);
        break;
    case EID_OperationEnd:   // completion of a previously-issued IRP
        A("irp", IT_PTR); A("extrainformation", IT_PTR); A("ntstatus", IT_I32);
        break;
    case EID_DeletePath:
    case EID_RenamePath:
        A("irp", IT_PTR); A("threadid", IT_U32);
        A("fileobject", IT_PTR); A("filekey", IT_PTR);
        A("extrainformation", IT_PTR); A("infoclass", IT_U32);
        A("filepath", IT_USTR);
        break;
    default:
        return false;
    }
    sc.valid = true;
    return true;
}

// Decode the UserData block sequentially (Kernel-File payloads are packed).
bool decodeEvent(const EVENT_RECORD* rec, const Schema& sc, Parsed& out)
{
    const BYTE* p   = static_cast<const BYTE*>(rec->UserData);
    const BYTE* end = p + rec->UserDataLength;
    const size_t ptrSize =
        (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    for (size_t i = 0; i < sc.types.size(); ++i) {
        const USHORT t = sc.types[i];
        const int idx = static_cast<int>(i);
        size_t sz = 0;
        bool isInt = true;

        switch (t) {
        case IT_I8:  case IT_U8:                                   sz = 1; break;
        case IT_I16: case IT_U16:                                  sz = 2; break;
        case IT_I32: case IT_U32: case IT_HEX32:
        case IT_BOOL: case IT_FLOAT:                               sz = 4; break;
        case IT_I64: case IT_U64: case IT_HEX64:
        case IT_DOUBLE: case IT_FILETIME:                          sz = 8; break;
        case IT_PTR: case IT_SIZET:                                sz = ptrSize; break;
        case IT_GUID: case IT_SYSTIME:                             sz = 16; isInt = false; break;
        case IT_USTR: case IT_ASTR:                                isInt = false; break;
        default:
            return true;   // unknown layout from here on; keep what we have
        }

        if (t == IT_USTR) {
            const size_t maxc = static_cast<size_t>(end - p) / 2;
            const WCHAR* w = reinterpret_cast<const WCHAR*>(p);
            size_t n = 0;
            while (n < maxc && w[n]) ++n;
            const QString s = QString::fromWCharArray(w, static_cast<int>(n));
            if (idx == sc.iPath)  out.path  = s;
            if (idx == sc.iImage) out.image = s;
            sz = (n < maxc) ? (n + 1) * 2 : n * 2;
        } else if (t == IT_ASTR) {
            const size_t maxc = static_cast<size_t>(end - p);
            size_t n = 0;
            while (n < maxc && p[n]) ++n;
            const QString s = QString::fromLatin1(reinterpret_cast<const char*>(p),
                                                  static_cast<int>(n));
            if (idx == sc.iPath)  out.path  = s;
            if (idx == sc.iImage) out.image = s;
            sz = (n < maxc) ? n + 1 : n;
        } else {
            if (static_cast<size_t>(end - p) < sz)
                return false;
            if (isInt) {
                quint64 v = 0;
                std::memcpy(&v, p, sz > 8 ? 8 : sz);
                if (idx == sc.iFileObject) out.fileObject = v;
                else if (idx == sc.iFileKey)  out.fileKey = v;
                else if (idx == sc.iOptions)  out.options = v;
                else if (idx == sc.iPid)      out.pid = v;
                else if (idx == sc.iInfoClass) out.infoClass = v;
                else if (idx == sc.iIrp)       out.irp = v;
                else if (idx == sc.iStatus)    out.status = v;
            }
        }
        p += sz;
    }
    return true;
}

// ------------------------------------------------------------
// NT path -> Win32 path
// ------------------------------------------------------------
void buildDeviceMap(QHash<QString, QString>& map)
{
    map.clear();
    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(511, drives))
        return;
    for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        wchar_t dev[MAX_PATH] = {};
        wchar_t letter[3] = { d[0], d[1], L'\0' };
        if (QueryDosDeviceW(letter, dev, MAX_PATH))
            map[QString::fromWCharArray(dev)] = QString::fromWCharArray(letter);
    }
}

// FILE_INFORMATION_CLASS (ntifs.h) -> short, human-readable description of
// *what* a QueryInformation/SetInformation call was asking about. This is
// the piece that actually answers "what kind of query was this" — the ETW
// event itself never carries the queried VALUES (attributes, size, etc.),
// only which class of metadata was requested and (via OperationEnd) whether
// it succeeded.
QString fileInfoClassToString(quint32 ic)
{
    switch (ic) {
    case 1:  return QStringLiteral("Directory listing");
    case 4:  return QStringLiteral("Basic info (attributes/timestamps)");
    case 5:  return QStringLiteral("Standard info (size/links/is-directory)");
    case 6:  return QStringLiteral("Internal info (file ID)");
    case 7:  return QStringLiteral("EA info");
    case 8:  return QStringLiteral("Access info");
    case 9:  return QStringLiteral("Name info");
    case 10: return QStringLiteral("Rename");
    case 11: return QStringLiteral("Hard link create");
    case 13: return QStringLiteral("Disposition (delete-on-close)");
    case 14: return QStringLiteral("Position info");
    case 16: return QStringLiteral("Mode info");
    case 18: return QStringLiteral("All info (combined)");
    case 19: return QStringLiteral("Allocation size");
    case 20: return QStringLiteral("End-of-file (truncate/extend)");
    case 21: return QStringLiteral("Alternate (8.3) name");
    case 22: return QStringLiteral("Alternate data streams");
    case 28: return QStringLiteral("Compression info");
    case 32: return QStringLiteral("Quota info");
    case 33: return QStringLiteral("Reparse point info");
    case 34: return QStringLiteral("Network open info (attrs via open)");
    case 35: return QStringLiteral("Attribute tag (incl. reparse tag)");
    case 37: return QStringLiteral("Directory listing (with file ID)");
    case 46: return QStringLiteral("Hard link enumeration");
    case 48: return QStringLiteral("Normalized name info");
    case 59: return QStringLiteral("File ID info");
    case 68: return QStringLiteral("Stat info (Linux-style fstat)");
    default: return QStringLiteral("info class %1").arg(ic);
    }
}

// A handful of NTSTATUS codes that are actually interesting to see next to
// a file query (the rest just show as a hex code, which is still useful for
// looking the value up).
QString ntStatusToString(quint32 st)
{
    switch (st) {
    case 0x00000000: return QStringLiteral("OK");
    case 0xC0000034: return QStringLiteral("not found");
    case 0xC000003A: return QStringLiteral("path not found");
    case 0xC0000022: return QStringLiteral("access denied");
    case 0xC0000043: return QStringLiteral("sharing violation");
    case 0xC0000056: return QStringLiteral("delete pending");
    case 0xC0000023: return QStringLiteral("buffer too small");
    case 0x80000005: return QStringLiteral("buffer too small, result truncated");
    case 0xC000000D: return QStringLiteral("invalid parameter");
    case 0xC00000BB: return QStringLiteral("not supported");
    case 0xC0000008: return QStringLiteral("invalid handle");
    default: return QString("0x%1").arg(st, 8, 16, QLatin1Char('0'));
    }
}

QString ntPathToWin32(const QString& in)
{
    QString p = in.trimmed();
    if (p.isEmpty()) return p;
    if (p.startsWith(QStringLiteral("\\??\\")) || p.startsWith(QStringLiteral("\\\\?\\")))
        p = p.mid(4);
    if (p.length() >= 2 && p[1] == QLatin1Char(':')) return p;
    if (!p.startsWith(QLatin1Char('\\'))) return p;

    if (p.startsWith(QStringLiteral("\\Device\\Mup\\"), Qt::CaseInsensitive))
        return QStringLiteral("\\\\") + p.mid(12);

    static QHash<QString, QString> s_devMap;
    static ULONGLONG s_lastBuild = 0;

    auto lookup = [&](QString& result) -> bool {
        for (auto it = s_devMap.constBegin(); it != s_devMap.constEnd(); ++it) {
            const QString& dev = it.key();
            if (p.startsWith(dev, Qt::CaseInsensitive) &&
                (p.length() == dev.length() || p[dev.length()] == QLatin1Char('\\'))) {
                result = it.value() + p.mid(dev.length());
                return true;
            }
        }
        return false;
    };

    if (s_devMap.isEmpty()) { buildDeviceMap(s_devMap); s_lastBuild = GetTickCount64(); }
    QString out;
    if (lookup(out)) return out;

    // Miss: a volume may have been mounted since we built the table.
    const ULONGLONG now = GetTickCount64();
    if (now - s_lastBuild > 5000) {
        buildDeviceMap(s_devMap);
        s_lastBuild = now;
        if (lookup(out)) return out;
    }
    return p;
}

QString queryImageName(quint32 pid)
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

typedef qint64 Tick;
static Tick nowTick() { return static_cast<Tick>(GetTickCount64()); }

// ETW event time (QPC, because ClientContext=1) -> GetTickCount64 timeline.
static Tick eventTick(const EVENT_RECORD* rec)
{
    static LONGLONG s_freq = 0;
    if (!s_freq) {
        LARGE_INTEGER f; QueryPerformanceFrequency(&f);
        s_freq = f.QuadPart ? f.QuadPart : 1;
    }
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    const Tick now = nowTick();
    const LONGLONG diff = q.QuadPart - rec->EventHeader.TimeStamp.QuadPart;
    if (diff < 0 || diff > s_freq * 600) return now;      // clock mismatch: use arrival time
    return now - static_cast<Tick>(diff * 1000 / s_freq);
}

// USN events are held back this long so the (up to ~1 s delayed) ETW events
// for the same change can arrive before we try to attribute it.
static const Tick kAttribDelayMs = 1800;

// ============================================================
// All mutable ETW/USN state
// ============================================================
struct EtwFileWatcher::Impl
{
    struct FileObj { QString path; quint32 pid = 0; };
    struct Act     { quint32 pid; Tick tick; char kind; };   // w c o x d n
    struct OpenH   { quint64 fo; quint32 pid; };
    struct Attr    { quint32 pid = 0; QString name; QString extra; };
    // A QueryInformation event we've seen but whose result (OperationEnd)
    // hasn't arrived yet. Keyed by Irp pointer, which is how Kernel-File
    // correlates a request with its completion.
    struct PendingQuery { QString path; quint32 pid = 0; quint32 infoClass = 0; Tick tick; };
    struct PendingUsn {
        ActivityEvent::Type type;
        QString path, suffix, reason;
        Tick usnTick, readTick;
        char reportedKind, attrKind;
    };

    // ---- ETW-thread only ----
    QHash<quint32, Schema>  schemas;
    QHash<quint64, FileObj> byObject;   // FileObject -> path/opener
    QHash<quint64, QString> byKey;      // FileKey    -> path
    QHash<quint64, PendingQuery> pendingQueries;   // Irp -> query awaiting its result
    // pid+path+infoClass -> tick of the last "buffer too small" WARN shown
    // for that exact query. See the EID_OperationEnd comment: the standard
    // "ask for the size, then ask again with a big-enough buffer" pattern
    // means a WARN here is almost always immediately followed by an OK for
    // the literal same query — this lets us say so instead of leaving two
    // unexplained, seemingly-contradictory rows.
    QHash<QString, Tick> recentBufferTooSmall;
    struct ThrottleState { ULONGLONG lastTick = 0; int suppressedCount = 0; };
    QHash<QString, ThrottleState> lastEmit;
    quint64   unresolved = 0, unresolvedReported = 0;
    quint64   lostReported = 0;
    ULONGLONG lastHealth = 0;
    bool      warnedFallback = false;

    // ---- process names (ETW + USN threads) ----
    QMutex nameMutex;
    QHash<quint32, QString> procNames;
    ULONGLONG lastSnapshot = 0;

    // ---- ETW <-> USN correlation (guarded by corrMutex) ----
    QMutex corrMutex;
    QHash<QString, QVector<Act>>   activity;     // lower(path) -> recent ops
    QHash<QString, QVector<OpenH>> openByPath;   // lower(path) -> live handles
    QHash<QString, Tick>           reported;     // kind+lower(path) -> ETW already showed it

    // ---- USN thread only ----
    std::deque<PendingUsn> pendingUsn;

    // ---- optional diagnostics (env PM_ETW_TRACE=<path substring>) ----
    QMutex  traceMutex;
    QString traceFilter, tracePath;

    quint32 selfPid = GetCurrentProcessId();

    // Drops entries nobody completed within the timeout (a lost/filtered
    // completion event, or we started mid-stream). Cheap no-op most of the
    // time since real completions arrive within microseconds.
    void prunePendingQueries(Tick now) {
        for (auto it = pendingQueries.begin(); it != pendingQueries.end();) {
            if (now - it.value().tick > kPendingQueryTimeoutMs) it = pendingQueries.erase(it);
            else ++it;
        }
    }

    void reset() {
        schemas.clear(); byObject.clear(); byKey.clear(); pendingQueries.clear(); lastEmit.clear();
        recentBufferTooSmall.clear();
        unresolved = unresolvedReported = lostReported = 0;
        lastHealth = 0; warnedFallback = false;
        { QMutexLocker l(&nameMutex); procNames.clear(); lastSnapshot = 0; }
        { QMutexLocker l(&corrMutex); activity.clear(); openByPath.clear(); reported.clear(); }
        pendingUsn.clear();
        selfPid = GetCurrentProcessId();
    }

    // ---------------- diagnostics ----------------
    bool traceMatch(const QString& path) const {
        return !traceFilter.isEmpty() && path.contains(traceFilter, Qt::CaseInsensitive);
    }
    void trace(const QString& line) {
        if (tracePath.isEmpty()) return;
        QMutexLocker l(&traceMutex);
        QFile f(tracePath);
        if (f.open(QIODevice::Append | QIODevice::Text)) {
            QTextStream ts(&f);
            ts << QDateTime::currentDateTime().toString("hh:mm:ss.zzz") << ' ' << line << '\n';
        }
    }

    // ---------------- process names ----------------
    void refreshSnapshotLocked() {
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
    void refreshSnapshot() { QMutexLocker l(&nameMutex); refreshSnapshotLocked(); }

    void setProcName(quint32 pid, const QString& n) {
        QMutexLocker l(&nameMutex);
        if (procNames.size() > 16384) procNames.clear();
        procNames.insert(pid, n);
    }

    QString procName(quint32 pid) {
        if (pid == 0) return QStringLiteral("System Idle");
        if (pid == 4) return QStringLiteral("System");
        QMutexLocker l(&nameMutex);
        auto it = procNames.constFind(pid);
        if (it != procNames.constEnd()) return it.value();

        QString n = queryImageName(pid);
        if (n.isEmpty() && GetTickCount64() - lastSnapshot > 2000) {
            refreshSnapshotLocked();
            it = procNames.constFind(pid);
            if (it != procNames.constEnd()) return it.value();
        }
        if (n.isEmpty())
            return QString("pid-%1").arg(pid);     // not cached: retry later
        if (procNames.size() > 16384) procNames.clear();
        procNames.insert(pid, n);
        return n;
    }

    // ---------------- ETW schema cache ----------------
    Schema& schemaFor(PEVENT_RECORD rec, int provIdx, bool& usedFallback) {
        const USHORT id = rec->EventHeader.EventDescriptor.Id;
        const quint32 key = (quint32(provIdx) << 24) | (quint32(id) << 8) |
                            quint32(rec->EventHeader.EventDescriptor.Version);
        auto it = schemas.find(key);
        if (it != schemas.end()) return it.value();

        Schema sc;
        if (!loadSchemaTdh(rec, sc) && provIdx == 0) {
            sc = Schema();
            if (builtinFileSchema(id, sc)) usedFallback = true;
        }
        return schemas.insert(key, sc).value();
    }

    // true = identical event handled recently -> suppress (ETW thread only).
    // "Visible coalescing": rather than silently dropping duplicates
    // forever, this counts how many were suppressed since the last one
    // that actually got shown, and hands that count back (via
    // suppressedOut) the next time a matching event IS allowed through —
    // emitFile() folds it into that row's details as "(xN in ...)". Known
    // limitation: if the repeats stop entirely, the tally for that last
    // burst has nowhere to surface (there's no next row to attach it to)
    // and is simply dropped with the rest of this map's state on reset().
    bool throttled(char kind, quint32 pid, const QString& path, ULONGLONG windowMs,
                   int* suppressedOut = nullptr) {
        const ULONGLONG now = GetTickCount64();
        const QString key = QString::number(pid) + QLatin1Char(kind) + path.toLower();
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

    // ---------------- correlation ----------------
    void noteActivity(const QString& path, quint32 pid, char kind, Tick tick) {
        if (pid == 0 || pid == 4 || path.isEmpty()) return;
        QMutexLocker l(&corrMutex);
        if (activity.size() > 150000) activity.clear();
        QVector<Act>& v = activity[path.toLower()];
        if (!v.isEmpty()) {
            const Act& a = v.last();
            if (a.pid == pid && a.kind == kind && tick - a.tick < 100) return;
        }
        if (v.size() >= 24) v.removeFirst();
        v.push_back({pid, tick, kind});
    }
    void noteOpen(const QString& path, quint64 fo, quint32 pid) {
        if (!fo || pid == 0 || pid == 4 || path.isEmpty()) return;
        QMutexLocker l(&corrMutex);
        if (openByPath.size() > 150000) openByPath.clear();
        QVector<OpenH>& v = openByPath[path.toLower()];
        if (v.size() >= 32) v.removeFirst();
        v.push_back({fo, pid});
    }
    void noteClose(const QString& path, quint64 fo) {
        if (path.isEmpty()) return;
        QMutexLocker l(&corrMutex);
        auto it = openByPath.find(path.toLower());
        if (it == openByPath.end()) return;
        QVector<OpenH>& v = it.value();
        for (int i = 0; i < v.size(); ++i)
            if (v[i].fo == fo) { v.remove(i); break; }
        if (v.isEmpty()) openByPath.erase(it);
    }
    void noteReported(char kind, const QString& path, Tick tick) {
        if (path.isEmpty()) return;
        QMutexLocker l(&corrMutex);
        if (reported.size() > 30000) reported.clear();
        reported.insert(QString(QLatin1Char(kind)) + path.toLower(), tick);
    }
    bool wasReported(char kind, const QString& path, Tick around, Tick windowMs) {
        QMutexLocker l(&corrMutex);
        auto it = reported.constFind(QString(QLatin1Char(kind)) + path.toLower());
        if (it == reported.constEnd()) return false;
        const Tick d = it.value() - around;
        return d >= -windowMs && d <= windowMs;
    }
    void pruneCorrelation(Tick now) {
        QMutexLocker l(&corrMutex);
        for (auto it = activity.begin(); it != activity.end();) {
            QVector<Act>& v = it.value();
            for (int i = v.size() - 1; i >= 0; --i)
                if (now - v[i].tick > 30000) v.remove(i);
            if (v.isEmpty()) it = activity.erase(it); else ++it;
        }
        for (auto it = reported.begin(); it != reported.end();)
            if (now - it.value() > 30000) it = reported.erase(it); else ++it;
    }

    // Who most plausibly caused a change to `path` at `usnTick`?
    Attr attribute(const QString& path, Tick usnTick, char wanted) {
        QHash<quint32, int>  score;
        QHash<quint32, Tick> latest;
        {
            QMutexLocker l(&corrMutex);
            const QString k = path.toLower();
            auto ai = activity.constFind(k);
            if (ai != activity.constEnd()) {
                for (const Act& a : ai.value()) {
                    const Tick dt = a.tick - usnTick;          // > 0: after the USN stamp
                    if (dt < -6000 || dt > 3000) continue;
                    int s = 0;
                    if (a.kind == wanted)                    s = 100;  // same operation seen
                    else if (a.kind == 'c')                  s = 60;   // created / overwritten it
                    else if (a.kind == 'x' && dt >= -2500)   s = 40;   // handle closed right then
                    else if (a.kind == 'o')                  s = 10;
                    if (!s) continue;
                    score[a.pid] += s;
                    if (a.tick > latest.value(a.pid, 0)) latest[a.pid] = a.tick;
                }
            }
            // Handles still open on the file (e.g. memory-mapped writers that
            // opened it long before the change).
            auto oi = openByPath.constFind(k);
            if (oi != openByPath.constEnd())
                for (const OpenH& h : oi.value()) score[h.pid] += 30;
        }
        Attr out;
        if (score.isEmpty()) return out;

        QList<quint32> pids = score.keys();
        std::sort(pids.begin(), pids.end(), [&](quint32 a, quint32 b) {
            if (score[a] != score[b]) return score[a] > score[b];
            return latest.value(a, 0) > latest.value(b, 0);
        });
        out.pid  = pids.first();
        out.name = procName(out.pid);
        QStringList others;
        for (int i = 1; i < pids.size() && i <= 2; ++i)
            others << QString("%1(%2)").arg(procName(pids[i])).arg(pids[i]);
        if (!others.isEmpty())
            out.extra = QStringLiteral("  [also involved: ") + others.join(", ") + QLatin1Char(']');
        return out;
    }
};

// ============================================================
// Class plumbing
// ============================================================
static void WINAPI eventRecordCallback(PEVENT_RECORD pRec)
{
    if (g_etwInstance)
        g_etwInstance->handleEventRecord(static_cast<void*>(pRec));
}

EtwFileWatcher::EtwFileWatcher(QObject* parent)
    : QThread(parent), m_d(new Impl), m_stopRequested(0)
{}

EtwFileWatcher::~EtwFileWatcher()
{
    requestStop();
    wait(10000);
    if (g_etwInstance == this)
        g_etwInstance = nullptr;
    delete m_d;
    m_d = nullptr;
}

void EtwFileWatcher::setSettings(const MonitorSettings& s)
{
    QMutexLocker lock(&m_settingsMutex);
    m_settings = s;
}

void EtwFileWatcher::requestStop()
{
    m_stopRequested.storeRelease(1);
    m_usnStop.storeRelease(1);
    // Take ownership of the handles under the lock. Whichever side clears
    // a handle is the only one that closes it, so each is closed exactly once.
    void* session = nullptr;
    void* consumer = nullptr;
    {
        QMutexLocker l(&m_handleMutex);
        session = m_sessionHandle;  m_sessionHandle  = nullptr;
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

bool EtwFileWatcher::isRunningAsAdmin()
{
    BOOL admin = FALSE;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&auth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(nullptr, sid, &admin);
        FreeSid(sid);
    }
    return admin == TRUE;
}

// ============================================================
// Event handling (runs on the ProcessTrace thread)
// ============================================================
void EtwFileWatcher::handleEventRecord(void* pRaw)
{
    if (!pRaw || !m_d) return;
    PEVENT_RECORD rec = static_cast<PEVENT_RECORD>(pRaw);
    Impl& d = *m_d;

    int provIdx = -1;
    if (IsEqualGUID(rec->EventHeader.ProviderId, KernelFileProviderGuid))
        provIdx = 0;
    else if (IsEqualGUID(rec->EventHeader.ProviderId, KernelProcessProviderGuid))
        provIdx = 1;
    if (provIdx < 0) return;

    const USHORT eid = rec->EventHeader.EventDescriptor.Id;

    // ---- Health report (every ~5 s): lost events + unresolved writes ----
    {
        const ULONGLONG now = GetTickCount64();
        if (now - d.lastHealth >= 5000) {
            d.lastHealth = now;
            d.pruneCorrelation(static_cast<Tick>(now));
            void* session = m_sessionHandle;
            if (session) {
                struct { EVENT_TRACE_PROPERTIES p; WCHAR name[256]; WCHAR file[256]; } q = {};
                q.p.Wnode.BufferSize = sizeof(q);
                q.p.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                q.p.LogFileNameOffset = 0;
                if (ControlTraceW(reinterpret_cast<TRACEHANDLE>(session), SESSION_NAME,
                                  &q.p, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
                    const quint64 lost = q.p.EventsLost + q.p.RealTimeBuffersLost +
                                         q.p.LogBuffersLost;
                    if (lost > d.lostReported) {
                        emit statusMessage(QString(
                            "WARNING: ETW dropped events (lost so far: %1). The USN journal "
                            "still reports the change, but PID attribution may be missing.")
                            .arg(lost));
                        d.lostReported = lost;
                    }
                }
            }
            if (d.unresolved > d.unresolvedReported) {
                emit statusMessage(QString(
                    "Note: %1 ETW read/write event(s) had no known path (file opened before "
                    "monitoring started); USN journal covers these.").arg(d.unresolved));
                d.unresolvedReported = d.unresolved;
            }
        }
    }

    // ---- Process provider: keep PID -> name up to date ----
    if (provIdx == 1) {
        if (eid != EID_ProcStart) return;
        bool fb = false;
        Schema& sc = d.schemaFor(rec, 1, fb);
        if (!sc.valid) return;
        Parsed f;
        if (!decodeEvent(rec, sc, f)) return;
        const quint32 pid = f.pid ? static_cast<quint32>(f.pid) : rec->EventHeader.ProcessId;
        const QString name = QFileInfo(f.image).fileName();
        if (pid && !name.isEmpty())
            d.setProcName(pid, name);          // overwrites stale name on PID reuse
        return;
    }

    // ---- Kernel-File: cheap early filter on event id ----
    switch (eid) {
    case EID_NameCreate: case EID_NameDelete: case EID_Create: case EID_CreateNewFile:
    case EID_Cleanup: case EID_Close: case EID_Read: case EID_Write: case EID_Delete:
    case EID_DeletePath: case EID_RenamePath: case EID_QueryInfo: case EID_OperationEnd:
        break;
    default:
        return;
    }

    MonitorSettings settings;
    {
        QMutexLocker lock(&m_settingsMutex);
        settings = m_settings;
    }

    // Reads/queries are only decoded if wanted; everything else feeds correlation.
    // OperationEnd is pure overhead unless File Query is on — it fires for
    // essentially every completed file operation system-wide, not just
    // queries, so it's entirely gated behind the same setting.
    if (eid == EID_Read && !settings.trackFileRead) return;
    if ((eid == EID_QueryInfo || eid == EID_OperationEnd) && !settings.trackFileQuery) return;

    bool usedFallback = false;
    Schema& sc = d.schemaFor(rec, 0, usedFallback);
    if (usedFallback && !d.warnedFallback) {
        d.warnedFallback = true;
        emit statusMessage(QStringLiteral(
            "TDH schema unavailable for Kernel-File — using built-in event layout."));
    }
    if (!sc.valid) return;

    Parsed f;
    if (!decodeEvent(rec, sc, f)) return;

    const quint32 hdrPid = rec->EventHeader.ProcessId;
    const Tick evTick = eventTick(rec);

    // suppressed > 0 means `throttled()` swallowed this many identical
    // events since the last one that was actually shown — "visible
    // coalescing": fold that into the row instead of just losing it.
    auto emitFile = [&](ActivityEvent::Type type, quint32 pid, const QString& details,
                        int suppressed = 0) {
        if (pid == d.selfPid) return;                       // ignore our own I/O
        const QString name = d.procName(pid);
        if (!settings.processNameFilter.isEmpty() &&
            !name.contains(settings.processNameFilter, Qt::CaseInsensitive))
            return;
        // Capture-time path include/exclude (prefix match on details path text).
        if (!settings.pathPassesCaptureFilter(details))
            return;
        ActivityEvent ev;
        ev.type = type;
        ev.pid = static_cast<int>(pid);
        ev.processName = name;
        ev.details = (suppressed > 0)
            ? details + QString("  (×%1 recently)").arg(suppressed + 1)
            : details;
        ev.timestamp = QDateTime::currentDateTime();
        emit fileEventDetected(ev);
    };

    auto resolve = [&](QString& path, quint32& openerPid) {
        auto it = d.byObject.constFind(f.fileObject);
        if (f.fileObject && it != d.byObject.constEnd()) {
            path = it.value().path;
            openerPid = it.value().pid;
        } else if (f.fileKey) {
            path = d.byKey.value(f.fileKey);
        }
    };

    auto tr = [&](const char* what, const QString& path, quint32 pid) {
        if (d.traceMatch(path))
            d.trace(QString("ETW %1 eid=%2 pid=%3 (%4) fo=0x%5 path=%6")
                    .arg(what).arg(eid).arg(pid).arg(d.procName(pid))
                    .arg(f.fileObject, 0, 16).arg(path));
    };

    switch (eid) {

    case EID_NameCreate: {
        const QString p = ntPathToWin32(f.path);
        if (f.fileKey && !p.isEmpty()) {
            if (static_cast<size_t>(d.byKey.size()) > kMaxTrackedObjects) d.byKey.clear();
            d.byKey.insert(f.fileKey, p);
        }
        return;
    }
    case EID_NameDelete:
        if (f.fileKey) d.byKey.remove(f.fileKey);      // cache eviction, NOT a delete
        return;

    case EID_Cleanup: {                                 // a handle was closed
        QString path; quint32 opener = 0;
        resolve(path, opener);
        if (path.isEmpty()) return;
        d.noteActivity(path, hdrPid, 'x', evTick);
        tr("cleanup", path, hdrPid);
        return;
    }
    case EID_Close: {
        auto it = d.byObject.find(f.fileObject);
        if (f.fileObject && it != d.byObject.end()) {
            d.noteClose(it.value().path, f.fileObject);
            d.byObject.erase(it);
        }
        return;
    }

    case EID_Create:
    case EID_CreateNewFile: {
        const QString path = ntPathToWin32(f.path);
        if (path.isEmpty()) return;
        if (f.fileObject) {
            if (static_cast<size_t>(d.byObject.size()) > kMaxTrackedObjects) d.byObject.clear();
            d.byObject.insert(f.fileObject, { path, hdrPid });
        }
        const bool isDir = (f.options & kFileDirectoryFile) || path.endsWith(QLatin1Char('\\'));
        if (isDir) return;

        const quint32 disp = (static_cast<quint32>(f.options) >> 24) & 0xFF;
        const bool creates = (eid == EID_CreateNewFile);
        const bool overwrites = (disp == kDispOverwrite);
        d.noteOpen(path, f.fileObject, hdrPid);
        d.noteActivity(path, hdrPid, (creates || overwrites) ? 'c' : 'o', evTick);
        tr(creates ? "create-new" : "create/open", path, hdrPid);

        if (settings.trackFileOpen) {
            int sup = 0;
            if (!d.throttled('o', hdrPid, path, kCoalesceOtherMs, &sup))
                emitFile(ActivityEvent::Type::FileOpen, hdrPid, path, sup);
        }

        if (settings.trackFileWrite && (creates || overwrites)) {
            d.noteReported('w', path, evTick);
            int sup = 0;
            if (!d.throttled('w', hdrPid, path, kCoalesceWriteMs, &sup))
                emitFile(ActivityEvent::Type::FileWrite, hdrPid,
                         path + (creates ? QStringLiteral("  (create)")
                                         : QStringLiteral("  (overwrite)")), sup);
        }
        return;
    }

    case EID_Read:
    case EID_Write: {
        const bool isWrite = (eid == EID_Write);
        if (isWrite ? !settings.trackFileWrite : !settings.trackFileRead) return;

        QString path;
        quint32 opener = 0;
        resolve(path, opener);
        if (path.isEmpty()) {
            if (hdrPid != 4 && hdrPid != 0) {
                ++d.unresolved;
                if (isWrite && !d.traceFilter.isEmpty())
                    d.trace(QString("ETW UNRESOLVED write pid=%1 (%2) fo=0x%3 key=0x%4")
                            .arg(hdrPid).arg(d.procName(hdrPid))
                            .arg(f.fileObject, 0, 16).arg(f.fileKey, 0, 16));
            }
            return;
        }
        // Lazy-writer / cache-manager I/O shows up as System: blame the opener.
        const quint32 pid = ((hdrPid == 4 || hdrPid == 0) && opener) ? opener : hdrPid;
        if (isWrite && !d.throttled('A', pid, path, 250)) {
            d.noteActivity(path, pid, 'w', evTick);
            d.noteReported('w', path, evTick);
            tr("write", path, pid);
        }
        int sup = 0;
        if (d.throttled(isWrite ? 'w' : 'r', pid, path,
                        isWrite ? kCoalesceWriteMs : kCoalesceReadMs, &sup))
            return;
        emitFile(isWrite ? ActivityEvent::Type::FileWrite : ActivityEvent::Type::FileRead,
                 pid, path, sup);
        return;
    }

    case EID_QueryInfo: {
        // A process asked for metadata (attributes/size/etc.) about a file
        // it already has a HANDLE open on. This does NOT catch
        // GetFileAttributesW()-style existence checks that never open a
        // handle — see the trackFileQuery comment in MonitorSettings.h.
        //
        // The event itself only tells us WHICH kind of metadata was asked
        // for (f.infoClass) — never the actual values returned. The
        // success/failure of the call arrives in a separate OperationEnd
        // event a moment later, correlated by IRP, so we hold this one in
        // `pendingQueries` rather than emitting immediately.
        QString path;
        quint32 opener = 0;
        resolve(path, opener);
        if (path.isEmpty()) return;
        const quint32 pid = ((hdrPid == 4 || hdrPid == 0) && opener) ? opener : hdrPid;

        if (!f.irp) {
            // No Irp to correlate against (seen on some older builds) —
            // show what we know rather than lose the event entirely.
            int sup = 0;
            if (!d.throttled('q', pid, path, kCoalesceOtherMs, &sup))
                emitFile(ActivityEvent::Type::FileQuery, pid,
                         path + QStringLiteral("  —  ") +
                         fileInfoClassToString(static_cast<quint32>(f.infoClass)), sup);
            return;
        }
        if (static_cast<size_t>(d.pendingQueries.size()) > kMaxPendingQueries)
            d.prunePendingQueries(evTick);
        if (static_cast<size_t>(d.pendingQueries.size()) > kMaxPendingQueries)
            d.pendingQueries.clear();
        d.pendingQueries.insert(f.irp, { path, pid, static_cast<quint32>(f.infoClass), evTick });
        return;
    }

    case EID_OperationEnd: {
        if (!f.irp) return;
        auto it = d.pendingQueries.find(f.irp);
        if (it == d.pendingQueries.end()) return;   // completion of some other op we don't track
        const auto pq = it.value();
        d.pendingQueries.erase(it);

        const quint32 st32 = static_cast<quint32>(f.status);
        const bool isBufferTooSmall = (st32 == 0x80000005);
        QString result;
        if (st32 == 0) {
            result = QStringLiteral("OK");
        } else {
            // NTSTATUS top 2 bits = severity: 0 success, 1 informational,
            // 2 warning, 3 error. Only true errors get labelled FAILED —
            // e.g. a truncated-buffer warning is not really a "failure".
            const quint32 severity = st32 >> 30;
            result = (severity == 3 ? QStringLiteral("FAILED: ") : QStringLiteral("WARN: ")) +
                     ntStatusToString(st32);
        }

        // pid+path+infoClass identifies "the same logical query" across a
        // size-probe/retry pair (each call gets its own Irp, so pendingQueries
        // alone can't tell they're related).
        const QString queryKey = QString::number(pq.pid) + QLatin1Char('|') +
                                 pq.path.toLower() + QLatin1Char('|') +
                                 QString::number(pq.infoClass);

        if (isBufferTooSmall) {
            // Don't show this on its own yet — hold it until we know
            // whether a same-query retry follows. If nothing ever follows
            // (app queried but never retried, or exited first), the
            // periodic sweep below eventually drops it silently; that's a
            // deliberate tradeoff for not showing a confusing orphan WARN
            // on what is, in the overwhelming majority of cases, just the
            // first half of a normal two-call pattern.
            d.recentBufferTooSmall.insert(queryKey, evTick);
            if (d.recentBufferTooSmall.size() > 5000) {
                for (auto i = d.recentBufferTooSmall.begin(); i != d.recentBufferTooSmall.end();) {
                    if (evTick - i.value() > 3000) i = d.recentBufferTooSmall.erase(i); else ++i;
                }
            }
            return;
        }

        // Outcome-aware throttle key: a WARN and the OK that follows it are
        // DIFFERENT outcomes for the same query, so they must not share a
        // coalesce bucket — otherwise the retry's real result can get
        // silently swallowed as if it were "just a duplicate" of the WARN,
        // which is exactly the confusing behavior being fixed here.
        int sup = 0;
        // Folding the outcome class ("OK"/"WARN"/"FAIL") into the throttled()
        // path argument gives WARN and OK their own separate coalesce
        // buckets for the same file, without needing a new throttled()
        // overload.
        if (d.throttled('q', pq.pid, pq.path + QLatin1Char('|') + result.left(4), kCoalesceOtherMs, &sup))
            return;

        QString details = pq.path + QStringLiteral("  —  ") + fileInfoClassToString(pq.infoClass) +
                          QStringLiteral("  →  ") + result;

        auto warnIt = d.recentBufferTooSmall.find(queryKey);
        if (warnIt != d.recentBufferTooSmall.end()) {
            if (evTick - warnIt.value() < 2000)
                details += QStringLiteral(" (after an initial buffer-too-small probe — "
                                          "this is the normal ask-size-then-ask-again pattern)");
            d.recentBufferTooSmall.erase(warnIt);
        }

        emitFile(ActivityEvent::Type::FileQuery, pq.pid, details, sup);
        return;
    }

    case EID_Delete:
    case EID_DeletePath: {
        QString path = (eid == EID_DeletePath) ? ntPathToWin32(f.path) : QString();
        quint32 opener = 0;
        if (path.isEmpty()) resolve(path, opener);
        if (path.isEmpty()) return;
        d.noteActivity(path, hdrPid, 'd', evTick);
        d.noteReported('d', path, evTick);
        tr("delete", path, hdrPid);
        if (!settings.trackFileDelete) return;
        int sup = 0;
        if (d.throttled('d', hdrPid, path, kCoalesceOtherMs, &sup)) return;   // 18 + 26 dedupe
        emitFile(ActivityEvent::Type::FileDelete, hdrPid, path, sup);
        return;
    }

    case EID_RenamePath: {
        const QString newPath = ntPathToWin32(f.path);
        if (newPath.isEmpty()) return;
        QString oldPath;
        quint32 opener = 0;
        resolve(oldPath, opener);
        if (f.fileObject) {
            auto it = d.byObject.find(f.fileObject);
            if (it != d.byObject.end()) it.value().path = newPath;
        }
        if (f.fileKey) d.byKey.insert(f.fileKey, newPath);

        d.noteActivity(newPath, hdrPid, 'n', evTick);
        d.noteReported('n', newPath, evTick);
        tr("rename", newPath, hdrPid);
        if (!settings.trackFileRename) return;
        int sup = 0;
        if (d.throttled('n', hdrPid, newPath, kCoalesceOtherMs, &sup)) return;
        if (!oldPath.isEmpty() && oldPath.compare(newPath, Qt::CaseInsensitive) != 0)
            emitFile(ActivityEvent::Type::FileRename, hdrPid,
                     oldPath + QStringLiteral(" \u2192 ") + newPath, sup);
        else
            emitFile(ActivityEvent::Type::FileRename, hdrPid,
                     QStringLiteral("(renamed to) ") + newPath, sup);
        return;
    }

    default:
        return;
    }
}

// ============================================================
// Thread body: start session, enable providers, consume
// ============================================================
void EtwFileWatcher::run()
{
    emit statusMessage(QStringLiteral("Starting Kernel-File ETW + USN journal…"));
    g_etwInstance = this;
    m_stopRequested.storeRelease(0);
    m_usnStop.storeRelease(0);
    m_d->reset();
    m_d->refreshSnapshot();            // names for processes that already exist

    // Optional diagnostics: set env PM_ETW_TRACE=AutomaticDestinations (any path
    // substring) before starting the app; every matching ETW/USN event is
    // appended to %TEMP%\pm_etw_trace.log.
    m_d->traceFilter = qEnvironmentVariable("PM_ETW_TRACE");
    if (!m_d->traceFilter.isEmpty()) {
        m_d->tracePath = qEnvironmentVariable("TEMP") + QStringLiteral("\\pm_etw_trace.log");
        QFile::remove(m_d->tracePath);
        emit statusMessage(QString("Tracing paths containing '%1' to %2")
                           .arg(m_d->traceFilter, m_d->tracePath));
    } else {
        m_d->tracePath.clear();
    }

    struct SessionProps {
        EVENT_TRACE_PROPERTIES props;
        WCHAR name[256];
    };
    auto initProps = [](SessionProps& sp) {
        ZeroMemory(&sp, sizeof(sp));
        sp.props.Wnode.BufferSize = sizeof(sp);
        sp.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sp.props.Wnode.ClientContext = 1;
        sp.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sp.props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        sp.props.BufferSize = 512;
        sp.props.MinimumBuffers = 64;
        sp.props.MaximumBuffers = 256;
        sp.props.FlushTimer = 1;        // deliver at least once per second
        wcscpy_s(sp.name, SESSION_NAME);
    };

    SessionProps sp;
    initProps(sp);
    TRACEHANDLE hSession = 0;
    ULONG result = StartTraceW(&hSession, SESSION_NAME, &sp.props);

    if (result == ERROR_ALREADY_EXISTS) {
        // Stale session from a previous crashed run.
        ControlTraceW(0, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        initProps(sp);
        result = StartTraceW(&hSession, SESSION_NAME, &sp.props);
    }
    if (result == ERROR_ACCESS_DENIED) {
        emit errorOccurred(QStringLiteral("Access denied — run as Administrator."));
        return;
    }
    if (result != ERROR_SUCCESS) {
        emit errorOccurred(QString("StartTrace failed: %1").arg(result));
        return;
    }
    { QMutexLocker hl(&m_handleMutex); m_sessionHandle = reinterpret_cast<void*>(hSession); }

    const ULONGLONG fileKeywords =
        KW_FILENAME | KW_FILEIO | KW_CREATE | KW_READ | KW_WRITE |
        KW_DELETE_PATH | KW_RENAME_SETLINK_PATH | KW_CREATE_NEW_FILE;

    result = EnableTraceEx2(hSession, &KernelFileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
        fileKeywords, 0, 0, nullptr);
    if (result != ERROR_SUCCESS) {
        emit errorOccurred(QString("EnableTraceEx2 (Kernel-File) failed: %1").arg(result));
        ControlTraceW(hSession, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = nullptr;
        return;
    }

    // Best effort: process start events (names of short-lived processes).
    EnableTraceEx2(hSession, &KernelProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
        KWP_PROCESS, 0, 0, nullptr);

    // Best effort: ask the provider to emit names of files that are already
    // open, so reads/writes to them can be resolved. Harmless if unsupported.
    EnableTraceEx2(hSession, &KernelFileProviderGuid,
        EVENT_CONTROL_CODE_CAPTURE_STATE, TRACE_LEVEL_INFORMATION,
        fileKeywords, 0, 0, nullptr);

    emit statusMessage(QStringLiteral(
        "Kernel-File ETW + USN journal active — USN detects every change, ETW supplies the PID."));

    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    logFile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = eventRecordCallback;

    TRACEHANDLE hConsumer = OpenTraceW(&logFile);
    if (hConsumer == reinterpret_cast<TRACEHANDLE>(INVALID_HANDLE_VALUE)) {
        emit errorOccurred(QString("OpenTrace failed: %1").arg(GetLastError()));
        ControlTraceW(hSession, SESSION_NAME, &sp.props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = nullptr;
        return;
    }
    { QMutexLocker hl(&m_handleMutex); m_consumerHandle = reinterpret_cast<void*>(hConsumer); }

    std::thread usnThread([this]() { usnWatcherMain(); });

    ULONG pr = ProcessTrace(&hConsumer, 1, nullptr, nullptr);
    if (pr != ERROR_SUCCESS && pr != ERROR_CANCELLED)
        emit errorOccurred(QString("ProcessTrace ended: %1").arg(pr));

    m_usnStop.storeRelease(1);
    usnThread.join();

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
    emit statusMessage(QStringLiteral("ETW file watcher stopped."));
}


// ============================================================
// USN journal (detector) — MinGW: FRN is DWORDLONG, not LARGE_INTEGER
// ============================================================
static QString pathFromFileId(HANDLE hVolume, ULONGLONG frn)
{
    FILE_ID_DESCRIPTOR fid;
    memset(&fid, 0, sizeof(fid));
    fid.dwSize = sizeof(fid);
    fid.Type = FileIdType;
    fid.FileId.QuadPart = static_cast<LONGLONG>(frn);

    HANDLE hFile = OpenFileById(
        hVolume, &fid, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, FILE_FLAG_BACKUP_SEMANTICS);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};

    wchar_t buf[MAX_PATH * 4] = {};
    DWORD n = GetFinalPathNameByHandleW(hFile, buf, MAX_PATH * 4, FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    if (n == 0 || n >= MAX_PATH * 4)
        return {};
    QString p = QString::fromWCharArray(buf, static_cast<int>(n));
    if (p.startsWith(QStringLiteral("\\\\?\\")))
        p = p.mid(4);
    return p;
}

void EtwFileWatcher::usnWatcherMain()
{
    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(511, drives))
        return;

    struct Vol {
        QString root;
        HANDLE  h = INVALID_HANDLE_VALUE;
        USN     nextUsn = 0;
        DWORDLONG journalId = 0;
        QHash<ULONGLONG, QString> frnToPath;
        // FRN -> old path, paired with the matching NEW_NAME record.
        // Per volume, because FRNs can collide across volumes.
        QHash<ULONGLONG, QString> renameOldByFrn;
    };
    std::vector<Vol*> vols;

    for (const wchar_t* dr = drives; *dr; dr += wcslen(dr) + 1) {
        if (GetDriveTypeW(dr) != DRIVE_FIXED)
            continue;
        wchar_t volPath[16] = {};
        swprintf_s(volPath, L"\\\\.\\%c:", dr[0]);
        HANDLE h = CreateFileW(volPath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        USN_JOURNAL_DATA journal = {};
        DWORD ret = 0;
        if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                             &journal, sizeof(journal), &ret, nullptr)) {
            CloseHandle(h);
            continue;
        }
        Vol* v = new Vol;
        v->root = QString::fromWCharArray(dr);
        v->h = h;
        v->nextUsn = journal.NextUsn;
        v->journalId = journal.UsnJournalID;
        vols.push_back(v);
    }

    if (vols.empty())
        emit statusMessage(QStringLiteral("USN journal unavailable on all volumes (NTFS + admin required)."));

    std::vector<BYTE> buf(256 * 1024);

    while (!m_usnStop.loadAcquire()) {
        for (Vol* v : vols) {
            if (m_usnStop.loadAcquire()) break;

            READ_USN_JOURNAL_DATA readData = {};
            readData.StartUsn = v->nextUsn;
            readData.ReasonMask =
                USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE |
                USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
                USN_REASON_DATA_TRUNCATION | USN_REASON_RENAME_OLD_NAME |
                USN_REASON_RENAME_NEW_NAME | USN_REASON_HARD_LINK_CHANGE |
                USN_REASON_CLOSE;
            readData.ReturnOnlyOnClose = FALSE;
            readData.Timeout = 0;
            readData.BytesToWaitFor = 0;
            readData.UsnJournalID = v->journalId;

            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(v->h, FSCTL_READ_USN_JOURNAL,
                &readData, sizeof(readData),
                buf.data(), static_cast<DWORD>(buf.size()), &bytes, nullptr);

            if (!ok) {
                DWORD err = GetLastError();
                if (err == ERROR_JOURNAL_ENTRY_DELETED || err == ERROR_JOURNAL_NOT_ACTIVE) {
                    USN_JOURNAL_DATA journal = {};
                    DWORD r = 0;
                    if (DeviceIoControl(v->h, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                                        &journal, sizeof(journal), &r, nullptr)) {
                        v->nextUsn = journal.NextUsn;
                        v->journalId = journal.UsnJournalID;
                    }
                }
                continue;
            }
            if (bytes > sizeof(USN)) {
                USN next = *reinterpret_cast<const USN*>(buf.data());
                processUsnBuffer(v->h, v->root, &v->frnToPath, &v->renameOldByFrn,
                                 reinterpret_cast<const char*>(buf.data()),
                                 static_cast<unsigned int>(bytes));
                v->nextUsn = next;
            }
        }
        flushPendingUsn(false);
        Sleep(200);
    }

    flushPendingUsn(true);
    for (Vol* v : vols) {
        if (v->h != INVALID_HANDLE_VALUE) CloseHandle(v->h);
        delete v;
    }
}

// Reads a buffer of USN records and QUEUES the changes; they are attributed and
// emitted by flushPendingUsn() once ETW has had time to deliver its side.
void EtwFileWatcher::processUsnBuffer(void* hVol, const QString& volumeRoot, void* frnMapPtr,
                                      void* renameOldMapPtr, const char* buffer, unsigned int bytes)
{
    if (!buffer || bytes < sizeof(USN) || !m_d) return;
    Impl& d = *m_d;
    HANDLE hVolume = static_cast<HANDLE>(hVol);
    auto& frnToPath = *static_cast<QHash<ULONGLONG, QString>*>(frnMapPtr);
    auto& renameOldByFrn = *static_cast<QHash<ULONGLONG, QString>*>(renameOldMapPtr);

    MonitorSettings settings;
    {
        QMutexLocker lock(&m_settingsMutex);
        settings = m_settings;
    }

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    const ULONGLONG nowFile = (static_cast<ULONGLONG>(nowFt.dwHighDateTime) << 32) | nowFt.dwLowDateTime;
    const Tick readTick = nowTick();

    const char* ptr = buffer + sizeof(USN);
    const char* end = buffer + bytes;

    while (ptr + sizeof(USN_RECORD) <= end) {
        const USN_RECORD* r = reinterpret_cast<const USN_RECORD*>(ptr);
        if (r->RecordLength == 0 || ptr + r->RecordLength > end)
            break;

        const ULONGLONG frn = static_cast<ULONGLONG>(r->FileReferenceNumber);
        const ULONGLONG parentFrn = static_cast<ULONGLONG>(r->ParentFileReferenceNumber);
        const DWORD reason = r->Reason;

        const QString name = QString::fromWCharArray(
            reinterpret_cast<const WCHAR*>(reinterpret_cast<const BYTE*>(r) + r->FileNameOffset),
            r->FileNameLength / sizeof(WCHAR));

        QString fullPath;
        {
            const QString parentPath = frnToPath.value(parentFrn);
            if (!parentPath.isEmpty())
                fullPath = parentPath + QLatin1Char('\\') + name;
            else if (frnToPath.contains(frn))
                fullPath = frnToPath.value(frn);

            if (reason & (USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME |
                          USN_REASON_HARD_LINK_CHANGE)) {
                if (!fullPath.isEmpty()) frnToPath[frn] = fullPath;
            }
            if ((reason & USN_REASON_RENAME_OLD_NAME) && fullPath.isEmpty())
                fullPath = frnToPath.value(frn);
            // Keep the OLD path until the matching NEW_NAME record arrives, so
            // the rename can be reported as "old -> new" instead of "new" alone.
            if ((reason & USN_REASON_RENAME_OLD_NAME) && !fullPath.isEmpty()) {
                if (renameOldByFrn.size() > 10000) renameOldByFrn.clear();   // bound memory
                renameOldByFrn[frn] = fullPath;
            }
            if ((reason & USN_REASON_FILE_DELETE) && fullPath.isEmpty())
                fullPath = frnToPath.take(frn);
        }

        if ((fullPath.isEmpty() || !fullPath.contains(QLatin1Char(':'))) &&
            hVolume != INVALID_HANDLE_VALUE) {
            const QString byId = pathFromFileId(hVolume, frn);
            if (!byId.isEmpty()) {
                fullPath = byId;
                if (frnToPath.size() > 500000) frnToPath.clear();
                frnToPath[frn] = fullPath;
                const QString parentDir = QFileInfo(fullPath).absolutePath();
                if (!parentDir.isEmpty() && parentFrn)
                    frnToPath[parentFrn] = QDir::toNativeSeparators(parentDir);
            }
        }
        if (fullPath.isEmpty() && !name.isEmpty())
            fullPath = volumeRoot + name;

        // Timestamp of the change on our tick timeline.
        const ULONGLONG recFile = static_cast<ULONGLONG>(r->TimeStamp.QuadPart);
        Tick usnTick = readTick;
        if (nowFile >= recFile) {
            const ULONGLONG ageMs = (nowFile - recFile) / 10000ULL;
            if (ageMs < 600000ULL) usnTick = readTick - static_cast<Tick>(ageMs);
        }

        if (d.traceMatch(fullPath))
            d.trace(QString("USN reason=0x%1 path=%2").arg(reason, 0, 16).arg(fullPath));

        auto queue = [&](ActivityEvent::Type type, const QString& suffix, char rk, char ak) {
            if (fullPath.isEmpty()) return;
            if (d.pendingUsn.size() > 50000) d.pendingUsn.pop_front();
            d.pendingUsn.push_back({ type, fullPath, suffix, QString::number(reason, 16),
                                     usnTick, readTick, rk, ak });
        };

        if ((reason & USN_REASON_FILE_CREATE) && settings.trackFileWrite)
            queue(ActivityEvent::Type::FileWrite, QStringLiteral("  (create)"), 'w', 'c');

        if ((reason & (USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
                       USN_REASON_DATA_TRUNCATION)) && settings.trackFileWrite)
            queue(ActivityEvent::Type::FileWrite, QString(), 'w', 'w');

        if ((reason & USN_REASON_FILE_DELETE) && settings.trackFileDelete)
            queue(ActivityEvent::Type::FileDelete, QString(), 'd', 'd');

        if ((reason & USN_REASON_RENAME_NEW_NAME) && settings.trackFileRename) {
            const QString oldPath = renameOldByFrn.take(frn);
            // Encode the pair in the suffix; flushPendingUsn formats it.
            queue(ActivityEvent::Type::FileRename,
                  oldPath.isEmpty() ? QString()
                                    : QStringLiteral("\x01") + oldPath,
                  'n', 'n');
        }

        ptr += r->RecordLength;
    }
}

// Emits queued USN changes that are old enough for ETW to have caught up.
void EtwFileWatcher::flushPendingUsn(bool force)
{
    if (!m_d) return;
    Impl& d = *m_d;
    if (d.pendingUsn.empty()) return;

    MonitorSettings settings;
    {
        QMutexLocker lock(&m_settingsMutex);
        settings = m_settings;
    }

    const Tick now = nowTick();
    while (!d.pendingUsn.empty()) {
        const Impl::PendingUsn p = d.pendingUsn.front();
        if (!force && now - p.readTick < kAttribDelayMs)
            break;
        d.pendingUsn.pop_front();

        // ETW already reported this change (with a PID) -> don't duplicate.
        if (d.wasReported(p.reportedKind, p.path, p.usnTick, 3000)) {
            if (d.traceMatch(p.path))
                d.trace(QString("USN -> suppressed (ETW already reported) %1").arg(p.path));
            continue;
        }

        const Impl::Attr a = d.attribute(p.path, p.usnTick, p.attrKind);
        if (a.pid == d.selfPid && a.pid != 0) continue;          // our own I/O

        const QString name = a.pid ? a.name : QStringLiteral("(USN)");
        if (!settings.processNameFilter.isEmpty() &&
            (a.pid == 0 || !name.contains(settings.processNameFilter, Qt::CaseInsensitive)))
            continue;

        if (d.traceMatch(p.path))
            d.trace(QString("USN -> emitted pid=%1 (%2) %3").arg(a.pid).arg(name).arg(p.path));

        ActivityEvent ev;
        ev.type = p.type;
        ev.pid = static_cast<int>(a.pid);
        ev.processName = name;
        if (p.type == ActivityEvent::Type::FileRename && p.suffix.startsWith(QChar(0x01))) {
            // Paired rename: suffix carries the old path after a marker char.
            const QString oldPath = p.suffix.mid(1);
            ev.details = oldPath + QStringLiteral(" -> ") + p.path + a.extra;
        } else if (p.type == ActivityEvent::Type::FileRename) {
            ev.details = QStringLiteral("(renamed to) ") + p.path + a.extra;
        } else {
            ev.details = p.path + p.suffix + a.extra;
        }
        ev.timestamp = QDateTime::currentDateTime();
        emit fileEventDetected(ev);
    }
}
