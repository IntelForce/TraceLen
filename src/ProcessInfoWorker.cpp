// ============================================================
// ProcessInfoWorker.cpp  —  Background process metadata fetcher
// ============================================================

// ---- Windows headers (strict order required) ----
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>       // QueryFullProcessImageNameW
#include <winternl.h>    // PROCESS_BASIC_INFORMATION (for command line)
#include <softpub.h>     // WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <wintrust.h>    // WinVerifyTrust (Authenticode)
#include <wincrypt.h>    // CryptQueryObject / CertGetNameStringW (signer name)
// Note: advapi32 (service), version (file info), wintrust + crypt32
// (Authenticode signature check) are linked via CMakeLists

// ---- Standard C++ ----
#include <vector>

// ---- Qt ----
#include <QMutexLocker>
#include <QFileInfo>

#include "ProcessInfoWorker.h"

// A fetch is "useful" when at least one field came back. A PID that is
// protected or already gone yields nothing; that is not worth remembering.
static bool infoIsUseful(const ProcInfo& i)
{
    return !i.path.isEmpty() || !i.publisher.isEmpty() || !i.version.isEmpty() ||
           !i.service.isEmpty() || !i.cmdLine.isEmpty() || !i.user.isEmpty();
}

static const int kMaxCacheEntries = 20000;
static const quint64 kServiceCacheMs = 5000;   // refresh service map every 5 s

// ============================================================
// Constructor / Destructor
// ============================================================
ProcessInfoWorker::ProcessInfoWorker(QObject* parent)
    : QThread(parent), m_stopRequested(0) {}

ProcessInfoWorker::~ProcessInfoWorker()
{
    requestStop();
    wait(5000);
}

void ProcessInfoWorker::requestStop()
{
    { QMutexLocker lock(&m_mutex); m_stopRequested.storeRelease(1); }
    m_condition.wakeAll();
}

// ============================================================
// queueFetch()  —  called from the UI thread
// ============================================================
void ProcessInfoWorker::queueFetch(int pid)
{
    if (pid <= 0) return;

    QMutexLocker lock(&m_mutex);

    // Return cached result immediately if available
    if (m_cache.contains(pid))
    {
        ProcInfo cached = m_cache[pid];
        lock.unlock();
        emit infoReady(pid, cached);
        return;
    }

    if (m_queued.contains(pid)) return;   // Already queued, skip

    m_queue.enqueue(pid);
    m_queued.insert(pid);
    m_condition.wakeOne();
}

// ============================================================
// run()  —  background thread main loop
// ============================================================
void ProcessInfoWorker::run()
{
    while (m_stopRequested.loadAcquire() == 0)
    {
        int  pid     = 0;
        bool hasWork = false;

        {
            QMutexLocker lock(&m_mutex);
            if (m_queue.isEmpty())
                m_condition.wait(&m_mutex, 500);

            if (!m_queue.isEmpty())
            {
                pid     = m_queue.dequeue();
                hasWork = true;
            }
        }

        if (!hasWork) continue;

        // Fetch all metadata for this PID (may take a few hundred ms)
        ProcInfo info = fetchOne(pid);

        {
            QMutexLocker lock(&m_mutex);
            m_queued.remove(pid);
            // Cache only a fetch that actually learned something. An empty
            // result usually means access denied or the process already
            // exited; caching it would block any later, successful lookup.
            if (infoIsUseful(info)) {
                if (m_cache.size() >= kMaxCacheEntries) m_cache.clear();
                m_cache[pid] = info;
            }
        }

        emit infoReady(pid, info);
    }
}

// ============================================================
// getPath()  —  full executable path
// ============================================================
// Uses QueryFullProcessImageNameW which works for most processes
// with only PROCESS_QUERY_LIMITED_INFORMATION rights.
// Owner of a process as "DOMAIN\name", read from its access token.
//
// Needs PROCESS_QUERY_LIMITED_INFORMATION to open the process and TOKEN_QUERY
// on its token; both work for normal user-level processes without elevation.
// Protected processes and some system processes deny this, so the result is
// the marker "(access denied)" rather than a blank that looks like a bug.
// A PID that has already exited returns "(process exited)".
QString ProcessInfoWorker::getProcessUser(int pid) const
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               static_cast<DWORD>(pid));
    if (!hProc) {
        return (GetLastError() == ERROR_INVALID_PARAMETER)
                   ? QStringLiteral("(process exited)")
                   : QStringLiteral("(access denied)");
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return QStringLiteral("(access denied)");
    }
    CloseHandle(hProc);

    // First call sizes the buffer, second fills it.
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0) { CloseHandle(hToken); return {}; }

    std::vector<BYTE> buf(needed);
    QString result;
    if (GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed)) {
        const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD nameLen = 256, domainLen = 256;
        SID_NAME_USE use = SidTypeUnknown;
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen,
                              domain, &domainLen, &use)) {
            const QString n = QString::fromWCharArray(name);
            const QString d = QString::fromWCharArray(domain);
            result = d.isEmpty() ? n : d + QLatin1Char('\\') + n;
        } else {
            result = QStringLiteral("(unresolved SID)");
        }
    }
    CloseHandle(hToken);
    return result;
}

QString ProcessInfoWorker::getPath(int pid) const
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, static_cast<DWORD>(pid));
    if (!h) return {};

    wchar_t buf[MAX_PATH] = {};
    DWORD   sz = MAX_PATH;
    BOOL    ok = QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);

    return ok ? QString::fromWCharArray(buf) : QString();
}

// ============================================================
// getVersionInfo()  —  publisher + version from the PE file
// ============================================================
// Windows PE files often embed a "version resource" containing
// strings like CompanyName, FileVersion, ProductName, etc.
// We use these Win32 functions:
//   GetFileVersionInfoSizeW  — how many bytes to allocate
//   GetFileVersionInfoW      — fill the buffer
//   VerQueryValueW           — extract a specific string
//
// The strings are stored under a locale key.  We first read
// the "Translation" block to find which locale(s) are present,
// then query the CompanyName and FileVersion for that locale.
QPair<QString, QString> ProcessInfoWorker::getVersionInfo(
    const QString& exePath) const
{
    if (exePath.isEmpty()) return {};

    const std::wstring wpath = exePath.toStdWString();

    // Step 1 — How much space do we need?
    DWORD dummy = 0;
    DWORD size  = GetFileVersionInfoSizeW(wpath.c_str(), &dummy);
    if (size == 0) return {};

    // Step 2 — Fill the buffer
    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(wpath.c_str(), 0, size, buf.data()))
        return {};

    // Step 3 — Read the translation table
    // The translation table is an array of {WORD language, WORD codepage} pairs.
    // We only read the first entry (index 0) for simplicity.
    struct LangCodepage { WORD language; WORD codepage; };
    LangCodepage* trans = nullptr;
    UINT          transLen = 0;

    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                        reinterpret_cast<LPVOID*>(&trans), &transLen)
        || transLen == 0)
        return {};

    // Step 4 — Build the query string for each value we want.
    // Format: "\\StringFileInfo\\LLLLCCCC\\ValueName"
    // where LLLL = language hex, CCCC = codepage hex
    auto queryString = [&](const wchar_t* valueName) -> QString
    {
        wchar_t query[128];
        swprintf_s(query, 128,
                   L"\\StringFileInfo\\%04X%04X\\%s",
                   trans[0].language, trans[0].codepage, valueName);

        wchar_t* value = nullptr;
        UINT     valueLen = 0;
        if (!VerQueryValueW(buf.data(), query,
                            reinterpret_cast<LPVOID*>(&value), &valueLen)
            || !value || valueLen == 0)
            return {};

        return QString::fromWCharArray(value).trimmed();
    };

    QString publisher = queryString(L"CompanyName");
    QString version   = queryString(L"FileVersion");

    return { publisher, version };
}

// ============================================================
// isUnusualLocation()  —  classic "dropped it somewhere weird" paths
// ============================================================
// A verified signature means the FILE wasn't tampered with — it says
// nothing about whether it's suspicious for that particular, genuinely
// signed binary to be running from this particular folder. A real copy of
// a signed tool (even a Microsoft one — "living off the land" abuse uses
// legitimate signed binaries on purpose) launched from a temp/downloads
// folder is a much stronger signal than an unsigned file in Program Files.
// Kept deliberately narrow and high-confidence to avoid flagging the many
// legitimately-signed apps that install under AppData\Local\<Vendor> —
// this only matches folders nothing is supposed to run from long-term.
bool ProcessInfoWorker::isUnusualLocation(const QString& path) const
{
    const QString p = path.toLower();
    static const QStringList kUnusualFragments = {
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\$recycle.bin\\",
        "\\users\\public\\",
    };
    for (const QString& frag : kUnusualFragments)
        if (p.contains(frag)) return true;
    return false;
}

// ============================================================
// getSignatureInfo()  —  real Authenticode verification
// ============================================================
// Unlike getVersionInfo()'s CompanyName (just a text string any file can
// claim), this cryptographically checks whether the file carries a valid
// Authenticode signature, using the same API Windows itself uses for
// "right-click -> Properties -> Digital Signatures".
//
//   WinVerifyTrust()  — does the actual chain-of-trust verification
//
// Deliberately offline-only:
//   * fdwRevocationChecks = WTD_REVOKE_NONE   (no CRL/OCSP network checks)
//   * dwProvFlags has WTD_CACHE_ONLY_URL_RETRIEVAL
// A monitoring tool that might look up many new processes per second can't
// afford to block on a certificate-revocation network round trip (or hang
// if one is unreachable) — so this trades a small amount of accuracy
// (a certificate revoked since it was last cached won't be caught) for
// bounded, local-only latency. If you need full revocation checking,
// flip WTD_REVOKE_NONE to WTD_REVOKE_WHOLECHAIN, but expect occasional
// multi-second stalls on this worker thread when offline or when a CA's
// responder is slow.
QString ProcessInfoWorker::getSignatureInfo(const QString& exePath) const
{
    if (exePath.isEmpty()) return {};
    const std::wstring wpath = exePath.toStdWString();

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct    = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath.c_str();

    WINTRUST_DATA wtd   = {};
    wtd.cbStruct         = sizeof(wtd);
    wtd.dwUIChoice       = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;        // offline only, see comment above
    wtd.dwUnionChoice    = WTD_CHOICE_FILE;
    wtd.pFile            = &fileInfo;
    wtd.dwStateAction    = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags      = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG trustResult = WinVerifyTrust(nullptr, &action, &wtd);

    QString status;
    switch (trustResult) {
    case ERROR_SUCCESS:              status = QStringLiteral("Verified");       break;
    case TRUST_E_NOSIGNATURE:        status = QStringLiteral("Unsigned");       break;
    case TRUST_E_EXPLICIT_DISTRUST:  status = QStringLiteral("Distrusted");     break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:status = QStringLiteral("Untrusted");      break;
    case CERT_E_EXPIRED:             status = QStringLiteral("Expired");       break;
    case CERT_E_UNTRUSTEDROOT:       status = QStringLiteral("Untrusted root");break;
    case CERT_E_REVOKED:             status = QStringLiteral("Revoked");       break;
    case TRUST_E_BAD_DIGEST:         status = QStringLiteral("Tampered");      break;   // file modified after signing
    default:                         status = QStringLiteral("Unverified");    break;
    }

    // Must release the WinVerifyTrust state regardless of the outcome above.
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wtd);

    return status;
}

// ============================================================
// getServiceName()  —  check if this PID is a Windows service
// ============================================================
// The Service Control Manager (SCM) manages all Windows services.
// We open the SCM, enumerate all services, and look for one whose
// dwProcessId matches our target PID.
//
// EnumServicesStatusExW fills a buffer with ENUM_SERVICE_STATUS_PROCESSW
// entries, each containing lpServiceName and ServiceStatusProcess.dwProcessId.
// We do a two-pass call: first to get the required buffer size, then
// to actually retrieve the data.
QString ProcessInfoWorker::getServiceName(int pid) const
{
    // Serve from the cache when it is fresh. Enumerating every service is
    // expensive, and this is called once per PID; the list changes rarely.
    {
        QMutexLocker l(&m_serviceCacheMutex);
        const quint64 now = GetTickCount64();
        if (m_serviceCacheAt != 0 && now - m_serviceCacheAt < kServiceCacheMs) {
            auto it = m_serviceCache.constFind(pid);
            return it != m_serviceCache.constEnd() ? it.value() : QString();
        }
    }

    // Open the Service Control Manager in read-only mode
    SC_HANDLE scm = OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return {};

    DWORD needed    = 0;
    DWORD count     = 0;
    DWORD resume    = 0;

    // First call: get required buffer size (will return FALSE with ERROR_MORE_DATA)
    EnumServicesStatusExW(
        scm, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,      // All Win32 services (own process + shared process)
        SERVICE_STATE_ALL,  // Running and stopped
        nullptr, 0, &needed, &count, &resume, nullptr);

    if (needed == 0) { CloseServiceHandle(scm); return {}; }

    // Second call: fill the buffer with actual data
    std::vector<BYTE> buf(needed);
    resume = 0;
    BOOL ok = EnumServicesStatusExW(
        scm, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32, SERVICE_STATE_ALL,
        buf.data(), static_cast<DWORD>(buf.size()),
        &needed, &count, &resume, nullptr);

    CloseServiceHandle(scm);

    if (!ok) return {};

    // Rebuild the PID -> service map once, then answer from it.
    auto* services =
        reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    QHash<int, QString> fresh;
    for (DWORD i = 0; i < count; ++i)
    {
        const int svcPid = static_cast<int>(services[i].ServiceStatusProcess.dwProcessId);
        if (svcPid <= 0) continue;
        // lpServiceName is the short internal name (e.g., "WSearch")
        // lpDisplayName is the human-readable name (e.g., "Windows Search")
        fresh.insert(svcPid,
                     QString::fromWCharArray(services[i].lpDisplayName)
                     + " (" + QString::fromWCharArray(services[i].lpServiceName) + ")");
    }
    {
        QMutexLocker l(&m_serviceCacheMutex);
        m_serviceCache = fresh;
        m_serviceCacheAt = GetTickCount64();
    }
    auto it = fresh.constFind(pid);
    return it != fresh.constEnd() ? it.value() : QString();
}

// ============================================================
// getCommandLine()  —  read the command line from PEB memory
// ============================================================
// Every Windows process has a "Process Environment Block" (PEB) in
// its own virtual address space.  The PEB contains a pointer to
// RTL_USER_PROCESS_PARAMETERS which has the command line string.
//
// To read another process's memory we:
//   1. Call NtQueryInformationProcess() to learn where its PEB lives.
//   2. Use ReadProcessMemory() to read the PEB.
//   3. Follow the ProcessParameters pointer and read the CommandLine field.
//
// MEMORY LAYOUT (64-bit Windows):
//   PEB + 0x20  → RTL_USER_PROCESS_PARAMETERS*
//   RTL_USER_PROCESS_PARAMETERS + 0x70 → UNICODE_STRING CommandLine
//   UNICODE_STRING: USHORT Length (bytes), USHORT MaxLen, ULONG pad, PWCH Buffer
//
// These offsets have been stable since Windows Vista on 64-bit systems.

// True when `hProc` is a native 64-bit process running on a 64-bit OS, i.e.
// the PEB layout matches the offsets used in getCommandLine(). A WOW64
// process (32-bit app on 64-bit Windows) and any 32-bit process are rejected.
static bool isNative64BitTarget(HANDLE hProc)
{
#if defined(_WIN64)
    using IsWow64Process2_t = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto fn = k32 ? reinterpret_cast<IsWow64Process2_t>(
                        GetProcAddress(k32, "IsWow64Process2")) : nullptr;
    if (fn) {
        USHORT procMachine = 0, nativeMachine = 0;
        if (!fn(hProc, &procMachine, &nativeMachine)) return false;
        // IMAGE_FILE_MACHINE_UNKNOWN (0) means the process is native to the
        // host OS architecture, i.e. not WOW64.
        return procMachine == 0;
    }
    // Older Windows without IsWow64Process2: fall back to IsWow64Process.
    BOOL wow = FALSE;
    if (!IsWow64Process(hProc, &wow)) return false;
    return wow == FALSE;
#else
    Q_UNUSED(hProc);
    return false;   // 32-bit build: the 64-bit offsets never apply.
#endif
}

QString ProcessInfoWorker::getCommandLine(int pid) const
{
    // We need two access rights:
    //   PROCESS_QUERY_INFORMATION — for NtQueryInformationProcess
    //   PROCESS_VM_READ           — for ReadProcessMemory
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, static_cast<DWORD>(pid));
    if (!hProc) return {};

    // ---- Step 1: Get the PEB base address ----
    // NtQueryInformationProcess is exported from ntdll.dll.
    // We load it dynamically (GetProcAddress) because it is not in
    // the standard import libraries — it's an internal NT API.
    using NtQIP_t = NTSTATUS (NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll  = GetModuleHandleW(L"ntdll.dll");
    auto    NtQIP  = reinterpret_cast<NtQIP_t>(
                         GetProcAddress(ntdll, "NtQueryInformationProcess"));

    if (!NtQIP) { CloseHandle(hProc); return {}; }

    // The PEB offsets below are for the NATIVE 64-bit layout. A 32-bit or
    // WOW64 target has a different PEB/ProcessParameters layout, so reading
    // these offsets would return garbage, not an error. Only read targets
    // whose bitness matches this (64-bit) build.
    if (!isNative64BitTarget(hProc)) { CloseHandle(hProc); return {}; }

    // PROCESS_BASIC_INFORMATION (class 0) gives us the PEB address.
    // The struct comes from <winternl.h>.
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = NtQIP(hProc, 0, &pbi, sizeof(pbi), &retLen);
    if (status < 0 || !pbi.PebBaseAddress)
    { CloseHandle(hProc); return {}; }

    // ---- Step 2: Read the ProcessParameters pointer from the PEB ----
    // On 64-bit Windows, PEB::ProcessParameters is at byte offset 0x20.
    PVOID procParamsPtr = nullptr;
    SIZE_T bytesRead    = 0;
    if (!ReadProcessMemory(
            hProc,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParamsPtr, sizeof(PVOID), &bytesRead)
        || !procParamsPtr)
    { CloseHandle(hProc); return {}; }

    // ---- Step 3: Read the CommandLine UNICODE_STRING ----
    // At offset 0x70 from RTL_USER_PROCESS_PARAMETERS on 64-bit Windows:
    //   USHORT Length        (2 bytes) — byte length of the string
    //   USHORT MaximumLength (2 bytes)
    //   ULONG  Padding       (4 bytes) — alignment to 8-byte boundary
    //   PWCH   Buffer        (8 bytes) — pointer to the wide-char data
#pragma pack(push, 1)
    struct UnicodeStringLayout
    {
        USHORT length;        // Number of bytes in the string (not chars)
        USHORT maxLength;
        ULONG  padding;       // 4-byte alignment gap before the 8-byte pointer
        PWCH   buffer;        // Pointer into the target process's address space
    };
#pragma pack(pop)

    UnicodeStringLayout cmdUs = {};
    if (!ReadProcessMemory(
            hProc,
            reinterpret_cast<BYTE*>(procParamsPtr) + 0x70,
            &cmdUs, sizeof(cmdUs), &bytesRead)
        || cmdUs.length == 0 || !cmdUs.buffer)
    { CloseHandle(hProc); return {}; }

    // ---- Step 4: Read the actual command line characters ----
    // length is in bytes; each wchar_t is 2 bytes.
    std::vector<wchar_t> cmdBuf(cmdUs.length / sizeof(wchar_t) + 1, L'\0');
    if (!ReadProcessMemory(hProc, cmdUs.buffer, cmdBuf.data(),
                           cmdUs.length, &bytesRead))
    { CloseHandle(hProc); return {}; }

    CloseHandle(hProc);
    return QString::fromWCharArray(cmdBuf.data(),
                                   cmdUs.length / sizeof(wchar_t));
}

// ============================================================
// fetchOne()  —  collect all metadata for one PID
// ============================================================
ProcInfo ProcessInfoWorker::fetchOne(int pid) const
{
    ProcInfo info;
    info.path    = getPath(pid);
    info.cmdLine = getCommandLine(pid);
    info.service = getServiceName(pid);
    info.user    = getProcessUser(pid);

    if (!info.path.isEmpty())
    {
        auto [pub, ver] = getVersionInfo(info.path);
        info.publisher = pub;
        info.version   = ver;
        info.signatureStatus = getSignatureInfo(info.path);
        if (info.signatureStatus == QLatin1String("Verified") && isUnusualLocation(info.path))
            info.signatureStatus = QStringLiteral("Verified (unusual location)");
    }

    return info;
}
