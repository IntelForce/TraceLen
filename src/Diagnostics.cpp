// ============================================================
// Diagnostics.cpp  —  crash evidence and session logging
// ============================================================
// See Diagnostics.h for what gets written and where.
// ============================================================

#include "Diagnostics.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QOperatingSystemVersion>
#include <QStandardPaths>
#include <QTextStream>
#include <QThread>
#include <QtGlobal>

#include <windows.h>
#include <dbghelp.h>
#include <exception>
#include <vector>

namespace {

QMutex              g_mutex;
QFile               g_sessionFile;
QStringList         g_breadcrumbs;          // ring of the last 200 actions
QString             g_logDir;
QString             g_sessionStamp;         // YYYYMMDD_HHMMSS for this run
QString             g_cleanMarkerPath;      // present while the session runs
QString             g_previousReport;       // report written by a previous crash
bool                g_installed = false;
constexpr int       kMaxBreadcrumbs = 200;

// ---- file helpers --------------------------------------------------------

void writeLine(const QString& line)
{
    // Caller holds g_mutex. Flushed per line so the last line survives a crash.
    if (!g_sessionFile.isOpen()) return;
    g_sessionFile.write(line.toUtf8());
    g_sessionFile.write("\n", 1);
    g_sessionFile.flush();
}

const char* qtLevel(QtMsgType t)
{
    switch (t) {
        case QtDebugMsg:    return "DEBUG";
        case QtInfoMsg:     return "INFO ";
        case QtWarningMsg:  return "WARN ";
        case QtCriticalMsg: return "ERROR";
        case QtFatalMsg:    return "FATAL";
    }
    return "?    ";
}

// Keep the newest `keep` files matching `pattern` in `dir`, delete the rest.
void pruneOld(const QString& dir, const QString& pattern, int keep)
{
    QDir d(dir);
    const QFileInfoList files = d.entryInfoList({pattern}, QDir::Files, QDir::Time);
    for (int i = keep; i < files.size(); ++i)
        QFile::remove(files[i].absoluteFilePath());
}

// ---- Qt message handler ----------------------------------------------------

void qtMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg)
{
    const QString where = ctx.file
        ? QString("%1:%2").arg(QString::fromUtf8(ctx.file)).arg(ctx.line)
        : QStringLiteral("-");
    const QString line = QString("%1 [%2] %3 (%4)")
        .arg(QDateTime::currentDateTime().toString("HH:mm:ss.zzz"))
        .arg(qtLevel(type))
        .arg(msg)
        .arg(where);

    {
        QMutexLocker l(&g_mutex);
        writeLine(line);
    }

    // Also keep warnings and errors on the console for developers.
    fprintf(stderr, "%s\n", line.toLocal8Bit().constData());
    if (type == QtFatalMsg) abort();
}

// ---- crash report ----------------------------------------------------------

// Human name for the exception codes that actually show up in practice.
QString exceptionName(DWORD code)
{
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:      return "EXCEPTION_ACCESS_VIOLATION (bad memory read/write)";
        case EXCEPTION_STACK_OVERFLOW:        return "EXCEPTION_STACK_OVERFLOW (runaway recursion)";
        case EXCEPTION_ILLEGAL_INSTRUCTION:   return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:    return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_IN_PAGE_ERROR:         return "EXCEPTION_IN_PAGE_ERROR";
        case STATUS_STACK_BUFFER_OVERRUN:     return "STATUS_STACK_BUFFER_OVERRUN (heap/stack corruption detected)";
        case STATUS_HEAP_CORRUPTION:          return "STATUS_HEAP_CORRUPTION";
        case 0xE06D7363:                      return "C++ exception (uncaught)";
    }
    return QString("exception 0x%1").arg(code, 8, 16, QChar('0')).toUpper();
}

// Module name containing an address, e.g. "TraceLen.exe" or "Qt5Widgets.dll".
QString moduleForAddress(const void* addr)
{
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(addr), &mod) || !mod)
        return QStringLiteral("(unknown module)");
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(mod, path, MAX_PATH);
    const QString full = QString::fromWCharArray(path);
    const int slash = full.lastIndexOf(QLatin1Char('\\'));
    return slash >= 0 ? full.mid(slash + 1) : full;
}

// Writes the minidump with dbghelp, loaded at runtime so the build needs no
// extra link library. Returns false if dbghelp is not available.
bool writeMinidump(EXCEPTION_POINTERS* ep, const QString& path)
{
    HMODULE dbg = LoadLibraryW(L"dbghelp.dll");
    if (!dbg) return false;
    auto writeDump = reinterpret_cast<decltype(&MiniDumpWriteDump)>(
        GetProcAddress(dbg, "MiniDumpWriteDump"));
    if (!writeDump) { FreeLibrary(dbg); return false; }

    HANDLE file = CreateFileW(reinterpret_cast<const wchar_t*>(path.utf16()),
                              GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { FreeLibrary(dbg); return false; }

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    // Normal dump: stacks, modules, handles and enough heap to show the
    // objects on the crashing thread. Full dumps are too large to attach.
    const MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo);
    const BOOL ok = writeDump(GetCurrentProcess(), GetCurrentProcessId(),
                              file, type, &mei, nullptr, nullptr);
    CloseHandle(file);
    FreeLibrary(dbg);
    return ok == TRUE;
}

// Best-effort text report. Runs inside the crashing process, so it avoids
// anything that could block for long. Snapshot the breadcrumbs without waiting
// on g_mutex indefinitely: if another thread holds it, we use a short try.
QString buildReportText(DWORD code, void* address, DWORD thread, const QStringList& crumbs)
{
    QString t;
    QTextStream s(&t);
    s << "TraceLen crash report\n";
    s << "===========================\n\n";
    s << "Time        : " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    s << "App version : " << QCoreApplication::applicationVersion() << "\n";
    s << "Qt          : " << qVersion() << "\n";
    s << "OS          : " << QOperatingSystemVersion::current().name()
      << " " << QOperatingSystemVersion::current().majorVersion()
      << "." << QOperatingSystemVersion::current().minorVersion() << "\n\n";

    s << "Exception   : " << exceptionName(code) << "\n";
    s << "Code        : 0x" << QString::number(code, 16).toUpper() << "\n";
    s << "Address     : 0x" << QString::number(reinterpret_cast<quintptr>(address), 16).toUpper() << "\n";
    s << "Module      : " << moduleForAddress(address) << "\n";
    s << "Thread id   : " << thread << "\n\n";

    s << "What the app was doing (most recent last):\n";
    if (crumbs.isEmpty())
        s << "  (no actions recorded)\n";
    for (const QString& c : crumbs)
        s << "  " << c << "\n";

    s << "\nIf a .dmp file was written next to this report, open it in Visual Studio\n"
         "(File > Open > File) and choose 'Debug with Native Only' to see the stack.\n";
    return t;
}

// The unhandled-exception filter. Runs on the thread that crashed.
LONG WINAPI onUnhandledException(EXCEPTION_POINTERS* ep)
{
    const DWORD code    = ep->ExceptionRecord->ExceptionCode;
    void* address       = ep->ExceptionRecord->ExceptionAddress;
    const DWORD thread  = GetCurrentThreadId();

    // Take a copy of the breadcrumbs. If another thread holds the lock (it may
    // be the one that crashed), do not wait forever: report without them.
    QStringList crumbs;
    if (g_mutex.tryLock(500)) {
        crumbs = g_breadcrumbs;
        g_mutex.unlock();
    } else {
        crumbs << "(breadcrumbs unavailable: log lock held at crash time)";
    }

    const QString stamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QString base  = g_logDir + "/crash_" + stamp;

    // Text report first: it is the most useful and the smallest.
    QFile txt(base + ".txt");
    if (txt.open(QIODevice::WriteOnly | QIODevice::Text)) {
        txt.write(buildReportText(code, address, thread, crumbs).toUtf8());
        txt.close();
    }

    const bool dumped = writeMinidump(ep, base + ".dmp");

    // Note the session crash in the session log too, if it is still writable.
    if (g_mutex.tryLock(200)) {
        writeLine(QString("CRASH exception 0x%1 at 0x%2 (report: %3, dump: %4)")
                      .arg(code, 8, 16, QChar('0'))
                      .arg(reinterpret_cast<quintptr>(address), 0, 16)
                      .arg(QFileInfo(txt).fileName())
                      .arg(dumped ? "yes" : "no"));
        g_mutex.unlock();
    }

    // Let Windows Error Reporting / the default handler finish the job, so the
    // usual "stopped working" behaviour is kept.
    return EXCEPTION_EXECUTE_HANDLER;
}

// Uncaught C++ exceptions. Without this the program just terminates silently.
void onTerminate()
{
    QString what = QStringLiteral("unknown");
    try {
        if (auto ep = std::current_exception()) std::rethrow_exception(ep);
    } catch (const std::exception& e) {
        what = QString::fromUtf8(e.what());
    } catch (...) {
        what = QStringLiteral("non-standard exception");
    }
    {
        QMutexLocker l(&g_mutex);
        writeLine(QString("FATAL uncaught exception: %1").arg(what));
    }
    fprintf(stderr, "Uncaught exception: %s\n", qPrintable(what));
    abort();
}

} // namespace

// ============================================================
// public API
// ============================================================
namespace Diagnostics {

QString logDirectory()
{
    return g_logDir;
}

void install()
{
    if (g_installed) return;
    g_installed = true;

    // Folder: per-user, always writable. Not next to the exe, which may be
    // under Program Files.
    g_logDir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
               + QStringLiteral("/logs");
    QDir().mkpath(g_logDir);

    // Did the previous session end cleanly? The marker is removed on a normal
    // exit, so if it is still there the last run did not finish.
    g_cleanMarkerPath = g_logDir + QStringLiteral("/running.marker");
    if (QFile::exists(g_cleanMarkerPath)) {
        // The newest crash report, if the previous run wrote one.
        QDir d(g_logDir);
        const QFileInfoList reports = d.entryInfoList({"crash_*.txt"}, QDir::Files, QDir::Time);
        g_previousReport = reports.isEmpty() ? QString() : reports.first().absoluteFilePath();
    }
    {
        QFile m(g_cleanMarkerPath);
        if (m.open(QIODevice::WriteOnly)) m.write("running\n");
    }

    // This session's log.
    g_sessionStamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    g_sessionFile.setFileName(g_logDir + "/session_" + g_sessionStamp + ".log");
    if (!g_sessionFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        return;
    {
        QMutexLocker l(&g_mutex);
        writeLine(QString("=== session start %1  version %2  Qt %3 ===")
                      .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
                      .arg(QCoreApplication::applicationVersion())
                      .arg(qVersion()));
    }

    pruneOld(g_logDir, "session_*.log", 10);
    pruneOld(g_logDir, "crash_*.txt", 10);
    pruneOld(g_logDir, "crash_*.dmp", 10);

    qInstallMessageHandler(qtMessageHandler);
    SetUnhandledExceptionFilter(onUnhandledException);
    std::set_terminate(onTerminate);
}

QString previousCrashReport()
{
    return g_previousReport;
}

void breadcrumb(const QString& text)
{
    QMutexLocker l(&g_mutex);
    g_breadcrumbs.append(QDateTime::currentDateTime().toString("HH:mm:ss") + "  " + text);
    while (g_breadcrumbs.size() > kMaxBreadcrumbs)
        g_breadcrumbs.removeFirst();
    writeLine(QString("[action] ") + g_breadcrumbs.last());
}

void markCleanExit()
{
    QMutexLocker l(&g_mutex);
    writeLine("=== session end (clean) ===");
    g_sessionFile.close();
    QFile::remove(g_cleanMarkerPath);
}

} // namespace Diagnostics
