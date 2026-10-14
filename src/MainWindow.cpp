// ============================================================
// MainWindow.cpp  —  Complete UI implementation
// ============================================================
#include "MainWindow.h"
#include "LogLoadWorker.h"
#include "ProcessTimeline.h"
#include "Diagnostics.h"
#include <QTabWidget>
#include <memory>

#include <QApplication>
#include <QClipboard>
#include <QEventLoop>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QListWidget>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>
#include <QLabel>
#include <QSpinBox>
#include <QToolBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QPlainTextEdit>
#include <QTextStream>
#include <QMessageBox>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QDialog>
#include <QDialogButtonBox>
#include <QMenu>
#include <QMenuBar>
#include <QAction>
#include <QColor>
#include <QBrush>
#include <QFont>
#include <QDir>
#include <QFileInfo>
#include <QFileIconProvider>
#include <QIcon>
#include <QDateTime>
#include <QCloseEvent>
#include <QPoint>
#include <QComboBox>
#include <QScrollArea>
#include <QRegularExpression>
#include <QTimer>
#include <QElapsedTimer>
#include <QScrollBar>
#include <QHash>
#include <QSet>
#include <QVector>
#include <QPair>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QToolTip>
#include <QHelpEvent>
#include <QFontMetrics>
#include <QStorageInfo>
#include <QFrame>
#include <algorithm>
#include <utility>

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

// Shared QPushButton look for MainWindow and top-level tool windows
// (nullptr-parent dialogs do not inherit the main window stylesheet).
static QString appButtonStyleSheet()
{
    return QStringLiteral(
        "QPushButton {"
        "  background-color: #f5f5f5;"
        "  border: 1px solid #bdbdbd;"
        "  border-radius: 4px;"
        "  padding: 4px 12px;"
        "  color: #212121;"
        "  font-weight: 600;"
        "}"
        "QPushButton:hover {"
        "  background-color: #eeeeee;"
        "  border-color: #9e9e9e;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #e0e0e0;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #fafafa;"
        "  color: #bdbdbd;"
        "  border-color: #e0e0e0;"
        "}"
        "QPushButton:default {"
        "  border: 1px solid #64b5f6;"
        "}"
        "QLineEdit, QPlainTextEdit, QTextEdit {"
        "  border: 1px solid #9e9e9e;"
        "  border-radius: 3px;"
        "  padding: 3px 5px;"
        "  background: #ffffff;"
        "  color: #212121;"
        "  selection-background-color: #bbdefb;"
        "}"
        "QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {"
        "  border: 1px solid #1565c0;"
        "}"
        "QComboBox {"
        "  border: 1px solid #9e9e9e;"
        "  border-radius: 3px;"
        "  padding: 2px 6px;"
        "  background: #ffffff;"
        "}"
        "QToolTip {"
        "  background-color: #fffde7;"
        "  color: #212121;"
        "  border: 1px solid #9e9e9e;"
        "  padding: 4px 6px;"
        "}");
}

// Tooltip text for long paths/details — capped so huge strings cannot stall Qt.
static QString safeHoverTip(const QString& text, int maxChars = 4096)
{
    if (text.isEmpty()) return {};
    if (text.size() <= maxChars) return text;
    return text.left(maxChars) + QStringLiteral("\n… (truncated)");
}

// Show a tooltip only when the cell/tree text is wider than the column.
// Measured at hover time so column resizes are respected.
class OverflowTipFilter : public QObject
{
public:
    explicit OverflowTipFilter(QAbstractItemView* view)
        : QObject(view), m_view(view)
    {
        if (m_view && m_view->viewport()) {
            m_view->setMouseTracking(true);
            m_view->viewport()->installEventFilter(this);
        }
    }

protected:
    bool eventFilter(QObject* obj, QEvent* event) override
    {
        if (event->type() != QEvent::ToolTip || !m_view || obj != m_view->viewport())
            return QObject::eventFilter(obj, event);

        const auto* he = static_cast<QHelpEvent*>(event);
        const QPoint pos = he->pos();
        QString text;
        int colWidth = 0;

        if (auto* table = qobject_cast<QTableWidget*>(m_view)) {
            if (QTableWidgetItem* item = table->itemAt(pos)) {
                text = item->text();
                colWidth = table->columnWidth(item->column());
            }
        } else if (auto* tree = qobject_cast<QTreeWidget*>(m_view)) {
            if (QTreeWidgetItem* item = tree->itemAt(pos)) {
                const int col = tree->columnAt(pos.x());
                if (col >= 0) {
                    text = item->text(col);
                    colWidth = tree->columnWidth(col);
                }
            }
        }

        if (text.isEmpty() || colWidth <= 0) {
            QToolTip::hideText();
            return true;
        }

        const QFontMetrics fm(m_view->font());
        if (fm.horizontalAdvance(text) > colWidth - 12) {
            QToolTip::showText(he->globalPos(), safeHoverTip(text), m_view->viewport());
        } else {
            QToolTip::hideText();
        }
        return true;
    }

private:
    QAbstractItemView* m_view = nullptr;
};

static void installOverflowTooltips(QAbstractItemView* view)
{
    if (!view) return;
    new OverflowTipFilter(view);   // parented to view
}

// ---- Column index constants ----
static const int COL_TIME      =  0;
static const int COL_PID       =  1;
static const int COL_PROCESS   =  2;
static const int COL_PARENT    =  3;
static const int COL_TYPE      =  4;
static const int COL_DETAILS   =  5;
static const int COL_HOSTNAME  =  6;
static const int COL_DNS_SERVER = 7;  // DNS resolver IP (from DNS Query events)
static const int COL_STATUS    =  8;  // Operation result (OK / FAILED: …)
static const int COL_PUBLISHER =  9;
static const int COL_SIGNATURE = 10;
static const int COL_CMDLINE   = 11;
static const int COL_PATH      = 12;
static const int COL_VERSION   = 13;
static const int COL_SERVICE   = 14;
static const int COL_USER      = 15;  // Process owner account (DOMAIN\name)
static const int COL_COUNT     = 16;

static const QStringList COL_NAMES = {
    "Timestamp", "PID", "Process", "Parent", "Type", "Details",
    "Hostname", "DNS Server", "Status", "Publisher", "Signature",
    "Cmd Line", "Path", "Version", "Service", "User"
};

// ============================================================
// Performance tuning (batched UI updates)
// ============================================================
static const int    kFlushIntervalMs = 50;      // how often queued events are turned into rows
static const int    kFlushBudgetMs   = 30;      // max GUI-thread time spent per batch
static const size_t kMaxPendingUi    = 20000;   // backlog cap; oldest pending rows are skipped
static const int    kMaxTableRows    = 30000;   // rows kept in the table while monitoring
static const int    kTrimSlack       = 3000;    // trim in chunks (amortised)
static const qint64 kSortIntervalMs  = 1000;    // re-sort at most once per second

// Compiling a QRegularExpression per row is very slow: cache them.
// ---- Regex safety --------------------------------------------------------
// Qt's regex engine has no match-time limit, so a pattern with a nested
// quantifier such as "(a+)+" can take exponential time on some inputs and
// freeze the UI, which runs matching on the GUI thread. We reject that shape
// (and absurdly long patterns) before compiling. This is a heuristic guard for
// the common pathological case, not a complete ReDoS proof.
static bool isPotentiallyCatastrophic(const QString& pat)
{
    // Same expression as the tested Python version. Written as a raw string so
    // each backslash appears exactly once in the regex the engine receives.
    static const QRegularExpression nested(
        QStringLiteral(R"RX(\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)\s*(?:[*+]|\{\d*,?\d*\}))RX"));
    static const int kMaxPatternLength = 200;
    return pat.size() > kMaxPatternLength || nested.match(pat).hasMatch();
}

// Validate a user-entered pattern. Returns an error message, or empty if OK.
// Uses the same case-insensitivity as matching, so validation and matching agree.
static QString validateUserRegex(const QString& pat)
{
    if (isPotentiallyCatastrophic(pat))
        return QStringLiteral("This pattern could take a very long time to match "
                              "(nested repetition such as \"(a+)+\", or it is too long). "
                              "Simplify it, or use plain text instead.");
    QRegularExpression rx(pat, QRegularExpression::CaseInsensitiveOption);
    if (!rx.isValid())
        return QStringLiteral("The pattern is not a valid regular expression:\n") + rx.errorString();
    return {};
}

static QRegularExpression cachedRegex(const QString& pattern, bool literal)
{
    static QHash<QString, QRegularExpression> cache;
    const QString key = (literal ? QStringLiteral("L:") : QStringLiteral("R:")) + pattern;
    auto it = cache.constFind(key);
    if (it != cache.constEnd()) return it.value();
    if (cache.size() > 256) cache.clear();
    // Refuse a dangerous pattern here too, so no route can reach the match loop
    // with one. A refused pattern matches nothing, and the reason is logged.
    if (!literal && isPotentiallyCatastrophic(pattern)) {
        cache.insert(key, QRegularExpression());   // invalid -> matches nothing
        return QRegularExpression();
    }
    QRegularExpression rx(literal ? QRegularExpression::escape(pattern) : pattern,
                          QRegularExpression::CaseInsensitiveOption);
    if (rx.isValid()) rx.optimize();
    cache.insert(key, rx);
    return rx;
}

// ============================================================
// resolveDevicePath — converts \Device\HarddiskVolumeN\... → C:\...
// ============================================================
QString MainWindow::resolveDevicePath(const QString& path)
{
    if (path.size() < 9 || path[0] != QLatin1Char('\\') ||
        !path.startsWith(QLatin1String("\\Device\\"), Qt::CaseInsensitive))
        return path;

#ifdef Q_OS_WIN
    // GUI thread only. Device -> drive-letter table is built once and rebuilt
    // (rate limited) only on a miss, instead of enumerating volumes per event.
    static QVector<QPair<QString, QString>> s_map;
    static qint64 s_built = 0;

    auto build = [&]() {
        s_map.clear();
        wchar_t drives[512] = {};
        if (GetLogicalDriveStringsW(511, drives)) {
            for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
                wchar_t dev[MAX_PATH] = {};
                wchar_t letter[3] = { d[0], d[1], L'\0' };
                if (QueryDosDeviceW(letter, dev, MAX_PATH))
                    s_map.push_back({ QString::fromWCharArray(dev),
                                      QString::fromWCharArray(letter) });
            }
        }
        s_built = QDateTime::currentMSecsSinceEpoch();
    };
    auto lookup = [&](QString& out) -> bool {
        for (const auto& kv : s_map) {
            const QString& dev = kv.first;
            if (path.startsWith(dev, Qt::CaseInsensitive) &&
                (path.length() == dev.length() || path[dev.length()] == QLatin1Char('\\'))) {
                out = kv.second + path.mid(dev.length());
                return true;
            }
        }
        return false;
    };

    if (s_map.isEmpty()) build();
    QString out;
    if (lookup(out)) return out;
    if (QDateTime::currentMSecsSinceEpoch() - s_built > 5000) {
        build();
        if (lookup(out)) return out;
    }
#endif
    return path;
}

// ============================================================
// signatureBadgeCell()  —  Authenticode status as a colored badge
// ============================================================
// `status` is whatever ProcessInfoWorker::getSignatureInfo() put in
// ev.signatureStatus: "Verified", "Unsigned", "Untrusted", "Expired", etc.,
// or empty if it hasn't been fetched yet (fetch is opt-in — see
// "Fetch Process Info" — and happens once per PID, async).
QTableWidgetItem* MainWindow::signatureBadgeCell(const QString& status, const QColor& fallbackBg)
{
    auto* it = new QTableWidgetItem(status.isEmpty() ? QString() : status);
    if (status.isEmpty()) {
        it->setBackground(QBrush(fallbackBg));
        return it;
    }
    if (status == QLatin1String("Verified (unusual location)")) {
        // Deliberately NOT green — a valid signature running from a temp/
        // downloads-style folder is a classic abuse pattern (a genuinely
        // signed binary used somewhere it has no business being), so this
        // should visually stand out rather than look "all clear".
        it->setText(QStringLiteral("⚠ Verified, unusual path"));
        it->setBackground(QBrush(QColor("#FFE0B2")));   // amber, same as Unsigned
    } else if (status == QLatin1String("Verified")) {
        it->setText(QStringLiteral("✓ Verified"));
        it->setBackground(QBrush(QColor("#C8E6C9")));   // green
    } else if (status == QLatin1String("Unsigned")) {
        it->setText(QStringLiteral("✗ Unsigned"));
        it->setBackground(QBrush(QColor("#FFE0B2")));   // amber
    } else {
        // Untrusted / Distrusted / Expired / Untrusted root / Unverified...
        it->setText(QStringLiteral("⚠ ") + status);
        it->setBackground(QBrush(QColor("#FFCDD2")));   // red
    }
    QFont f = it->font(); f.setBold(true); it->setFont(f);
    return it;
}

// ============================================================
// Constructor
// ============================================================
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    m_log = new ActivityLog(this);
    m_isAdmin = EtwFileWatcher::isRunningAsAdmin();

    m_dnsResolver = new DnsResolver(this);
    m_dnsResolver->start();

    m_procInfoWorker = new ProcessInfoWorker(this);
    m_procInfoWorker->start();

    setupUI();

    // If the last run did not exit cleanly, say so. Without this a crash looks
    // like nothing happened at all.
    const QString crashReport = Diagnostics::previousCrashReport();
    if (!crashReport.isEmpty()) {
        m_statusLabel->setText(
            "The app closed unexpectedly last time. Details saved in: "
            + Diagnostics::logDirectory());
    }
    Diagnostics::breadcrumb("app window opened");
    setupToolbar();
    setupStatusBar();
    setupMenuBar();
    connectSignals();
    loadFilterPresetsFromDisk();
    loadIgnoreListFromDisk();
    loadUiPreferences();   // restore filter checkboxes / options from last run
    updateUIState(false);

    setWindowTitle("TraceLen");
    resize(1400, 800);
    setMinimumSize(1000, 600);
}

MainWindow::~MainWindow()
{
    closeCircularLog();
    if (m_fileWatcher)    { m_fileWatcher->requestStop();    m_fileWatcher->wait(3000);    delete m_fileWatcher; }
    if (m_etwWatcher)     { m_etwWatcher->requestStop();     m_etwWatcher->wait(6000);     delete m_etwWatcher; }
    if (m_regDnsWatcher)  { m_regDnsWatcher->requestStop();  m_regDnsWatcher->wait(6000);  delete m_regDnsWatcher; }
    if (m_sysMonitor)     { m_sysMonitor->requestStop();     m_sysMonitor->wait(3000);     delete m_sysMonitor; }
    if (m_dnsResolver)    { m_dnsResolver->requestStop();    m_dnsResolver->wait(6000);    delete m_dnsResolver; }
    if (m_procInfoWorker) { m_procInfoWorker->requestStop(); m_procInfoWorker->wait(5000); delete m_procInfoWorker; }
}

void MainWindow::closeEvent(QCloseEvent* e)
{
    if (m_loadInProgress) {
        m_loadInProgress = false;
        if (m_loadPumpTimer) m_loadPumpTimer->stop();
        if (m_loadThread) {
            m_loadThread->quit();
            m_loadThread->wait(2000);
        }
    }
    if (m_isMonitoring) onStopClicked();
    saveUiPreferences();  // flush latest filter/options state
    // Subwindows are top-level (no parent) so they get their own taskbar
    // buttons — close them when the main window exits so they don't linger.
    if (m_statisticsWindow)
        m_statisticsWindow->close();
    if (m_behaviorWindow)
        m_behaviorWindow->close();
    if (m_behaviorMonitor)
        m_behaviorMonitor->stop();
    const auto detailWins = m_processDetailWindows;
    for (auto it = detailWins.cbegin(); it != detailWins.cend(); ++it) {
        if (it.value())
            it.value()->close();
    }
    e->accept();
}

// ============================================================
// setupUI
// ============================================================
void MainWindow::setupUI()
{
    // Baseline shape for every QPushButton in the main window.
    setStyleSheet(appButtonStyleSheet());

    QWidget* central = new QWidget(this);
    setCentralWidget(central);

    m_mainSplitter = new QSplitter(Qt::Horizontal, central);

    m_leftPanel  = new QWidget(m_mainSplitter);
    m_rightPanel = new QWidget(m_mainSplitter);
    m_leftPanel->setMinimumWidth(250);
    m_leftPanel->setMaximumWidth(340);

    setupLeftPanel(m_leftPanel);
    setupEventTable(m_rightPanel);

    m_mainSplitter->addWidget(m_leftPanel);
    m_mainSplitter->addWidget(m_rightPanel);
    m_mainSplitter->setSizes({290, 1200});

    auto* l = new QHBoxLayout(central);
    l->setContentsMargins(4, 4, 4, 4);
    l->addWidget(m_mainSplitter);
}

// ============================================================
// setupLeftPanel
// ============================================================
void MainWindow::setupLeftPanel(QWidget* p)
{
    // The sidebar has grown a lot of optional ETW/admin checkboxes (File,
    // Network, Processes, Registry...). Wrap the whole thing in a
    // QScrollArea so it stays usable at a normal window height instead of
    // clipping the lower groups or forcing the window taller. Everything
    // below is unchanged — widgets still get added to `vl` exactly as
    // before; Qt reparents them from `p` to `scrollContent` automatically
    // the moment they're added to a layout owned by `scrollContent`.
    auto* outer = new QVBoxLayout(p);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    auto* scrollArea = new QScrollArea(p);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");
    outer->addWidget(scrollArea);

    auto* scrollContent = new QWidget(scrollArea);
    scrollContent->setStyleSheet("background: transparent;");
    scrollArea->setWidget(scrollContent);

    auto* vl = new QVBoxLayout(scrollContent);
    vl->setSpacing(5);

    m_adminLabel = new QLabel(p);
    if (m_isAdmin)
        m_adminLabel->setText(
            "<span style='color:#2e7d32;font-weight:bold'>✔ Administrator</span>"
            "<br><small>ETW active — file ops include PID info</small>");
    else
        m_adminLabel->setText(
            "<span style='color:#c62828;font-weight:bold'>⚠ Not Administrator</span>"
            "<br><small>File events show path only (no PID).<br>"
            "Run as Admin for full per-process file monitoring.</small>");
    m_adminLabel->setStyleSheet(
        "background:#F5F5F5;border:1px solid #DDD;border-radius:4px;padding:6px;");
    m_adminLabel->setTextFormat(Qt::RichText);
    m_adminLabel->setWordWrap(true);
    vl->addWidget(m_adminLabel);

    auto* dg = new QGroupBox("Which folders should report file activity?", p);
    auto* dl = new QVBoxLayout(dg);
    dg->setToolTip(
        "This list answers: “which folders on disk should the app watch?”\n\n"
        "Example: add your Downloads folder to see when files appear or change there.\n\n"
        "• Not Administrator: the app can only see file changes inside these folders.\n"
        "  (It may not always know which program made the change.)\n\n"
        "• Administrator: the app already sees file activity across the PC;\n"
        "  you can still use this list to focus on specific folders.");
    auto* dirHint = new QLabel(
        QStringLiteral(
            "<b>What is this?</b> A list of folders on your PC that the app should watch "
            "for file activity (new files, writes, renames, deletes).<br>"
            "• <b>Without Admin:</b> only these folders are watched — add at least one "
            "(e.g. Downloads) or you may see little file activity.<br>"
            "• <b>With Admin:</b> optional — file activity can be seen system-wide already."),
        dg);
    dirHint->setWordWrap(true);
    dirHint->setTextFormat(Qt::RichText);
    dirHint->setStyleSheet(QStringLiteral("color:#424242;font-size:11px;font-weight:normal;"));
    dl->addWidget(dirHint);
    m_dirList = new QListWidget(dg);
    m_addDirBtn    = new QPushButton("+ Add folder…",  dg);
    m_removeDirBtn = new QPushButton("− Remove selected", dg);
    m_addDirBtn->setFixedHeight(28);
    m_removeDirBtn->setFixedHeight(28);
    dl->addWidget(m_dirList);
    dl->addWidget(m_addDirBtn);
    dl->addWidget(m_removeDirBtn);
    vl->addWidget(dg);

    auto* fg = new QGroupBox("What to capture (turn types on/off)", p);
    auto* fl = new QVBoxLayout(fg);

    // ---- Filter presets row ----
    // Saves/restores the whole checkbox state below as a named preset, to
    // a filter_presets.json file next to the executable (so it travels
    // with a portable copy of the app rather than living in the registry
    // or a per-user profile folder).
    auto* presetRow = new QWidget(fg);
    auto* presetLayout = new QHBoxLayout(presetRow);
    presetLayout->setContentsMargins(0, 0, 0, 0);
    presetLayout->addWidget(new QLabel("Saved setup:", presetRow));
    m_presetCombo = new QComboBox(presetRow);
    m_presetCombo->setToolTip("Pick a saved combination of the checkboxes below.");
    presetLayout->addWidget(m_presetCombo, 1);
    m_presetSaveBtn = new QPushButton("💾", presetRow);
    m_presetSaveBtn->setToolTip("Save the current checkboxes as a named setup");
    m_presetSaveBtn->setFixedSize(32, 28);
    presetLayout->addWidget(m_presetSaveBtn);
    m_presetDeleteBtn = new QPushButton("🗑", presetRow);
    m_presetDeleteBtn->setToolTip("Delete the selected saved setup");
    m_presetDeleteBtn->setFixedSize(32, 28);
    presetLayout->addWidget(m_presetDeleteBtn);
    fl->addWidget(presetRow);

    auto mkCb = [&](const QString& lbl, const QString& tip, bool def = true) {
        auto* cb = new QCheckBox(lbl, fg);
        cb->setChecked(def);
        // Empty tooltips show as a blank black popup — only set when text exists.
        if (!tip.trimmed().isEmpty())
            cb->setToolTip(tip);
        return cb;
    };
    auto sep = [&](const QString& t) {
        auto* l = new QLabel(t, fg);
        l->setStyleSheet("color:#888;font-size:10px;margin-top:3px;"); return l;
    };

    m_cbFileOpen   = mkCb("📂  File open (needs Admin)",
        "When a program opens a file. Requires Administrator.", false);
    m_cbFileRead   = mkCb("📖  File read (needs Admin)",
        "When a program reads a file. Requires Administrator.", false);
    m_cbFileWrite  = mkCb("✏  File Write / Create",  "File writes and new file creation.");
    m_cbFileDelete = mkCb("🗑  File Delete",          "File deletions.");
    m_cbFileRename = mkCb("🔄  File Rename / Move",   "Renames and moves.");
    m_cbFileQuery  = mkCb("❓  File query (needs Admin)",
        "When a program checks file info on an already-open file.\n"
        "Requires Administrator. Does not catch every existence check.", false);
    m_cbNetConnect = mkCb("🌐  Network connect",       "New outbound network connections (shows process ID).");
    m_cbNetListen  = mkCb("📡  Network listen",        "Programs waiting for incoming connections on a port.");
    m_cbProcStart  = mkCb("▶  Process Start",          "New processes — shows parent.");
    m_cbProcStop   = mkCb("⏹  Process Stop",           "Processes that exited.");

    m_cbRegCreateKey   = mkCb("🗝  Registry create key (needs Admin)",
        "Registry keys created — requires Administrator (ETW).", false);
    m_cbRegSetValue    = mkCb("📝  Registry set value (needs Admin)",
        "Registry values written — requires Administrator (ETW).", false);
    m_cbRegDeleteValue = mkCb("➖  Registry delete value (needs Admin)",
        "Registry values deleted — requires Administrator (ETW).", false);
    m_cbRegDeleteKey   = mkCb("🗑  Registry delete key (needs Admin)",
        "Registry keys deleted — requires Administrator (ETW).", false);
    m_cbRegRenameKey   = mkCb("🔄  Registry rename key (needs Admin)",
        "Registry keys renamed — requires Administrator (ETW).", false);

    m_cbDnsQuery = mkCb("🔎  DNS lookup (needs Admin)",
        "The actual domain name each process asks Windows to resolve, with\n"
        "the result when available. Separate from 'Resolve IPs' below, which\n"
        "only does our own reverse lookups on IPs already in Net Connect rows.",
        false);

    m_cbNetConnectLive = mkCb("⚡  Network connect (live, needs Admin)",
        "Records connections as they happen (more complete than the basic\n"
        "Network connect option). Requires Administrator.\n"
        "If both options are on, the same connection may appear twice.", false);
    m_cbNetDisconnectLive = mkCb("⚡  Network disconnect (live, needs Admin)",
        "Records when a network connection closes. Requires Administrator.",
        false);

    m_cbFileOpen->setEnabled(m_isAdmin);
    m_cbFileRead->setEnabled(m_isAdmin);
    m_cbFileQuery->setEnabled(m_isAdmin);
    m_cbRegCreateKey->setEnabled(m_isAdmin);
    m_cbRegSetValue->setEnabled(m_isAdmin);
    m_cbRegDeleteValue->setEnabled(m_isAdmin);
    m_cbRegDeleteKey->setEnabled(m_isAdmin);
    m_cbRegRenameKey->setEnabled(m_isAdmin);
    m_cbDnsQuery->setEnabled(m_isAdmin);
    m_cbNetConnectLive->setEnabled(m_isAdmin);
    m_cbNetDisconnectLive->setEnabled(m_isAdmin);

    fl->addWidget(sep("── File ─────────────────────────"));
    fl->addWidget(m_cbFileOpen);
    fl->addWidget(m_cbFileRead);
    fl->addWidget(m_cbFileWrite);
    fl->addWidget(m_cbFileDelete);
    fl->addWidget(m_cbFileRename);
    fl->addWidget(m_cbFileQuery);
    fl->addWidget(sep("── Network ──────────────────────"));
    fl->addWidget(m_cbNetConnect);
    fl->addWidget(m_cbNetListen);
    fl->addWidget(m_cbNetConnectLive);
    fl->addWidget(m_cbNetDisconnectLive);
    fl->addWidget(m_cbDnsQuery);
    fl->addWidget(sep("── Processes ────────────────────"));
    fl->addWidget(m_cbProcStart);
    fl->addWidget(m_cbProcStop);
    fl->addWidget(sep("── Registry (needs Admin) ───────"));
    fl->addWidget(m_cbRegCreateKey);
    fl->addWidget(m_cbRegSetValue);
    fl->addWidget(m_cbRegDeleteValue);
    fl->addWidget(m_cbRegDeleteKey);
    fl->addWidget(m_cbRegRenameKey);
    vl->addWidget(fg);

    auto* og = new QGroupBox("Options", p);
    auto* ol = new QVBoxLayout(og);

    ol->addWidget(new QLabel("Show only processes containing:", og));
    m_processFilter = new QLineEdit(og);
    m_processFilter->setPlaceholderText("e.g. chrome  (empty = all)");
    m_processFilter->setToolTip("Hide rows unless the process name contains this text.");
    ol->addWidget(m_processFilter);

    ol->addWidget(new QLabel("Only include paths that start with (one per line):", og));
    m_pathIncludeEdit = new QPlainTextEdit(og);
    m_pathIncludeEdit->setPlaceholderText(
        "Empty = all paths.\nExample:\nC:\\Users\\\nHKCU\\Software\\");
    m_pathIncludeEdit->setToolTip(
        "Leave empty to include all paths.\n"
        "Otherwise only events whose file path starts with one of these lines are kept.\n"
        "Example: C:\\Users\\You\\Downloads");
    m_pathIncludeEdit->setMaximumHeight(60);
    ol->addWidget(m_pathIncludeEdit);

    ol->addWidget(new QLabel("Ignore paths that start with (one per line):", og));
    m_pathExcludeEdit = new QPlainTextEdit(og);
    m_pathExcludeEdit->setPlaceholderText(
        "Example:\nC:\\Windows\\Prefetch\\\nHKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\");
    m_pathExcludeEdit->setToolTip(
        "Events whose file path starts with any of these lines are ignored.\n"
        "Example: C:\\Windows\\Temp");
    m_pathExcludeEdit->setMaximumHeight(60);
    ol->addWidget(m_pathExcludeEdit);

    m_cbHideSuccessfulOps = new QCheckBox("Show only failed actions", og);
    m_cbHideSuccessfulOps->setToolTip(
        "When checked, registry (and similar) operations that succeed\n"
        "are not logged — only failures show up.");
    m_cbHideSuccessfulOps->setChecked(false);
    ol->addWidget(m_cbHideSuccessfulOps);

    m_cbCircularLog = new QCheckBox("Keep a backup file of events", og);
    m_cbCircularLog->setToolTip(
        "While monitoring, continuously write every event to a file next to the app\n"
        "(name includes the date and time). When the file grows large (~50 MB),\n"
        "a new file is started. Useful if the screen list is limited or the app closes.\n"
        "This is separate from the Save button.");
    m_cbCircularLog->setChecked(true);
    ol->addWidget(m_cbCircularLog);

    m_cbResolveIPs = new QCheckBox("Show hostnames for IP addresses", og);
    m_cbResolveIPs->setChecked(false);
    ol->addWidget(m_cbResolveIPs);

    m_cbFetchProcInfo = new QCheckBox("Load process details (publisher, path…)", og);
    m_cbFetchProcInfo->setChecked(false);
    m_cbFetchProcInfo->setToolTip(
        "Look up path, publisher, signature, version, command line, and user\n"
        "for each process (needed for icons and Path / Publisher columns).");
    ol->addWidget(m_cbFetchProcInfo);

    m_cbShowProcessIcons = new QCheckBox("Show process icons", og);
    m_cbShowProcessIcons->setChecked(false);
    m_cbShowProcessIcons->setToolTip(
        "Show each process's executable icon in the Process column and in\n"
        "Group-by-process view. Requires a path (enable Fetch process details).\n"
        "Icons are loaded from the .exe when it exists on disk.");
    ol->addWidget(m_cbShowProcessIcons);

    ol->addWidget(new QLabel("Check interval (process + network):", og));
    m_pollInterval = new QSpinBox(og);
    m_pollInterval->setRange(200, 10000); m_pollInterval->setValue(1000);
    m_pollInterval->setSuffix(" ms");
    ol->addWidget(m_pollInterval);

    auto* hintLabel = new QLabel(
        "<small><i>💡 Right-click any column header<br>"
        "to show / hide that column</i></small>", og);
    hintLabel->setTextFormat(Qt::RichText);
    ol->addWidget(hintLabel);

    vl->addWidget(og);
    vl->addStretch();
}

// ============================================================
// setupEventTable
// ============================================================
void MainWindow::setupEventTable(QWidget* p)
{
    auto* lay = new QVBoxLayout(p);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(2);

    // ---- Search bar ----
    setupSearchBar(p);
    lay->addWidget(m_searchBarWidget);

    // ---- Column filter bar ----
    setupFilterBar(p);
    lay->addWidget(m_filterBarWidget);

    // ---- Event table ----
    m_eventTable = new QTableWidget(p);
    m_eventTable->setColumnCount(COL_COUNT);
    m_eventTable->setHorizontalHeaderLabels(COL_NAMES);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_eventTable->setShowGrid(false);
    m_eventTable->setWordWrap(false);
    m_eventTable->setSortingEnabled(true);
    m_eventTable->verticalHeader()->hide();
    m_eventTable->verticalHeader()->setDefaultSectionSize(24);

    m_eventTable->setColumnWidth(COL_TIME,       118);
    m_eventTable->setColumnWidth(COL_PID,         50);
    m_eventTable->setColumnWidth(COL_PROCESS,    115);
    m_eventTable->setColumnWidth(COL_PARENT,     115);
    m_eventTable->setColumnWidth(COL_TYPE,        95);
    m_eventTable->setColumnWidth(COL_DETAILS,    220);
    m_eventTable->setColumnWidth(COL_HOSTNAME,   120);
    m_eventTable->setColumnWidth(COL_DNS_SERVER, 100);
    m_eventTable->setColumnWidth(COL_STATUS,      90);
    m_eventTable->setColumnWidth(COL_PUBLISHER,  130);
    m_eventTable->setColumnWidth(COL_SIGNATURE,   90);
    m_eventTable->setColumnWidth(COL_CMDLINE,    160);
    m_eventTable->setColumnWidth(COL_PATH,       180);
    m_eventTable->setColumnWidth(COL_VERSION,     80);
    m_eventTable->setColumnWidth(COL_USER,       120);
    m_eventTable->horizontalHeader()->setStretchLastSection(true);

    m_eventTable->setColumnHidden(COL_DNS_SERVER, true); // show when using DNS Query
    m_eventTable->setColumnHidden(COL_STATUS,     true); // show for file/registry failures
    m_eventTable->setColumnHidden(COL_PATH,       true);
    m_eventTable->setColumnHidden(COL_VERSION,    true);
    m_eventTable->setColumnHidden(COL_SERVICE,    true);

    installOverflowTooltips(m_eventTable);

    m_eventTable->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    lay->addWidget(m_eventTable);

    // ---- Process tree (alternate view, hidden until "Group by process" is checked) ----
    m_processTree = new QTreeWidget(p);
    // Columns mirror the useful process-metadata columns from the flat table
    // so Group-by view can show Verified / Path / Cmd Line without opening
    // a separate detail window. Indices:
    //   0 Process/Event  1 PID  2 Type  3 Details
    //   4 Publisher  5 Signature  6 Path  7 Cmd Line  8 Version  9 Service
    //   10 User   (appended last so no existing column index changes)
    m_processTree->setColumnCount(11);
    m_processTree->setHeaderLabels({
        "Process / Event", "PID", "Type", "Details",
        "Publisher", "Signature", "Path", "Cmd Line", "Version", "Service",
        "User"
    });
    m_processTree->setColumnWidth(10, 170);
    m_processTree->setColumnWidth(0, 220);
    m_processTree->setColumnWidth(1, 55);
    m_processTree->setColumnWidth(2, 100);
    m_processTree->setColumnWidth(3, 200);
    m_processTree->setColumnWidth(4, 130);
    m_processTree->setColumnWidth(5, 85);
    m_processTree->setColumnWidth(6, 180);
    m_processTree->setColumnWidth(7, 160);
    m_processTree->setColumnWidth(8, 80);
    m_processTree->setColumnWidth(9, 80);
    // Version / Service hidden by default (same as flat table); user can
    // show them via right-click on the header.
    m_processTree->setColumnHidden(8, true);
    m_processTree->setColumnHidden(9, true);
    m_processTree->header()->setStretchLastSection(true);
    m_processTree->header()->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_processTree->header(), &QWidget::customContextMenuRequested,
            this, [this](const QPoint& pos) {
        QMenu menu(this);
        for (int c = 0; c < m_processTree->columnCount(); ++c) {
            auto* act = menu.addAction(m_processTree->headerItem()->text(c));
            act->setCheckable(true);
            act->setChecked(!m_processTree->isColumnHidden(c));
            // Keep Process/Event and PID always visible.
            if (c == 0 || c == 1) act->setEnabled(false);
            connect(act, &QAction::toggled, this, [this, c](bool on) {
                m_processTree->setColumnHidden(c, !on);
                scheduleUiPreferencesSave();
            });
        }
        menu.exec(m_processTree->header()->mapToGlobal(pos));
    });
    m_processTree->setAlternatingRowColors(true);
    m_processTree->setUniformRowHeights(true);
    m_processTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processTree->setSelectionMode(QAbstractItemView::SingleSelection);
    // Column sorting (click header). Must re-apply after rebuildProcessTree.
    m_processTree->setSortingEnabled(true);
    m_processTree->header()->setSectionsClickable(true);
    m_processTree->header()->setSortIndicatorShown(true);
    installOverflowTooltips(m_processTree);
    m_processTree->setVisible(false);
    lay->addWidget(m_processTree);
}

// ============================================================
// setupSearchBar
// ============================================================
void MainWindow::setupSearchBar(QWidget* p)
{
    m_searchBarWidget = new QWidget(p);
    auto* hl = new QHBoxLayout(m_searchBarWidget);
    hl->setContentsMargins(4, 2, 4, 2);
    hl->setSpacing(6);

    auto* icon = new QLabel("🔍", m_searchBarWidget);
    icon->setFixedWidth(20);
    hl->addWidget(icon);

    m_searchEdit = new QLineEdit(m_searchBarWidget);
    m_searchEdit->setPlaceholderText("Search in the list…");
    m_searchEdit->setClearButtonEnabled(true);
    m_searchEdit->setFixedHeight(26);
    hl->addWidget(m_searchEdit, 1);

    auto* colLabel = new QLabel("search in:", m_searchBarWidget);
    colLabel->setStyleSheet("color:#666;");
    hl->addWidget(colLabel);

    m_searchColCombo = new QComboBox(m_searchBarWidget);
    m_searchColCombo->addItem("All Columns", -1);
    for (int i = 0; i < COL_COUNT; ++i)
        m_searchColCombo->addItem(COL_NAMES[i], i);
    m_searchColCombo->setFixedHeight(26);
    m_searchColCombo->setMinimumWidth(110);
    hl->addWidget(m_searchColCombo);

    auto* typeLabel = new QLabel(QStringLiteral("event type:"), m_searchBarWidget);
    typeLabel->setStyleSheet(QStringLiteral("color:#666;"));
    hl->addWidget(typeLabel);

    m_typeFilterCombo = new QComboBox(m_searchBarWidget);
    m_typeFilterCombo->setToolTip(
        QStringLiteral("Show only one event type in the table and Group-by-process view.\n"
                       "Does not change what is captured — only what is displayed.\n"
                       "Left-panel Event Filters still apply as well."));
    m_typeFilterCombo->addItem(QStringLiteral("All types"), -1);
    // Populate from ActivityEvent type list (stable order)
    for (int i = 0; i <= static_cast<int>(ActivityEvent::Type::NetDisconnectLive); ++i) {
        const auto ty = static_cast<ActivityEvent::Type>(i);
        m_typeFilterCombo->addItem(ActivityEvent::typeToString(ty), i);
    }
    m_typeFilterCombo->setFixedHeight(26);
    m_typeFilterCombo->setMinimumWidth(140);
    hl->addWidget(m_typeFilterCombo);

    m_searchMatchLabel = new QLabel("", m_searchBarWidget);
    m_searchMatchLabel->setStyleSheet("color:#1565c0;min-width:60px;");
    hl->addWidget(m_searchMatchLabel);

    m_cbGroupByProcess = new QCheckBox("Group rows by process", m_searchBarWidget);
    m_cbGroupByProcess->setToolTip(
        "Switch to a tree view: processes (with their parent/child\n"
        "relationships) as branches, their individual events as leaves.\n"
        "Process rows show Publisher, Signature, Path, Cmd Line, etc.\n"
        "Right-click the column header to show/hide columns.\n"
        "Updates every couple of seconds while active rather than\n"
        "instantly on every event — the flat table above stays live.");
    hl->addWidget(m_cbGroupByProcess);

    m_expandTreeBtn = new QPushButton(QStringLiteral("⊞ Expand"), m_searchBarWidget);
    m_expandTreeBtn->setToolTip(QStringLiteral("Expand all process branches in the Group-by-process tree."));
    m_expandTreeBtn->setFixedHeight(26);
    m_expandTreeBtn->setVisible(false);
    hl->addWidget(m_expandTreeBtn);

    m_collapseTreeBtn = new QPushButton(QStringLiteral("⊟ Collapse"), m_searchBarWidget);
    m_collapseTreeBtn->setToolTip(QStringLiteral("Collapse all process branches in the Group-by-process tree."));
    m_collapseTreeBtn->setFixedHeight(26);
    m_collapseTreeBtn->setVisible(false);
    hl->addWidget(m_collapseTreeBtn);

    m_searchBarWidget->setStyleSheet(
        "background:#EEF2FF;border-bottom:1px solid #C5CAE9;");
}

// ============================================================
// setupFilterBar — column filters + capture conditions
// ============================================================
void MainWindow::setupFilterBar(QWidget* p)
{
    m_filterBarWidget = new QWidget(p);
    auto* mainVL = new QVBoxLayout(m_filterBarWidget);
    mainVL->setContentsMargins(4, 4, 4, 4);
    mainVL->setSpacing(4);

    // ---- Column filter row ----
    {
        auto* row = new QWidget(m_filterBarWidget);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0,0,0,0); hl->setSpacing(5);

        auto* lbl = new QLabel("🚫 <b>Hide when:</b>", row);
        lbl->setToolTip("Hide rows when the chosen column matches the pattern you enter");
        hl->addWidget(lbl);

        m_filterColCombo = new QComboBox(row);
        for (int i = 0; i < COL_COUNT; ++i)
            m_filterColCombo->addItem(COL_NAMES[i], i);
        m_filterColCombo->setFixedHeight(24);
        m_filterColCombo->setMinimumWidth(100);
        m_filterColCombo->setCurrentIndex(COL_DETAILS);
        hl->addWidget(m_filterColCombo);

        m_filterPatternEdit = new QLineEdit(row);
        m_filterPatternEdit->setPlaceholderText("regex, e.g.  \\.dll|\\.exe");
        m_filterPatternEdit->setFixedHeight(24);
        hl->addWidget(m_filterPatternEdit, 1);

        auto* addBtn = new QPushButton("+ Add", row);
        addBtn->setFixedHeight(24);
        addBtn->setStyleSheet(
            "QPushButton{background:#f57f17;color:white;border:none;border-radius:3px;padding:0 8px;font-weight:bold;}"
            "QPushButton:hover{background:#e65100;}");
        connect(addBtn, &QPushButton::clicked, this, &MainWindow::onAddColumnFilter);
        hl->addWidget(addBtn);

        mainVL->addWidget(row);

        // Tags container
        m_filterTagsWidget = new QWidget(m_filterBarWidget);
        auto* tagsHL = new QHBoxLayout(m_filterTagsWidget);
        tagsHL->setContentsMargins(0,0,0,0);
        tagsHL->setSpacing(4);
        tagsHL->addStretch();
        mainVL->addWidget(m_filterTagsWidget);
    }

    // ---- Separator ----
    auto* sep = new QFrame(m_filterBarWidget);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#DDD;");
    mainVL->addWidget(sep);

    // ---- Capture conditions row ----
    {
        auto* row = new QWidget(m_filterBarWidget);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0,0,0,0); hl->setSpacing(5);

        auto* lbl = new QLabel("✅ <b>Only record when:</b>", row);
        lbl->setToolTip("Only capture (log) new events where the selected column matches this regex.\n"
                        "When empty: capture everything.\n"
                        "Multiple conditions are OR-ed together.");
        hl->addWidget(lbl);

        m_captureColCombo = new QComboBox(row);
        for (int i = 0; i < COL_COUNT; ++i)
            m_captureColCombo->addItem(COL_NAMES[i], i);
        m_captureColCombo->setFixedHeight(24);
        m_captureColCombo->setMinimumWidth(100);
        m_captureColCombo->setCurrentIndex(COL_DETAILS);
        hl->addWidget(m_captureColCombo);

        m_capturePatternEdit = new QLineEdit(row);
        m_capturePatternEdit->setPlaceholderText("regex, e.g.  notepad|calc");
        m_capturePatternEdit->setFixedHeight(24);
        hl->addWidget(m_capturePatternEdit, 1);

        auto* addBtn = new QPushButton("+ Add", row);
        addBtn->setFixedHeight(24);
        addBtn->setStyleSheet(
            "QPushButton{background:#1b5e20;color:white;border:none;border-radius:3px;padding:0 8px;font-weight:bold;}"
            "QPushButton:hover{background:#2e7d32;}");
        connect(addBtn, &QPushButton::clicked, this, &MainWindow::onAddCaptureCondition);
        hl->addWidget(addBtn);

        mainVL->addWidget(row);

        m_captureTagsWidget = new QWidget(m_filterBarWidget);
        auto* tagsHL = new QHBoxLayout(m_captureTagsWidget);
        tagsHL->setContentsMargins(0,0,0,0);
        tagsHL->setSpacing(4);
        tagsHL->addStretch();
        mainVL->addWidget(m_captureTagsWidget);
    }

    m_filterBarWidget->setStyleSheet(
        "background:#FAFAFA;border-bottom:1px solid #DDD;");
}

// ============================================================
// setupToolbar
// ============================================================
void MainWindow::setupToolbar()
{
    m_mainToolbar = addToolBar("Actions");
    m_mainToolbar->setMovable(false);
    m_mainToolbar->setObjectName("mainToolbar");

    auto mkBtn = [&](const QString& text, const QString& tip, const QString& bg) {
        auto* b = new QPushButton(text);
        b->setToolTip(tip); b->setFixedHeight(30); b->setMinimumWidth(110);
        b->setStyleSheet(
            QString("QPushButton{background:%1;border:1px solid #ccc;"
                    "border-radius:4px;padding:2px 8px;font-weight:bold;color:#222;}"
                    "QPushButton:hover{opacity:0.85;}"
                    "QPushButton:disabled{background:#eee;color:#aaa;}").arg(bg));
        return b;
    };

    m_startBtn = mkBtn("▶  Start", "Begin monitoring",    "#c8e6c9");
    m_stopBtn  = mkBtn("⏹  Stop",  "Stop monitoring",     "#ffcdd2");
    m_saveBtn  = mkBtn("💾  Save",  "Save log to JSON",    "#bbdefb");
    m_loadBtn  = mkBtn("📂  Load",  "Load a saved log",    "#ffe0b2");
    m_clearBtn = mkBtn("🗑  Clear", "Clear all events",    "#eeeeee");
    m_statsBtn = mkBtn("📊  Stats", "Event statistics by process and type", "#e1bee7");
    m_behaviorBtn = mkBtn("🌐  Network",
        "Network activity: TCP/UDP, download / upload / streaming\n"
        "(per process, and per process + remote host)", "#b2dfdb");

    m_mainToolbar->addWidget(m_startBtn);
    m_mainToolbar->addWidget(m_stopBtn);
    m_mainToolbar->addSeparator();
    m_mainToolbar->addWidget(m_saveBtn);
    m_mainToolbar->addWidget(m_loadBtn);
    m_mainToolbar->addSeparator();
    m_mainToolbar->addWidget(m_clearBtn);
    m_mainToolbar->addWidget(m_statsBtn);
    m_mainToolbar->addWidget(m_behaviorBtn);

    auto* sp = new QWidget();
    sp->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_mainToolbar->addWidget(sp);

    m_cbAutoScroll = new QCheckBox("Auto-scroll to new events", m_mainToolbar);
    m_cbAutoScroll->setChecked(true);
    m_cbAutoScroll->setToolTip(
        "When checked (and the table is already scrolled to the bottom),\n"
        "new events keep the view pinned to the latest row.\n"
        "Uncheck to lock the scroll position — useful while reading or\n"
        "investigating a row, since an incoming event can no longer pull\n"
        "the view out from under you.");
    m_mainToolbar->addWidget(m_cbAutoScroll);
}

// ============================================================
// setupStatusBar
// ============================================================
void MainWindow::setupStatusBar()
{
    m_countLabel        = new QLabel(QStringLiteral("Events: 0"));
    m_netTrafficLabel   = new QLabel(QStringLiteral("Network: —"));
    m_visibleCountLabel = new QLabel(QStringLiteral("Visible: 0"));
    m_monitorStateLabel = new QLabel(QStringLiteral("● Stopped"));
    m_statusLabel       = new QLabel(QStringLiteral(
        "Ready. Click Start. Add folders on the left if you are not running as Administrator."));

    m_countLabel->setMinimumWidth(90);
    m_netTrafficLabel->setMinimumWidth(160);
    m_netTrafficLabel->setToolTip(QStringLiteral(
        "Total network traffic measured while monitoring is running\n"
        "(download In + upload Out from TCP connections Windows reports).\n"
        "Resets when you Clear in the Network window or restart monitoring."));
    m_visibleCountLabel->setMinimumWidth(80);
    m_monitorStateLabel->setMinimumWidth(80);
    m_monitorStateLabel->setStyleSheet(QStringLiteral("color:#c62828;font-weight:bold;"));
    m_statusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    auto* sb = statusBar();
    sb->addWidget(m_countLabel);
    sb->addWidget(new QLabel(QStringLiteral("|")));
    sb->addWidget(m_netTrafficLabel);
    sb->addWidget(new QLabel(QStringLiteral("|")));
    sb->addWidget(m_visibleCountLabel);
    sb->addWidget(new QLabel(QStringLiteral("|")));
    sb->addWidget(m_monitorStateLabel);
    sb->addWidget(new QLabel(QStringLiteral("|")));
    sb->addWidget(m_statusLabel, 1);
}

// ============================================================
// setupMenuBar — View menu
// ============================================================
void MainWindow::setupMenuBar()
{
    auto* mb = menuBar();

    // ---- View menu ----
    auto* viewMenu = mb->addMenu("&View");

    m_actSidePanel = viewMenu->addAction("Show &Side Panel");
    m_actSidePanel->setCheckable(true);
    m_actSidePanel->setChecked(true);
    m_actSidePanel->setShortcut(QKeySequence("Ctrl+Shift+S"));
    connect(m_actSidePanel, &QAction::toggled, this, &MainWindow::onToggleSidePanel);

    m_actToolbar = viewMenu->addAction("Show &Toolbar");
    m_actToolbar->setCheckable(true);
    m_actToolbar->setChecked(true);
    m_actToolbar->setShortcut(QKeySequence("Ctrl+Shift+T"));
    connect(m_actToolbar, &QAction::toggled, this, &MainWindow::onToggleToolbar);

    m_actStatusBar = viewMenu->addAction("Show St&atus Bar");
    m_actStatusBar->setCheckable(true);
    m_actStatusBar->setChecked(true);
    m_actStatusBar->setShortcut(QKeySequence("Ctrl+Shift+B"));
    connect(m_actStatusBar, &QAction::toggled, this, &MainWindow::onToggleStatusBar);

    viewMenu->addSeparator();

    auto* searchToggle = viewMenu->addAction("Show &Search Bar");
    searchToggle->setCheckable(true);
    searchToggle->setChecked(true);
    connect(searchToggle, &QAction::toggled, this, [this](bool v){
        m_searchBarWidget->setVisible(v);
    });

    auto* filterToggle = viewMenu->addAction("Show &Filter / Capture Bar");
    filterToggle->setCheckable(true);
    filterToggle->setChecked(true);
    connect(filterToggle, &QAction::toggled, this, [this](bool v){
        m_filterBarWidget->setVisible(v);
    });

    viewMenu->addSeparator();

    auto* statsAct = viewMenu->addAction("📊 &Statistics…");
    statsAct->setShortcut(QKeySequence("Ctrl+Shift+A"));
    statsAct->setToolTip("Counts of events by process and by type");
    connect(statsAct, &QAction::triggered, this, &MainWindow::showStatisticsWindow);

    viewMenu->addSeparator();

    // ---- Columns sub-menu ----
    auto* colMenu = viewMenu->addMenu("&Columns");
    for (int col = 0; col < COL_COUNT; ++col)
    {
        auto* act = colMenu->addAction(COL_NAMES[col]);
        act->setCheckable(true);
        act->setChecked(!m_eventTable->isColumnHidden(col));
        connect(act, &QAction::toggled, this, [this, col](bool checked){
            m_eventTable->setColumnHidden(col, !checked);
        });
    }

    // ---- Tools menu ----
    auto* toolsMenu = mb->addMenu("&Tools");
    toolsMenu->addAction("Manage &Ignore List...", this, &MainWindow::onManageIgnoreList);
}

// ============================================================
// connectSignals
// ============================================================
void MainWindow::connectSignals()
{
    m_flushTimer = new QTimer(this);
    m_flushTimer->setSingleShot(true);
    connect(m_flushTimer, &QTimer::timeout, this, &MainWindow::flushPendingEvents);

    m_resultFlushTimer = new QTimer(this);
    m_resultFlushTimer->setSingleShot(true);
    connect(m_resultFlushTimer, &QTimer::timeout, this, &MainWindow::flushResultUpdates);

    // Debounces the search box and process-name filter box: typing used to
    // re-scan + re-color every row in the table on every single keystroke,
    // which is what caused the UI to lag on large logs. Now a keystroke
    // just (re)starts this timer; the actual (still O(rows)) filter pass
    // only runs once the user pauses for 180ms, so normal typing speed
    // never triggers more than one or two passes instead of one per key.
    m_filterDebounceTimer = new QTimer(this);
    m_filterDebounceTimer->setSingleShot(true);
    connect(m_filterDebounceTimer, &QTimer::timeout, this, &MainWindow::applyFiltersAndMaybeTree);

    connect(m_startBtn, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(m_stopBtn,  &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(m_saveBtn,  &QPushButton::clicked, this, &MainWindow::onSaveLogClicked);
    connect(m_loadBtn,  &QPushButton::clicked, this, &MainWindow::onLoadLogClicked);
    connect(m_clearBtn, &QPushButton::clicked, this, &MainWindow::onClearLogClicked);
    connect(m_statsBtn, &QPushButton::clicked, this, &MainWindow::showStatisticsWindow);
    connect(m_behaviorBtn, &QPushButton::clicked, this, &MainWindow::showBehaviorWindow);

    connect(m_addDirBtn,    &QPushButton::clicked, this, &MainWindow::onAddDirectoryClicked);
    connect(m_removeDirBtn, &QPushButton::clicked, this, &MainWindow::onRemoveDirectoryClicked);

    for (QCheckBox* cb : { m_cbFileOpen, m_cbFileRead, m_cbFileWrite,
                           m_cbFileDelete, m_cbFileRename, m_cbFileQuery,
                           m_cbNetConnect, m_cbNetListen,
                           m_cbProcStart,  m_cbProcStop,
                           m_cbRegCreateKey, m_cbRegSetValue, m_cbRegDeleteValue,
                           m_cbRegDeleteKey, m_cbRegRenameKey, m_cbDnsQuery,
                           m_cbNetConnectLive, m_cbNetDisconnectLive })
        connect(cb, &QCheckBox::clicked, this, &MainWindow::onFilterChanged);

    // Options that should persist across restarts
    for (QCheckBox* cb : { m_cbResolveIPs, m_cbFetchProcInfo, m_cbShowProcessIcons,
                           m_cbHideSuccessfulOps, m_cbCircularLog, m_cbAutoScroll }) {
        if (cb)
            connect(cb, &QCheckBox::clicked, this, &MainWindow::scheduleUiPreferencesSave);
    }
    if (m_processFilter)
        connect(m_processFilter, &QLineEdit::editingFinished, this, &MainWindow::scheduleUiPreferencesSave);
    if (m_pathIncludeEdit)
        connect(m_pathIncludeEdit, &QPlainTextEdit::textChanged, this, &MainWindow::scheduleUiPreferencesSave);
    if (m_pathExcludeEdit)
        connect(m_pathExcludeEdit, &QPlainTextEdit::textChanged, this, &MainWindow::scheduleUiPreferencesSave);

    connect(m_cbResolveIPs,    &QCheckBox::clicked, this, &MainWindow::onResolveIPsToggled);
    connect(m_cbGroupByProcess, &QCheckBox::clicked, this, &MainWindow::onGroupByProcessToggled);
    connect(m_typeFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { applyFiltersAndMaybeTree(); });
    connect(m_expandTreeBtn, &QPushButton::clicked, this, [this]() {
        if (m_processTree) m_processTree->expandAll();
    });
    connect(m_collapseTreeBtn, &QPushButton::clicked, this, [this]() {
        if (m_processTree) m_processTree->collapseAll();
    });
    connect(m_processTree, &QTreeWidget::itemDoubleClicked,
            this, &MainWindow::onProcessTreeItemDoubleClicked);
    // Enter / activate on a process or event row opens the same process window
    connect(m_processTree, &QTreeWidget::itemActivated,
            this, &MainWindow::onProcessTreeItemDoubleClicked);
    m_processTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_processTree, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::onProcessTreeContextMenu);
    connect(m_presetSaveBtn,   &QPushButton::clicked, this, &MainWindow::onSavePresetClicked);
    connect(m_presetDeleteBtn, &QPushButton::clicked, this, &MainWindow::onDeletePresetClicked);
    connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onPresetComboChanged);
    connect(m_cbFetchProcInfo, &QCheckBox::clicked, this, &MainWindow::onFetchProcInfoToggled);
    connect(m_cbShowProcessIcons, &QCheckBox::clicked, this, &MainWindow::onShowProcessIconsToggled);
    connect(m_processFilter, &QLineEdit::textChanged, this, &MainWindow::onProcessFilterChanged);

    connect(m_eventTable, &QTableWidget::cellDoubleClicked,
            this, &MainWindow::onTableDoubleClicked);

    m_eventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_eventTable, &QTableWidget::customContextMenuRequested,
            this, &MainWindow::onEventTableContextMenu);

    connect(m_eventTable->horizontalHeader(),
            &QHeaderView::customContextMenuRequested,
            this, &MainWindow::onHeaderContextMenu);

    // Search bar
    connect(m_searchEdit, &QLineEdit::textChanged,
            this, &MainWindow::onSearchTextChanged);
    connect(m_searchColCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onSearchColumnChanged);

    // Background workers
    connect(m_dnsResolver,    &DnsResolver::hostnameResolved,
            this, &MainWindow::onHostnameResolved,   Qt::QueuedConnection);
    connect(m_procInfoWorker, &ProcessInfoWorker::infoReady,
            this, &MainWindow::onProcessInfoReady,   Qt::QueuedConnection);
}

// ============================================================
// onHeaderContextMenu
// ============================================================
void MainWindow::onHeaderContextMenu(const QPoint& pos)
{
    QMenu menu(this);
    menu.setTitle("Show / Hide Columns");

    for (int col = 0; col < COL_COUNT; ++col)
    {
        QAction* act = menu.addAction(COL_NAMES[col]);
        act->setCheckable(true);
        act->setChecked(!m_eventTable->isColumnHidden(col));
        connect(act, &QAction::triggered, this, [this, col](bool checked){
            m_eventTable->setColumnHidden(col, !checked);
        });
    }
    menu.exec(m_eventTable->horizontalHeader()->mapToGlobal(pos));
}

// ============================================================
// isEventTypeVisible
// ============================================================
bool MainWindow::isEventTypeVisible(ActivityEvent::Type t) const
{
    bool allowed = false;
    switch (t)
    {
        case ActivityEvent::Type::FileOpen:   allowed = m_cbFileOpen  ->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::FileRead:   allowed = m_cbFileRead  ->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::FileWrite:  allowed = m_cbFileWrite ->isChecked(); break;
        case ActivityEvent::Type::FileDelete: allowed = m_cbFileDelete->isChecked(); break;
        case ActivityEvent::Type::FileRename: allowed = m_cbFileRename->isChecked(); break;
        case ActivityEvent::Type::NetConnect: allowed = m_cbNetConnect->isChecked(); break;
        case ActivityEvent::Type::NetListen:  allowed = m_cbNetListen ->isChecked(); break;
        case ActivityEvent::Type::ProcStart:  allowed = m_cbProcStart ->isChecked(); break;
        case ActivityEvent::Type::ProcStop:   allowed = m_cbProcStop  ->isChecked(); break;
        case ActivityEvent::Type::FileQuery:  allowed = m_cbFileQuery ->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::RegistryCreateKey:
            allowed = m_cbRegCreateKey->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::RegistrySetValue:
            allowed = m_cbRegSetValue->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::RegistryDeleteValue:
            allowed = m_cbRegDeleteValue->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::RegistryDeleteKey:
            allowed = m_cbRegDeleteKey->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::RegistryRenameKey:
            allowed = m_cbRegRenameKey->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::DnsQuery:
            allowed = m_cbDnsQuery->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::NetConnectLive:
            allowed = m_cbNetConnectLive->isChecked() && m_isAdmin; break;
        case ActivityEvent::Type::NetDisconnectLive:
            allowed = m_cbNetDisconnectLive->isChecked() && m_isAdmin; break;
        default:
            allowed = false; break;
    }
    if (!allowed)
        return false;

    // Search-bar "type:" filter — display only (one type or all)
    if (m_typeFilterCombo) {
        const int want = m_typeFilterCombo->currentData().toInt();
        if (want >= 0 && static_cast<int>(t) != want)
            return false;
    }
    return true;
}

// ============================================================
// rowPassesColumnFilters — returns true if row should be shown
// ============================================================
bool MainWindow::rowPassesColumnFilters(int row) const
{
    return rowPassesCompiled(row, m_columnFilters);
}

// Same rule, using regexes compiled when each filter was added. applyFiltersToTable()
// calls this for every row, so it must not compile or look up the cache per row.
// A refused (invalid) filter hides nothing.
bool MainWindow::rowPassesCompiled(int row, const QList<ColumnFilter>& filters) const
{
    for (const ColumnFilter& f : filters)
    {
        if (!f.compiled.isValid()) continue;
        auto* it = m_eventTable->item(row, f.column);
        if (!it) continue;
        if (f.compiled.match(it->text()).hasMatch())
            return false;  // matched a hide-filter -> hide this row
    }
    return true;
}

// ============================================================
// rowPassesSearch — returns true if row matches search term
// ============================================================
bool MainWindow::rowPassesSearch(int row) const
{
    const QString term = m_searchEdit ? m_searchEdit->text().trimmed() : QString();
    if (term.isEmpty()) return true;

    const QRegularExpression rx = cachedRegex(term, true);

    if (m_searchColumn == -1)
    {
        // All columns
        for (int col = 0; col < COL_COUNT; ++col)
        {
            if (m_eventTable->isColumnHidden(col)) continue;
            auto* it = m_eventTable->item(row, col);
            if (it && rx.match(it->text()).hasMatch()) return true;
        }
        return false;
    }
    else
    {
        auto* it = m_eventTable->item(row, m_searchColumn);
        return it && rx.match(it->text()).hasMatch();
    }
}

// ============================================================
// eventPassesCaptureConditions
// Returns true if the event should be captured/logged.
// When no conditions are set: always capture.
// When conditions exist: capture if ANY condition matches.
// ============================================================
bool MainWindow::eventPassesCaptureConditions(const ActivityEvent& ev) const
{
    if (m_captureConditions.isEmpty()) return true;

    // Build a temporary map column→value for the event
    auto colValue = [&](int col) -> QString {
        switch (col) {
            case COL_TIME:      return ev.timestamp.toString("HH:mm:ss.zzz");
            case COL_PID:       return ev.pid > 0 ? QString::number(ev.pid) : "?";
            case COL_PROCESS:   return ev.processName;
            case COL_PARENT:    return ev.parentProcessName;
            case COL_TYPE:      return ActivityEvent::typeToString(ev.type);
            case COL_DETAILS:    return ev.details;
            case COL_HOSTNAME:   return ev.hostname;
            case COL_DNS_SERVER: return ev.dnsServer;
            case COL_STATUS:     return ev.operationStatus;
            case COL_PUBLISHER:  return ev.publisher;
            case COL_SIGNATURE:  return ev.signatureStatus;
            case COL_CMDLINE:    return ev.commandLine;
            case COL_PATH:       return ev.fullPath;
            case COL_VERSION:    return ev.fileVersion;
            case COL_SERVICE:    return ev.serviceName;
            case COL_USER:       return ev.userName;
            default:             return {};
        }
    };

    for (const CaptureCondition& c : m_captureConditions)
    {
        if (!c.compiled.isValid()) continue;   // refused or invalid: matches nothing
        if (c.compiled.match(colValue(c.column)).hasMatch())
            return true;
    }
    return false;
}

// ============================================================
// applyFiltersToTable
// ============================================================
// ============================================================
// applyFiltersToTable — performance notes
// ============================================================
// This used to be two full per-row, per-column passes (rowPassesSearch()'s
// own column loop just to decide visibility, then a second column loop
// here to decide color), called synchronously on every keystroke with no
// updates-batching — on a large log that's what caused the UI to lag while
// typing in Search. Fixes, in order of impact:
//   1. Callers debounce via scheduleFilterApply() instead of calling this
//      directly from textChanged — see connectSignals(). This is the
//      biggest win: typing "chrome" now runs this ~once instead of 6x.
//   2. setUpdatesEnabled(false) around the whole scan, so the table
//      doesn't repaint after every single row/cell change.
//   3. Single combined pass per row: search-matching and cell coloring
//      happen together instead of in two separate full column loops.
//   4. Skip rows whose type/name/column-filter already excludes them
//      before doing any per-cell/regex work at all.
//   5. Skip setRowHidden()/setBackground() calls that wouldn't actually
//      change anything — Qt still marks the view dirty for a same-value
//      set, so a true no-op check saves real work on an unchanged filter.
void MainWindow::applyFiltersToTable()
{
    m_eventTable->setSortingEnabled(false);
    m_eventTable->setUpdatesEnabled(false);

    // Always re-read from the combo so visibility matches the UI selection
    if (m_searchColCombo)
        m_searchColumn = m_searchColCombo->currentData().toInt();

    const QString nf = m_processFilter->text().trimmed().toLower();
    int vis = 0;

    const QColor highlightBg(255, 255, 153);  // yellow highlight
    const QString term = m_searchEdit ? m_searchEdit->text().trimmed() : QString();
    const bool hasTerm = !term.isEmpty();
    const QRegularExpression searchRx = hasTerm ? cachedRegex(term, true) : QRegularExpression();

    int searchMatches = 0;

    for (int r = 0; r < m_eventTable->rowCount(); ++r)
    {
        auto* c0 = m_eventTable->item(r, COL_TIME);
        if (!c0) {
            if (m_eventTable->isRowHidden(r)) m_eventTable->setRowHidden(r, false);
            continue;
        }

        ActivityEvent::Type type = static_cast<ActivityEvent::Type>(
            c0->data(Qt::UserRole).toInt());

        bool typeOk = isEventTypeVisible(type);
        bool nameOk = true;
        auto* pc = m_eventTable->item(r, COL_PROCESS);
        if (!nf.isEmpty())
            nameOk = pc && pc->text().toLower().contains(nf);
        bool ignoreOk = true;
        if (!m_ignoreList.isEmpty()) {
            auto* dc = m_eventTable->item(r, COL_DETAILS);
            ignoreOk = !isIgnored(pc ? pc->text() : QString(), dc ? dc->text() : QString());
        }
        const bool preShow = typeOk && nameOk && ignoreOk && rowPassesCompiled(r, m_columnFilters);

        bool show = preShow;

        if (preShow)
        {
            // When searching a specific column (not "All"), that column
            // alone decides visibility — matches rowPassesSearch()'s old
            // semantics exactly. In "All columns" mode, visibility is
            // decided inline below as we scan for highlighting anyway.
            bool rowHasMatch = !hasTerm;
            if (hasTerm && m_searchColumn != -1)
            {
                auto* it = m_eventTable->item(r, m_searchColumn);
                rowHasMatch = it && searchRx.match(it->text()).hasMatch();
            }

            const QColor typeBg(ActivityEvent::typeToColor(type));
            for (int col = 0; col < COL_COUNT; ++col)
            {
                auto* it = m_eventTable->item(r, col);
                if (!it) continue;

                QColor targetBg = typeBg;
                // Only treat a column as a "search hit" when:
                //  - All columns mode, or
                //  - This is the specifically selected search column
                const bool colInScope = (m_searchColumn == -1)
                    ? !m_eventTable->isColumnHidden(col)
                    : (col == m_searchColumn);
                if (hasTerm && colInScope && searchRx.match(it->text()).hasMatch())
                {
                    targetBg = highlightBg;
                    ++searchMatches;
                    if (m_searchColumn == -1)
                        rowHasMatch = true;
                    // specific-column mode already set rowHasMatch above
                }
                if (it->background().color() != targetBg)
                    it->setBackground(QBrush(targetBg));
            }

            if (hasTerm && !rowHasMatch) show = false;
        }

        const bool shouldBeHidden = !show;
        if (m_eventTable->isRowHidden(r) != shouldBeHidden)
            m_eventTable->setRowHidden(r, shouldBeHidden);
        if (show) ++vis;
    }

    m_eventTable->setUpdatesEnabled(true);
    m_eventTable->setSortingEnabled(true);
    m_visibleCountLabel->setText(QString("Visible: %1").arg(vis));

    if (m_searchMatchLabel)
    {
        if (term.isEmpty())
            m_searchMatchLabel->setText("");
        else
            m_searchMatchLabel->setText(
                QString("%1 match%2").arg(searchMatches).arg(searchMatches == 1 ? "" : "es"));
    }
}

void MainWindow::applyFiltersAndMaybeTree()
{
    applyFiltersToTable();
    // Filters change what the tree shows even when the log has not changed,
    // so this path must force a rebuild (the revision gate would skip it).
    if (m_processTree && m_processTree->isVisible()) {
        m_treeBuiltRevision = 0;
        rebuildProcessTree();
    }
}

void MainWindow::scheduleFilterApply()
{
    // Group-by-process rebuilds the whole tree from the log (expensive at 50k).
    // Wait longer after typing so we rebuild once per pause, not per key.
    const int ms = (m_processTree && m_processTree->isVisible()) ? 450 : 180;
    m_filterDebounceTimer->start(ms);
}

// ============================================================
// Filter presets
// ============================================================
QString MainWindow::filterPresetsFilePath() const
{
    return QApplication::applicationDirPath() + "/filter_presets.json";
}

QMap<QString, QCheckBox*> MainWindow::filterCheckboxRegistry() const
{
    // QMap (not QHash) so save order is stable/sorted — easier to read/diff
    // the JSON file by hand.
    return {
        {"FileOpen", m_cbFileOpen}, {"FileRead", m_cbFileRead},
        {"FileWrite", m_cbFileWrite}, {"FileDelete", m_cbFileDelete},
        {"FileRename", m_cbFileRename}, {"FileQuery", m_cbFileQuery},
        {"NetConnect", m_cbNetConnect}, {"NetListen", m_cbNetListen},
        {"NetConnectLive", m_cbNetConnectLive}, {"NetDisconnectLive", m_cbNetDisconnectLive},
        {"DnsQuery", m_cbDnsQuery},
        {"ProcStart", m_cbProcStart}, {"ProcStop", m_cbProcStop},
        {"RegCreateKey", m_cbRegCreateKey}, {"RegSetValue", m_cbRegSetValue},
        {"RegDeleteValue", m_cbRegDeleteValue}, {"RegDeleteKey", m_cbRegDeleteKey},
        {"RegRenameKey", m_cbRegRenameKey},
        {"ResolveIPs", m_cbResolveIPs}, {"FetchProcInfo", m_cbFetchProcInfo}, {"ShowProcessIcons", m_cbShowProcessIcons},
    };
}

void MainWindow::loadFilterPresetsFromDisk()
{
    m_filterPresets.clear();
    QFile f(filterPresetsFilePath());
    if (f.open(QIODevice::ReadOnly)) {
        const auto doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject()) {
            const QJsonObject root = doc.object();
            for (auto it = root.constBegin(); it != root.constEnd(); ++it)
                if (it.value().isObject()) m_filterPresets.insert(it.key(), it.value().toObject());
        }
    }
    refreshPresetCombo();
}

void MainWindow::saveFilterPresetsToDisk() const
{
    QJsonObject root;
    for (auto it = m_filterPresets.constBegin(); it != m_filterPresets.constEnd(); ++it)
        root.insert(it.key(), it.value());

    QFile f(filterPresetsFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(const_cast<MainWindow*>(this), "Presets",
            QString("Couldn't write %1 — check the app's folder is writable.")
                .arg(filterPresetsFilePath()));
        return;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
}

void MainWindow::refreshPresetCombo()
{
    const QString current = m_presetCombo->currentText();
    m_presetCombo->blockSignals(true);
    m_presetCombo->clear();
    m_presetCombo->addItem("(none)");
    for (const QString& name : m_filterPresets.keys()) m_presetCombo->addItem(name);
    int idx = m_presetCombo->findText(current);
    m_presetCombo->setCurrentIndex(idx >= 0 ? idx : 0);
    m_presetCombo->blockSignals(false);
}

void MainWindow::applyFilterPreset(const QString& name)
{
    Diagnostics::breadcrumb("preset applied: " + name);
    auto it = m_filterPresets.constFind(name);
    if (it == m_filterPresets.constEnd()) return;
    const QJsonObject obj = it.value();
    const auto reg = filterCheckboxRegistry();
    for (auto regIt = reg.constBegin(); regIt != reg.constEnd(); ++regIt) {
        if (!regIt.value()) continue;
        if (!regIt.value()->isEnabled()) continue;   // leave admin-only boxes alone if not admin
        if (obj.contains(regIt.key()))
            regIt.value()->setChecked(obj.value(regIt.key()).toBool());
    }
    applyFiltersAndMaybeTree();
    if (m_isMonitoring) {
        // Push the newly-applied checkbox state to the running watchers,
        // same as a normal checkbox click would.
        auto s = readSettings();
        if (m_fileWatcher)   m_fileWatcher->setSettings(s);
        if (m_etwWatcher)    m_etwWatcher->setSettings(s);
        if (m_regDnsWatcher) m_regDnsWatcher->setSettings(s);
        if (m_sysMonitor)    m_sysMonitor->setSettings(s);
    }
}

void MainWindow::onSavePresetClicked()
{
    bool ok = false;
    const QString name = QInputDialog::getText(this, "Save Filter Preset",
        "Preset name:", QLineEdit::Normal,
        m_presetCombo->currentText() == "(none)" ? "" : m_presetCombo->currentText(), &ok);
    if (!ok || name.trimmed().isEmpty()) return;

    QJsonObject obj;
    const auto reg = filterCheckboxRegistry();
    for (auto it = reg.constBegin(); it != reg.constEnd(); ++it)
        if (it.value()) obj.insert(it.key(), it.value()->isChecked());

    m_filterPresets.insert(name.trimmed(), obj);
    saveFilterPresetsToDisk();
    refreshPresetCombo();
    const int idx = m_presetCombo->findText(name.trimmed());
    if (idx >= 0) m_presetCombo->setCurrentIndex(idx);
    m_statusLabel->setText(QString("Preset \"%1\" saved.").arg(name.trimmed()));
}

void MainWindow::onDeletePresetClicked()
{
    const QString name = m_presetCombo->currentText();
    if (name == "(none)" || !m_filterPresets.contains(name)) return;
    if (QMessageBox::question(this, "Delete Preset",
            QString("Delete preset \"%1\"?").arg(name)) != QMessageBox::Yes)
        return;
    m_filterPresets.remove(name);
    saveFilterPresetsToDisk();
    refreshPresetCombo();
}

void MainWindow::onPresetComboChanged(int index)
{
    if (index <= 0) return;   // "(none)"
    applyFilterPreset(m_presetCombo->currentText());
}

// ============================================================
// Persistent ignore list
// ============================================================
QString MainWindow::ignoreListFilePath() const
{
    return QApplication::applicationDirPath() + "/ignore_list.json";
}

void MainWindow::loadIgnoreListFromDisk()
{
    m_ignoreList.clear();
    QFile f(ignoreListFilePath());
    if (f.open(QIODevice::ReadOnly)) {
        const auto doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isArray())
            for (const auto& v : doc.array())
                if (v.isString()) m_ignoreList.append(v.toString());
    }
}

void MainWindow::saveIgnoreListToDisk() const
{
    QJsonArray arr;
    for (const QString& s : m_ignoreList) arr.append(s);
    QFile f(ignoreListFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(const_cast<MainWindow*>(this), "Ignore List",
            QString("Couldn't write %1 — check the app's folder is writable.")
                .arg(ignoreListFilePath()));
        return;
    }
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    f.close();
}

bool MainWindow::isIgnored(const QString& processName, const QString& details) const
{
    if (m_ignoreList.isEmpty()) return false;
    for (const QString& pat : m_ignoreList) {
        if (pat.isEmpty()) continue;
        if (processName.contains(pat, Qt::CaseInsensitive) ||
            details.contains(pat, Qt::CaseInsensitive))
            return true;
    }
    return false;
}

void MainWindow::onEventTableContextMenu(const QPoint& pos)
{
    const QTableWidgetItem* item = m_eventTable->itemAt(pos);
    QMenu menu(this);

    if (item) {
        const int row = item->row();
        auto* pc = m_eventTable->item(row, COL_PROCESS);
        auto* dc = m_eventTable->item(row, COL_DETAILS);
        const QString procName = pc ? pc->text() : QString();
        const QString details  = dc ? dc->text() : QString();

        auto* pidCell = m_eventTable->item(row, COL_PID);
        const int rowPid = pidCell ? pidCell->text().toInt() : -1;
        if (rowPid > 0) {
            auto* act = menu.addAction(QString("📋 Open events window for \"%1\"").arg(procName));
            connect(act, &QAction::triggered, this, [this, rowPid, procName]() {
                showProcessDetailWindow(rowPid, procName);
            });
            menu.addSeparator();
        }

        if (!procName.isEmpty()) {
            auto* act = menu.addAction(QString("🚫 Ignore process \"%1\"").arg(procName));
            connect(act, &QAction::triggered, this, [this, procName]() {
                m_ignoreList.append(procName);
                saveIgnoreListToDisk();
                applyFiltersAndMaybeTree();
                m_statusLabel->setText(QString("Added \"%1\" to the ignore list.").arg(procName));
            });
        }
        if (!details.isEmpty()) {
            auto* act = menu.addAction("🚫 Ignore this exact Details text");
            connect(act, &QAction::triggered, this, [this, details]() {
                m_ignoreList.append(details);
                saveIgnoreListToDisk();
                applyFiltersAndMaybeTree();
                m_statusLabel->setText("Added that Details text to the ignore list.");
            });
        }
        menu.addSeparator();
    }

    menu.addAction("⚙ Manage ignore list...", this, &MainWindow::onManageIgnoreList);
    menu.exec(m_eventTable->viewport()->mapToGlobal(pos));
}

void MainWindow::onManageIgnoreList()
{
    QDialog dlg(this);
    dlg.setWindowTitle("Manage Ignore List");
    dlg.resize(480, 360);
    auto* vl = new QVBoxLayout(&dlg);

    vl->addWidget(new QLabel(
        QString("Patterns are matched case-insensitively against a row's Process name\n"
               "or Details text. Saved to:\n%1").arg(ignoreListFilePath()), &dlg));

    auto* list = new QListWidget(&dlg);
    list->addItems(m_ignoreList);
    vl->addWidget(list, 1);

    auto* addRow = new QHBoxLayout();
    auto* addEdit = new QLineEdit(&dlg);
    addEdit->setPlaceholderText("New pattern...");
    auto* addBtn = new QPushButton("Add", &dlg);
    addRow->addWidget(addEdit, 1);
    addRow->addWidget(addBtn);
    vl->addLayout(addRow);

    auto* removeBtn = new QPushButton("Remove Selected", &dlg);
    vl->addWidget(removeBtn);

    connect(addBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString t = addEdit->text().trimmed();
        if (!t.isEmpty()) { list->addItem(t); addEdit->clear(); }
    });
    connect(addEdit, &QLineEdit::returnPressed, addBtn, &QPushButton::click);
    connect(removeBtn, &QPushButton::clicked, &dlg, [&]() {
        qDeleteAll(list->selectedItems());
    });

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dlg);
    vl->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() == QDialog::Accepted) {
        m_ignoreList.clear();
        for (int i = 0; i < list->count(); ++i) m_ignoreList.append(list->item(i)->text());
        saveIgnoreListToDisk();
        applyFiltersAndMaybeTree();
    }
}

// ============================================================
// rebuildFilterTagsUI
// ============================================================
void MainWindow::rebuildFilterTagsUI()
{
    // Remove existing children
    qDeleteAll(m_filterTagsWidget->findChildren<QWidget*>(
        QString(), Qt::FindDirectChildrenOnly));
    auto* hl = qobject_cast<QHBoxLayout*>(m_filterTagsWidget->layout());
    // Remove and re-add stretch properly
    while (hl->count()) hl->takeAt(0);

    for (int i = 0; i < m_columnFilters.size(); ++i)
    {
        const auto& f = m_columnFilters[i];
        auto* tag = new QWidget(m_filterTagsWidget);
        auto* tl  = new QHBoxLayout(tag);
        tl->setContentsMargins(4,1,4,1); tl->setSpacing(3);
        tag->setStyleSheet(
            "background:#fff3e0;border:1px solid #f57f17;border-radius:10px;");

        auto* lbl = new QLabel(
            QString("<b>%1</b>: %2")
                .arg(COL_NAMES.value(f.column, "?"), f.pattern.toHtmlEscaped()),
            tag);
        lbl->setStyleSheet("font-size:11px;background:transparent;border:none;");

        auto* closeBtn = new QPushButton("✕", tag);
        closeBtn->setFixedSize(16,16);
        closeBtn->setStyleSheet(
            "QPushButton{background:transparent;border:none;color:#e65100;font-weight:bold;font-size:10px;}"
            "QPushButton:hover{color:#bf360c;}");
        // Deferred: the rebuild destroys this button, so it must not happen from
        // inside the button's own clicked() handler (use-after-free). Keyed by content.
        const int col = f.column;
        const QString pat = f.pattern;
        connect(closeBtn, &QPushButton::clicked, this, [this, col, pat](){
            QTimer::singleShot(0, this, [this, col, pat]() { onRemoveColumnFilter(col, pat); });
        });

        tl->addWidget(lbl);
        tl->addWidget(closeBtn);
        hl->addWidget(tag);
    }
    hl->addStretch();
}

// ============================================================
// rebuildCaptureTagsUI
// ============================================================
void MainWindow::rebuildCaptureTagsUI()
{
    qDeleteAll(m_captureTagsWidget->findChildren<QWidget*>(
        QString(), Qt::FindDirectChildrenOnly));
    auto* hl = qobject_cast<QHBoxLayout*>(m_captureTagsWidget->layout());
    while (hl->count()) hl->takeAt(0);

    for (int i = 0; i < m_captureConditions.size(); ++i)
    {
        const auto& c = m_captureConditions[i];
        auto* tag = new QWidget(m_captureTagsWidget);
        auto* tl  = new QHBoxLayout(tag);
        tl->setContentsMargins(4,1,4,1); tl->setSpacing(3);
        tag->setStyleSheet(
            "background:#e8f5e9;border:1px solid #2e7d32;border-radius:10px;");

        auto* lbl = new QLabel(
            QString("<b>%1</b>: %2")
                .arg(COL_NAMES.value(c.column, "?"), c.pattern.toHtmlEscaped()),
            tag);
        lbl->setStyleSheet("font-size:11px;background:transparent;border:none;");

        auto* closeBtn = new QPushButton("✕", tag);
        closeBtn->setFixedSize(16,16);
        closeBtn->setStyleSheet(
            "QPushButton{background:transparent;border:none;color:#1b5e20;font-weight:bold;font-size:10px;}"
            "QPushButton:hover{color:#1b5e20;}");
        const int col = c.column;
        const QString pat = c.pattern;
        connect(closeBtn, &QPushButton::clicked, this, [this, col, pat](){
            QTimer::singleShot(0, this, [this, col, pat]() { onRemoveCaptureCondition(col, pat); });
        });

        tl->addWidget(lbl);
        tl->addWidget(closeBtn);
        hl->addWidget(tag);
    }
    hl->addStretch();
}

// ============================================================
// extractRemoteIP
// ============================================================
QString MainWindow::extractRemoteIP(const QString& details)
{
    int arrow = details.indexOf("->");
    if (arrow < 0) return {};
    QString after    = details.mid(arrow + 2).trimmed();
    QString addrPort = after.split(' ', Qt::SkipEmptyParts).value(0);
    int colon        = addrPort.lastIndexOf(':');
    return (colon > 0) ? addrPort.left(colon) : addrPort;
}

// ============================================================
// readSettings
// ============================================================
MonitorSettings MainWindow::readSettings() const
{
    MonitorSettings s;
    s.trackFileOpen   = m_cbFileOpen  ->isChecked() && m_isAdmin;
    s.trackFileRead   = m_cbFileRead  ->isChecked() && m_isAdmin;
    s.trackFileWrite  = m_cbFileWrite ->isChecked();
    s.trackFileDelete = m_cbFileDelete->isChecked();
    s.trackFileRename = m_cbFileRename->isChecked();
    s.trackNetConnect = m_cbNetConnect->isChecked();
    s.trackNetListen  = m_cbNetListen ->isChecked();
    s.trackProcStart  = m_cbProcStart ->isChecked();
    s.trackProcStop   = m_cbProcStop  ->isChecked();
    s.resolveIPs      = m_cbResolveIPs->isChecked();
    s.trackFileQuery  = m_cbFileQuery->isChecked() && m_isAdmin;
    s.trackRegistryCreateKey   = m_cbRegCreateKey  ->isChecked() && m_isAdmin;
    s.trackRegistrySetValue    = m_cbRegSetValue   ->isChecked() && m_isAdmin;
    s.trackRegistryDeleteValue = m_cbRegDeleteValue->isChecked() && m_isAdmin;
    s.trackRegistryDeleteKey   = m_cbRegDeleteKey  ->isChecked() && m_isAdmin;
    s.trackRegistryRenameKey   = m_cbRegRenameKey  ->isChecked() && m_isAdmin;
    s.trackDnsQuery            = m_cbDnsQuery      ->isChecked() && m_isAdmin;
    s.trackNetConnectLive      = m_cbNetConnectLive   ->isChecked() && m_isAdmin;
    s.trackNetDisconnectLive   = m_cbNetDisconnectLive->isChecked() && m_isAdmin;
    s.watchedDirectories.clear();
    for (int i = 0; i < m_dirList->count(); ++i)
        s.watchedDirectories << m_dirList->item(i)->text();
    s.processNameFilter = m_processFilter->text();
    s.pollIntervalMs    = m_pollInterval->value();

    auto splitLines = [](QPlainTextEdit* ed) -> QStringList {
        QStringList out;
        if (!ed) return out;
        for (const QString& line : ed->toPlainText().split(QLatin1Char('\n'))) {
            const QString t = line.trimmed();
            if (!t.isEmpty()) out << t;
        }
        return out;
    };
    s.pathIncludePrefixes = splitLines(m_pathIncludeEdit);
    s.pathExcludePrefixes = splitLines(m_pathExcludeEdit);
    s.hideSuccessfulOps   = m_cbHideSuccessfulOps && m_cbHideSuccessfulOps->isChecked();
    s.circularLogEnabled  = m_cbCircularLog && m_cbCircularLog->isChecked();
    s.circularLogMaxBytes = m_circularMaxBytes;
    return s;
}

// ============================================================
// updateUIState
// ============================================================
void MainWindow::updateUIState(bool mon)
{
    m_isMonitoring = mon;
    m_startBtn->setEnabled(!mon);
    m_stopBtn ->setEnabled( mon);
    m_addDirBtn   ->setEnabled(!mon);
    m_removeDirBtn->setEnabled(!mon);
    m_pollInterval->setEnabled(!mon);

    if (mon) {
        m_monitorStateLabel->setText("● Active");
        m_monitorStateLabel->setStyleSheet("color:#2e7d32;font-weight:bold;");
    } else {
        m_monitorStateLabel->setText("● Stopped");
        m_monitorStateLabel->setStyleSheet("color:#c62828;font-weight:bold;");
    }
}

void MainWindow::updateNetTrafficStatus()
{
    if (!m_netTrafficLabel) return;
    if (!m_behaviorMonitor) {
        m_netTrafficLabel->setTextFormat(Qt::RichText);
        m_netTrafficLabel->setText(QStringLiteral("Network: —"));
        return;
    }
    // Without Admin, per-connection sizes are not reliable — do not display junk totals.
    if (!m_behaviorMonitor->collectByteStats() || !m_isAdmin) {
        m_netTrafficLabel->setTextFormat(Qt::RichText);
        m_netTrafficLabel->setText(QStringLiteral(
            "Network: <span style='color:#757575'>sizes need Admin</span>"));
        m_netTrafficLabel->setToolTip(QStringLiteral(
            "Traffic sizes (MB downloaded/uploaded) need Administrator rights.\n"
            "Without Admin, connection lists still work, but byte counters are unreliable."));
        return;
    }
    quint64 totIn = 0, totOut = 0;
    for (const BehaviorRow& row : m_behaviorMonitor->snapshotByProcess()) {
        totIn  += row.bytesIn;
        totOut += row.bytesOut;
    }
    const quint64 total = totIn + totOut;
    auto fmt = [](quint64 n) -> QString {
        if (n < 1024ull) return QString::number(n) + QStringLiteral(" B");
        if (n < 1024ull * 1024) return QString::number(n / 1024.0, 'f', 1) + QStringLiteral(" KB");
        if (n < 1024ull * 1024 * 1024)
            return QString::number(n / (1024.0 * 1024.0), 'f', 2) + QStringLiteral(" MB");
        return QString::number(n / (1024.0 * 1024.0 * 1024.0), 'f', 2) + QStringLiteral(" GB");
    };
    // Same colors as Network window totals: total blue, In green, Out orange
    m_netTrafficLabel->setTextFormat(Qt::RichText);
    m_netTrafficLabel->setToolTip(QStringLiteral(
        "Total network traffic while monitoring (TCP byte counters).\n"
        "↓ download (In)  ·  ↑ upload (Out)"));
    m_netTrafficLabel->setText(
        QStringLiteral("Network: <span style='color:#1565c0;font-weight:bold'>%1</span>"
                       "  <span style='color:#2e7d32'>↓%2</span>"
                       "  <span style='color:#e65100'>↑%3</span>")
            .arg(fmt(total), fmt(totIn), fmt(totOut)));
}

void MainWindow::updateStatusBar()
{
    m_countLabel->setText(QStringLiteral("Events: %1").arg(m_log->count()));
    int vis = 0;
    for (int r = 0; r < m_eventTable->rowCount(); ++r)
        if (!m_eventTable->isRowHidden(r)) ++vis;
    m_visibleCountLabel->setText(QStringLiteral("Visible: %1").arg(vis));
    updateNetTrafficStatus();
}

// ============================================================
// addEventToTable
// ============================================================
void MainWindow::appendRow(const ActivityEvent& ev)
{
    // Caller (flushPendingEvents / load) has already disabled sorting and
    // updates, and applied the capture-condition gate.
    int row = m_eventTable->rowCount();
    m_eventTable->insertRow(row);

    QColor bg(ActivityEvent::typeToColor(ev.type));
    auto cell = [&](const QString& text) {
        auto* it = new QTableWidgetItem(text);
        it->setBackground(QBrush(bg));
        return it;
    };

    // COL_TIME
    auto* timeItem = cell(ev.timestamp.toString("HH:mm:ss.zzz"));
    timeItem->setData(Qt::UserRole, static_cast<int>(ev.type));
    timeItem->setData(Qt::UserRole + 1, ++m_rowSeq);      // for trimming oldest rows
    m_eventTable->setItem(row, COL_TIME, timeItem);

    // COL_PID
    auto* pidItem = cell(ev.pid > 0 ? QString::number(ev.pid) : "?");
    pidItem->setData(Qt::UserRole, ev.pid);
    m_eventTable->setItem(row, COL_PID, pidItem);

    {
        auto* procItem = cell(ev.processName);
        if (!m_bulkLoading && m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
            QString path = resolveDevicePath(ev.fullPath);
            if (path.isEmpty()) {
                auto it = m_procInfoCache.constFind(ev.pid);
                if (it != m_procInfoCache.constEnd())
                    path = resolveDevicePath(it->path);
            }
            // Prefer event path only if basename matches process name
            if (!path.isEmpty() && !pathMatchesExeName(path, ev.processName))
                path.clear();
            const QIcon ic = iconForProcessPath(path, ev.processName);
            if (!ic.isNull())
                procItem->setIcon(ic);
        }
        m_eventTable->setItem(row, COL_PROCESS, procItem);
    }

    // COL_PARENT
    QString parentText;
    if (!ev.parentProcessName.isEmpty() && ev.parentPid > 0)
        parentText = QString("%1 (%2)").arg(ev.parentProcessName).arg(ev.parentPid);
    else if (!ev.parentProcessName.isEmpty())
        parentText = ev.parentProcessName;
    else if (ev.parentPid > 0)
        parentText = QString("PID %1").arg(ev.parentPid);
    m_eventTable->setItem(row, COL_PARENT, cell(parentText));

    // COL_TYPE — bold
    auto* typeItem = cell(ActivityEvent::typeToString(ev.type));
    QFont bf = typeItem->font(); bf.setBold(true); typeItem->setFont(bf);
    m_eventTable->setItem(row, COL_TYPE, typeItem);

    // COL_DETAILS — convert \Device\HarddiskVolumeN → drive letter
    QString details = resolveDevicePath(ev.details);
    m_eventTable->setItem(row, COL_DETAILS, cell(details));

    // COL_HOSTNAME
    auto* hostItem = cell(ev.hostname);
    if (ev.isNetworkEvent())
    {
        QString remIP = extractRemoteIP(ev.details);
        hostItem->setData(Qt::UserRole, remIP);

        bool isLocal = remIP.isEmpty()
                    || remIP == "0.0.0.0"
                    || remIP == "255.255.255.255"
                    || remIP == "::1"
                    || remIP == "::"
                    || remIP.startsWith("127.")
                    || remIP.startsWith("169.254.")
                    || remIP.startsWith("fe80:", Qt::CaseInsensitive);

        if (!isLocal && m_cbResolveIPs->isChecked() && !remIP.isEmpty())
        {
            if (ev.hostname.isEmpty()) hostItem->setText("resolving…");
            m_dnsResolver->queueResolution(remIP);
        }
        else if (isLocal)
        {
            if (ev.hostname.isEmpty())
                hostItem->setText(remIP.isEmpty() ? "" : "local");
        }
    }
    m_eventTable->setItem(row, COL_HOSTNAME, hostItem);
    m_eventTable->setItem(row, COL_DNS_SERVER, cell(ev.dnsServer));
    {
        auto* stItem = cell(ev.operationStatus);
        if (ev.operationStatus.startsWith(QLatin1String("FAILED")))
            stItem->setBackground(QBrush(QColor(255, 205, 210)));
        else if (ev.operationStatus == QLatin1String("OK"))
            stItem->setBackground(QBrush(QColor(232, 245, 233)));
        m_eventTable->setItem(row, COL_STATUS, stItem);
    }

    // Extra metadata — convert device paths here too
    m_eventTable->setItem(row, COL_PUBLISHER, cell(ev.publisher));
    m_eventTable->setItem(row, COL_SIGNATURE, signatureBadgeCell(ev.signatureStatus, bg));
    m_eventTable->setItem(row, COL_CMDLINE,   cell(ev.commandLine));
    m_eventTable->setItem(row, COL_PATH,      cell(resolveDevicePath(ev.fullPath)));
    m_eventTable->setItem(row, COL_VERSION,   cell(ev.fileVersion));
    m_eventTable->setItem(row, COL_SERVICE,   cell(ev.serviceName));
    m_eventTable->setItem(row, COL_USER,      cell(ev.userName));

    // Queue ProcessInfoWorker fetch — ONCE per PID (later events get the cached info)
    const bool needProcMeta = !m_bulkLoading
        && ((m_cbFetchProcInfo && m_cbFetchProcInfo->isChecked())
            || (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()));
    if (needProcMeta && ev.pid > 0 && !m_procInfoRequested.contains(ev.pid)) {
        m_procInfoRequested.insert(ev.pid);
        const bool havePath = !resolveDevicePath(ev.fullPath).isEmpty()
            || (m_procInfoCache.contains(ev.pid)
                && !m_procInfoCache.value(ev.pid).path.isEmpty());
        // Only hit the worker when we still need path/metadata from a live process.
        if (!havePath || (m_cbFetchProcInfo && m_cbFetchProcInfo->isChecked()
                          && ev.publisher.isEmpty() && !havePath)) {
            if (!havePath)
                m_procInfoWorker->queueFetch(ev.pid);
        } else if (m_cbFetchProcInfo && m_cbFetchProcInfo->isChecked()
                   && ev.publisher.isEmpty()) {
            // Path known from log but other metadata missing — still worth one fetch
            // if the process might still be alive.
            m_procInfoWorker->queueFetch(ev.pid);
        }
    }

    // Apply all visibility filters
    bool typeOk    = isEventTypeVisible(ev.type);
    bool nameOk    = true;
    QString nf     = m_processFilter->text().trimmed().toLower();
    if (!nf.isEmpty()) nameOk = ev.processName.toLower().contains(nf);
    bool filterOk  = rowPassesColumnFilters(row);
    bool searchOk  = rowPassesSearch(row);
    bool ignoreOk  = !isIgnored(ev.processName, ev.details);

    m_eventTable->setRowHidden(row, !(typeOk && nameOk && filterOk && searchOk && ignoreOk));
}

// ============================================================
// Batched UI updates
// ============================================================
// Old behaviour: every event re-sorted the whole table, scanned every row for
// the status bar and scrolled — O(rows) work PER EVENT. Now events are queued
// (cheap) and turned into rows in time-boxed batches with ONE sort, ONE scroll
// and ONE status update per batch.
void MainWindow::addEventToTable(const ActivityEvent& ev) { enqueueEvent(ev); }

void MainWindow::applyCachedProcInfo(ActivityEvent& ev) const
{
    if (ev.pid <= 0) return;
    auto it = m_procInfoCache.constFind(ev.pid);
    if (it == m_procInfoCache.constEnd()) return;
    const ProcInfo& i = it.value();
    if (ev.fullPath.isEmpty())    ev.fullPath    = resolveDevicePath(i.path);
    if (ev.publisher.isEmpty())   ev.publisher   = i.publisher;
    if (ev.signatureStatus.isEmpty()) ev.signatureStatus = i.signatureStatus;
    if (ev.fileVersion.isEmpty()) ev.fileVersion = i.version;
    if (ev.serviceName.isEmpty()) ev.serviceName = i.service;
    if (ev.commandLine.isEmpty()) ev.commandLine = i.cmdLine;
    if (ev.userName.isEmpty())    ev.userName    = i.user;
}


// ============================================================
// UI preferences (filter checkboxes, options) — auto-saved next to the app
// ============================================================
static QString uiPreferencesPath()
{
    return QApplication::applicationDirPath() + QStringLiteral("/ui_preferences.json");
}

void MainWindow::scheduleUiPreferencesSave()
{
    if (!m_uiPrefsTimer) {
        m_uiPrefsTimer = new QTimer(this);
        m_uiPrefsTimer->setSingleShot(true);
        connect(m_uiPrefsTimer, &QTimer::timeout, this, &MainWindow::saveUiPreferences);
    }
    m_uiPrefsTimer->start(400); // debounce rapid checkbox clicks
}

void MainWindow::saveUiPreferences()
{
    QJsonObject o;
    auto putCb = [&](const char* key, QCheckBox* cb) {
        if (cb) o[QLatin1String(key)] = cb->isChecked();
    };
    putCb("FileOpen", m_cbFileOpen);
    putCb("FileRead", m_cbFileRead);
    putCb("FileWrite", m_cbFileWrite);
    putCb("FileDelete", m_cbFileDelete);
    putCb("FileRename", m_cbFileRename);
    putCb("FileQuery", m_cbFileQuery);
    putCb("NetConnect", m_cbNetConnect);
    putCb("NetListen", m_cbNetListen);
    putCb("NetConnectLive", m_cbNetConnectLive);
    putCb("NetDisconnectLive", m_cbNetDisconnectLive);
    putCb("DnsQuery", m_cbDnsQuery);
    putCb("ProcStart", m_cbProcStart);
    putCb("ProcStop", m_cbProcStop);
    putCb("RegCreateKey", m_cbRegCreateKey);
    putCb("RegSetValue", m_cbRegSetValue);
    putCb("RegDeleteValue", m_cbRegDeleteValue);
    putCb("RegDeleteKey", m_cbRegDeleteKey);
    putCb("RegRenameKey", m_cbRegRenameKey);
    putCb("ResolveIPs", m_cbResolveIPs);
    putCb("FetchProcInfo", m_cbFetchProcInfo);
    putCb("ShowProcessIcons", m_cbShowProcessIcons);
    putCb("HideSuccessfulOps", m_cbHideSuccessfulOps);
    putCb("CircularLog", m_cbCircularLog);
    putCb("AutoScroll", m_cbAutoScroll);
    putCb("GroupByProcess", m_cbGroupByProcess);
    if (m_processFilter)
        o[QStringLiteral("ProcessFilter")] = m_processFilter->text();
    if (m_pathIncludeEdit)
        o[QStringLiteral("PathInclude")] = m_pathIncludeEdit->toPlainText();
    if (m_pathExcludeEdit)
        o[QStringLiteral("PathExclude")] = m_pathExcludeEdit->toPlainText();
    if (m_pollInterval)
        o[QStringLiteral("PollIntervalMs")] = m_pollInterval->value();
    if (m_typeFilterCombo)
        o[QStringLiteral("TypeFilterIndex")] = m_typeFilterCombo->currentIndex();

    // Column visibility for the main events table
    if (m_eventTable) {
        QJsonArray hiddenCols;
        for (int c = 0; c < m_eventTable->columnCount(); ++c) {
            if (m_eventTable->isColumnHidden(c))
                hiddenCols.append(c);
        }
        o[QStringLiteral("HiddenColumns")] = hiddenCols;
        QJsonArray widths;
        for (int c = 0; c < m_eventTable->columnCount(); ++c)
            widths.append(m_eventTable->columnWidth(c));
        o[QStringLiteral("ColumnWidths")] = widths;
    }
    // Group-by-process tree column visibility
    if (m_processTree) {
        QJsonArray hiddenTree;
        for (int c = 0; c < m_processTree->columnCount(); ++c) {
            if (m_processTree->isColumnHidden(c))
                hiddenTree.append(c);
        }
        o[QStringLiteral("HiddenTreeColumns")] = hiddenTree;
    }

    QFile f(uiPreferencesPath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return;
    f.write(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

void MainWindow::loadUiPreferences()
{
    QFile f(uiPreferencesPath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return;
    const QJsonObject o = doc.object();

    auto getCb = [&](const char* key, QCheckBox* cb) {
        if (!cb) return;
        const QString k = QLatin1String(key);
        if (o.contains(k))
            cb->setChecked(o.value(k).toBool());
    };
    getCb("FileOpen", m_cbFileOpen);
    getCb("FileRead", m_cbFileRead);
    getCb("FileWrite", m_cbFileWrite);
    getCb("FileDelete", m_cbFileDelete);
    getCb("FileRename", m_cbFileRename);
    getCb("FileQuery", m_cbFileQuery);
    getCb("NetConnect", m_cbNetConnect);
    getCb("NetListen", m_cbNetListen);
    getCb("NetConnectLive", m_cbNetConnectLive);
    getCb("NetDisconnectLive", m_cbNetDisconnectLive);
    getCb("DnsQuery", m_cbDnsQuery);
    getCb("ProcStart", m_cbProcStart);
    getCb("ProcStop", m_cbProcStop);
    getCb("RegCreateKey", m_cbRegCreateKey);
    getCb("RegSetValue", m_cbRegSetValue);
    getCb("RegDeleteValue", m_cbRegDeleteValue);
    getCb("RegDeleteKey", m_cbRegDeleteKey);
    getCb("RegRenameKey", m_cbRegRenameKey);
    getCb("ResolveIPs", m_cbResolveIPs);
    getCb("FetchProcInfo", m_cbFetchProcInfo);
    getCb("ShowProcessIcons", m_cbShowProcessIcons);
    getCb("HideSuccessfulOps", m_cbHideSuccessfulOps);
    getCb("CircularLog", m_cbCircularLog);
    getCb("AutoScroll", m_cbAutoScroll);
    getCb("GroupByProcess", m_cbGroupByProcess);
    if (m_processFilter && o.contains(QStringLiteral("ProcessFilter")))
        m_processFilter->setText(o.value(QStringLiteral("ProcessFilter")).toString());
    if (m_pathIncludeEdit && o.contains(QStringLiteral("PathInclude")))
        m_pathIncludeEdit->setPlainText(o.value(QStringLiteral("PathInclude")).toString());
    if (m_pathExcludeEdit && o.contains(QStringLiteral("PathExclude")))
        m_pathExcludeEdit->setPlainText(o.value(QStringLiteral("PathExclude")).toString());
    if (m_pollInterval && o.contains(QStringLiteral("PollIntervalMs")))
        m_pollInterval->setValue(o.value(QStringLiteral("PollIntervalMs")).toInt(m_pollInterval->value()));
    if (m_typeFilterCombo && o.contains(QStringLiteral("TypeFilterIndex"))) {
        const int idx = o.value(QStringLiteral("TypeFilterIndex")).toInt(0);
        if (idx >= 0 && idx < m_typeFilterCombo->count())
            m_typeFilterCombo->setCurrentIndex(idx);
    }
    // Column visibility / widths for the main events table
    if (m_eventTable && o.contains(QStringLiteral("HiddenColumns"))) {
        // Show all first, then hide saved ones
        for (int c = 0; c < m_eventTable->columnCount(); ++c)
            m_eventTable->setColumnHidden(c, false);
        const QJsonArray hiddenCols = o.value(QStringLiteral("HiddenColumns")).toArray();
        for (const QJsonValue& v : hiddenCols) {
            const int c = v.toInt(-1);
            if (c >= 0 && c < m_eventTable->columnCount())
                m_eventTable->setColumnHidden(c, true);
        }
    }
    if (m_eventTable && o.contains(QStringLiteral("ColumnWidths"))) {
        const QJsonArray widths = o.value(QStringLiteral("ColumnWidths")).toArray();
        for (int i = 0; i < widths.size() && i < m_eventTable->columnCount(); ++i) {
            const int w = widths.at(i).toInt(0);
            if (w > 20)
                m_eventTable->setColumnWidth(i, w);
        }
    }
    if (m_processTree && o.contains(QStringLiteral("HiddenTreeColumns"))) {
        for (int c = 0; c < m_processTree->columnCount(); ++c)
            m_processTree->setColumnHidden(c, false);
        const QJsonArray hiddenTree = o.value(QStringLiteral("HiddenTreeColumns")).toArray();
        for (const QJsonValue& v : hiddenTree) {
            const int c = v.toInt(-1);
            if (c >= 0 && c < m_processTree->columnCount())
                m_processTree->setColumnHidden(c, true);
        }
    }

    // Re-apply admin gating after load (disabled boxes stay off for non-admin)
    if (!m_isAdmin) {
        for (QCheckBox* cb : { m_cbFileOpen, m_cbFileRead, m_cbFileQuery,
                               m_cbRegCreateKey, m_cbRegSetValue, m_cbRegDeleteValue,
                               m_cbRegDeleteKey, m_cbRegRenameKey, m_cbDnsQuery,
                               m_cbNetConnectLive, m_cbNetDisconnectLive }) {
            if (cb) { cb->setEnabled(false); /* leave checked state for when elevated */ }
        }
    }
}

void MainWindow::appendCircularLogLine(const ActivityEvent& ev)
{
    if (!m_cbCircularLog || !m_cbCircularLog->isChecked()) {
        closeCircularLog();                      // user turned it off: release the file
        return;
    }

    // Keep ONE file open for the session. The old code re-opened, stat'ed and
    // closed the file for every single event, on the UI thread.
    if (!m_circularFile) {
        const QString dir = QApplication::applicationDirPath();
        QString path = m_circularLogPath;
        if (path.isEmpty()) {
            // Unique file per session so runs do not overwrite each other
            const QString stamp = QDateTime::currentDateTime().toString(
                QStringLiteral("yyyyMMdd_HHmmss"));
            path = dir + QStringLiteral("/TraceLen_events_") + stamp
                 + QStringLiteral(".jsonl");
            m_circularLogPath = path; // keep same file for this session
        }
        m_circularFile = new QFile(path, this);
        if (!m_circularFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            delete m_circularFile;
            m_circularFile = nullptr;
            return;
        }
        m_circularBytes = m_circularFile->size();
    }

    // Rotate when the configured cap is reached: current -> .1, start fresh.
    // The cap comes from settings (circularLogMaxBytes) instead of a constant.
    const qint64 cap = m_circularMaxBytes > 0 ? m_circularMaxBytes : 50LL * 1024 * 1024;
    if (m_circularBytes >= cap) {
        const QString path = m_circularFile->fileName();
        m_circularFile->close();
        const QString bak = path + QStringLiteral(".")
            + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))
            + QStringLiteral(".bak");
        QFile::remove(bak);
        QFile::rename(path, bak);
        if (!m_circularFile->open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            delete m_circularFile;
            m_circularFile = nullptr;
            return;
        }
        m_circularBytes = 0;
    }

    QJsonObject o;
    o["ts"]         = ev.timestamp.toString(Qt::ISODateWithMs);
    o["type"]       = ActivityEvent::typeToString(ev.type);
    o["pid"]        = ev.pid;
    o["process"]    = ev.processName;
    o["parent_pid"] = ev.parentPid;
    o["parent"]     = ev.parentProcessName;
    o["details"]    = ev.details;
    o["hostname"]   = ev.hostname;
    o["dns_server"] = ev.dnsServer;
    o["status"]     = ev.operationStatus;
    o["path"]       = ev.fullPath;
    o["cmdline"]    = ev.commandLine;
    o["publisher"]  = ev.publisher;
    o["signature"]  = ev.signatureStatus;
    o["version"]    = ev.fileVersion;
    o["service"]    = ev.serviceName;
    o["user"]       = ev.userName;
    const QByteArray line = QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n";
    m_circularFile->write(line);
    m_circularBytes += line.size();
    // Flush every ~256 KB so a crash loses at most a small tail
    static qint64 s_sinceFlush = 0;
    s_sinceFlush += line.size();
    if (s_sinceFlush >= 256 * 1024) {
        m_circularFile->flush();
        s_sinceFlush = 0;
    }
}

void MainWindow::closeCircularLog()
{
    if (m_circularFile) {
        m_circularFile->close();
        delete m_circularFile;
        m_circularFile = nullptr;
        m_circularBytes = 0;
    }
}

void MainWindow::enqueueEvent(ActivityEvent ev)
{
    ev.details  = resolveDevicePath(ev.details);
    ev.fullPath = resolveDevicePath(ev.fullPath);
    applyCachedProcInfo(ev);
    learnHostnamesFromEvent(ev);                // IP→name for Network view (DNS + resolved)

    // PID can be reused after exit — drop stale metadata/icon path for this PID
    if (ev.type == ActivityEvent::Type::ProcStop && ev.pid > 0) {
        m_procInfoCache.remove(ev.pid);
        m_procInfoRequested.remove(ev.pid);
    } else if (ev.pid > 0 && !ev.processName.isEmpty()) {
        // Detect PID reuse while process is still "cached" under another exe name
        auto cit = m_procInfoCache.constFind(ev.pid);
        if (cit != m_procInfoCache.constEnd()
            && !cit->path.isEmpty()
            && !pathMatchesExeName(cit->path, ev.processName)) {
            m_procInfoCache.remove(ev.pid);
            m_procInfoRequested.remove(ev.pid);
        }
    }

    m_log->addEvent(ev);                        // the log always keeps every event
    appendCircularLogLine(ev);
    if (!eventPassesCaptureConditions(ev)) return;

    if (m_pending.size() >= kMaxPendingUi) {    // UI can't keep up: skip oldest rows
        const size_t drop = m_pending.size() / 2;
        m_pending.erase(m_pending.begin(), m_pending.begin() + static_cast<long>(drop));
        m_droppedForUi += drop;
    }
    m_pending.push_back(std::move(ev));

    if (m_flushTimer && !m_flushTimer->isActive())
        m_flushTimer->start(kFlushIntervalMs);
}

void MainWindow::flushPendingEvents()
{
    if (m_pending.empty() && !m_sortDirty) return;

    QElapsedTimer budget;
    budget.start();

    // "Follow new events" checkbox is authoritative: when checked, always
    // pin the view to the newest row after a flush. When unchecked, leave
    // the scroll position alone so the user can read older rows without
    // being yanked. (Previously we also required the bar to already be at
    // the bottom, which made the checkbox appear broken if the user had
    // scrolled up even one notch.)
    const bool follow = m_cbAutoScroll && m_cbAutoScroll->isChecked();

    m_eventTable->setUpdatesEnabled(false);
    m_eventTable->setSortingEnabled(false);

    int added = 0;
    while (!m_pending.empty() && budget.elapsed() < kFlushBudgetMs) {
        appendRow(m_pending.front());
        m_pending.pop_front();
        ++added;
    }
    if (added) m_sortDirty = true;
    trimTable();

    // Sorting re-orders the whole table, so do it at most once per interval.
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_sortingWanted) {
        if (m_sortDirty && now - m_lastSortMs >= kSortIntervalMs) {
            m_eventTable->setSortingEnabled(true);          // sorts once
            m_lastSortMs = now;
            m_sortDirty = false;
        } else {
            m_eventTable->horizontalHeader()->setSortIndicatorShown(true);
        }
    }

    m_eventTable->setUpdatesEnabled(true);
    if (follow && added) {
        // scrollToBottom can be a no-op if the model hasn't laid out yet
        // after setUpdatesEnabled(true); force the bar to maximum as well.
        m_eventTable->scrollToBottom();
        if (QScrollBar* sb = m_eventTable->verticalScrollBar())
            sb->setValue(sb->maximum());
    }
    updateStatusBar();

    if (m_droppedForUi != m_droppedShown) {
        m_droppedShown = m_droppedForUi;
        m_statusLabel->setText(QString(
            "UI is behind: %1 row(s) not shown (all events are still in the log / saved file).")
            .arg(m_droppedForUi));
    }

    if (!m_pending.empty())
        m_flushTimer->start(1);                             // yield to input, then continue
    else if (m_sortDirty && m_sortingWanted)
        m_flushTimer->start(static_cast<int>(kSortIntervalMs));   // final sort when idle
}

// Keep the table bounded. Rows are chosen by their sequence number (oldest
// first), not by current position, so it is correct for any sort order.
void MainWindow::trimTable()
{
    if (!m_isMonitoring) return;                            // never trim a loaded log
    const int rows = m_eventTable->rowCount();
    if (rows <= kMaxTableRows + kTrimSlack) return;

    // Time-boxed: if the table is sorted by a non-time column the old rows are
    // scattered and each run costs a removeRows(); never freeze the UI for it —
    // whatever is left is removed by the next batches.
    QElapsedTimer trimBudget;
    trimBudget.start();

    const qint64 cutoff = m_rowSeq - kMaxTableRows;         // seq <= cutoff -> remove
    QAbstractItemModel* model = m_eventTable->model();
    int end = -1;                                           // inclusive end of current run
    for (int r = rows - 1; r >= 0; --r) {
        auto* it = m_eventTable->item(r, COL_TIME);
        const bool old = it && it->data(Qt::UserRole + 1).toLongLong() <= cutoff;
        if (old) {
            if (end < 0) end = r;
        } else if (end >= 0) {
            model->removeRows(r + 1, end - r);
            end = -1;
            if (trimBudget.elapsed() > 25) return;
        }
    }
    if (end >= 0) model->removeRows(0, end + 1);
}

// ============================================================
// SLOT: onStartClicked
// ============================================================
void MainWindow::onStartClicked()
{
    Diagnostics::breadcrumb("monitoring start requested");
    if (m_isMonitoring) return;
    m_procInfoCache.clear();
    m_procInfoRequested.clear();
    MonitorSettings s = readSettings();

    if (m_isAdmin)
    {
        m_etwWatcher = new EtwFileWatcher(this);
        m_etwWatcher->setSettings(s);
        connect(m_etwWatcher, &EtwFileWatcher::fileEventDetected,
                this, &MainWindow::onFileEventDetected,  Qt::QueuedConnection);
        connect(m_etwWatcher, &EtwFileWatcher::statusMessage,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        connect(m_etwWatcher, &EtwFileWatcher::errorOccurred,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        m_etwWatcher->start();

        m_regDnsWatcher = new EtwRegistryDnsWatcher(this);
        m_regDnsWatcher->setSettings(s);
        connect(m_regDnsWatcher, &EtwRegistryDnsWatcher::eventDetected,
                this, &MainWindow::onFileEventDetected,  Qt::QueuedConnection);
        connect(m_regDnsWatcher, &EtwRegistryDnsWatcher::statusMessage,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        connect(m_regDnsWatcher, &EtwRegistryDnsWatcher::errorOccurred,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        m_regDnsWatcher->start();

        m_statusLabel->setText("Starting ETW capture (system-wide, with PID info)…");
    }
    else
    {
        if (m_dirList->count() == 0)
        {
            QMessageBox::warning(this, "No Folders",
                "Add at least one folder to watch.\n\n"
                "Or run as Administrator to use ETW (system-wide, all processes, with PID info).");
            return;
        }
        m_fileWatcher = new FileWatcher(this);
        m_fileWatcher->setWatchedDirectories(s.watchedDirectories);
        m_fileWatcher->setSettings(s);
        connect(m_fileWatcher, &FileWatcher::fileEventDetected,
                this, &MainWindow::onFileEventDetected,  Qt::QueuedConnection);
        connect(m_fileWatcher, &FileWatcher::statusMessage,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        connect(m_fileWatcher, &FileWatcher::errorOccurred,
                this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
        m_fileWatcher->start();
        m_statusLabel->setText(
            QString("Watching %1 folder(s). Run as Admin for system-wide ETW coverage.")
                .arg(s.watchedDirectories.size()));
    }

    m_sysMonitor = new SystemMonitor(this);
    m_sysMonitor->setSettings(s);
    connect(m_sysMonitor, &SystemMonitor::processEventDetected,
            this, &MainWindow::onProcessEventDetected, Qt::QueuedConnection);
    connect(m_sysMonitor, &SystemMonitor::networkEventDetected,
            this, &MainWindow::onNetworkEventDetected, Qt::QueuedConnection);
    connect(m_sysMonitor, &SystemMonitor::statusMessage,
            this, &MainWindow::onStatusMessage, Qt::QueuedConnection);
    m_sysMonitor->start();

    if (!m_behaviorMonitor)
        m_behaviorMonitor = new NetworkBehaviorMonitor(this);
    // Byte sizes need reliable TCP EStats; without Admin they are noisy/wrong.
    m_behaviorMonitor->setCollectByteStats(m_isAdmin);
    // Keep status-bar network total in sync (cheap; only updates labels)
    disconnect(m_behaviorMonitor, &NetworkBehaviorMonitor::updated, this, &MainWindow::updateNetTrafficStatus);
    connect(m_behaviorMonitor, &NetworkBehaviorMonitor::updated,
            this, &MainWindow::updateNetTrafficStatus, Qt::QueuedConnection);
    m_behaviorMonitor->start();

    // Each started watcher is expected to stay alive until Stop. Count them
    // so a single early exit is reported, and the monitor only shows as
    // stopped once every source has gone.
    m_stopping = false;
    m_unexpectedExits = 0;
    m_expectedWatchers = 0;
    auto track = [this](QThread* t, const char* name) {
        ++m_expectedWatchers;
        connect(t, &QThread::finished, this,
                [this, name]() { onWatcherFinished(QString::fromLatin1(name)); });
    };
    if (m_etwWatcher)    track(m_etwWatcher,    "ETW file watcher");
    if (m_regDnsWatcher) track(m_regDnsWatcher, "ETW registry/DNS watcher");
    if (m_fileWatcher)   track(m_fileWatcher,   "file watcher");
    track(m_sysMonitor, "process/network monitor");

    updateUIState(true);
    // Finer status is set by the watchers' own statusMessage signals.
    if (m_isAdmin)
        m_statusLabel->setText("Monitoring started. Waiting for ETW sessions to report…");
}

// ============================================================
// SLOT: onStopClicked
// ============================================================
void MainWindow::onStopClicked()
{
    Diagnostics::breadcrumb("monitoring stop requested");
    if (!m_isMonitoring) return;
    m_stopping = true;                        // deliberate: not an error
    m_statusLabel->setText("Stopping…");
    if (m_behaviorMonitor)
        m_behaviorMonitor->stop();

    // Stop all watchers in parallel, THEN wait once. Sequential waits used to
    // add up to ~18 s of frozen UI in the worst case; with parallel stop
    // requests the total wait is bounded by the slowest single thread.
    QThread* all[] = { m_etwWatcher, m_regDnsWatcher, m_fileWatcher, m_sysMonitor };
    for (QThread* t : all) {
        if (!t) continue;
        disconnect(t, nullptr, this, nullptr);   // no stale signals into the next session
        if (auto* w = qobject_cast<EtwFileWatcher*>(t))        w->requestStop();
        else if (auto* w = qobject_cast<EtwRegistryDnsWatcher*>(t)) w->requestStop();
        else if (auto* w = qobject_cast<FileWatcher*>(t))      w->requestStop();
        else if (auto* w = qobject_cast<SystemMonitor*>(t))    w->requestStop();
    }
    for (QThread* t : all) if (t) t->wait(5000);
    delete m_etwWatcher;    m_etwWatcher    = nullptr;
    delete m_regDnsWatcher; m_regDnsWatcher = nullptr;
    delete m_fileWatcher;   m_fileWatcher   = nullptr;
    delete m_sysMonitor;    m_sysMonitor    = nullptr;

    closeCircularLog();
    m_circularLogPath.clear(); // next Start creates a new timestamped backup file
    updateUIState(false);
    m_statusLabel->setText(QString("Stopped. %1 event(s) captured.").arg(m_log->count()));
}

// ============================================================
// SLOT: onSaveLogClicked
// ============================================================
void MainWindow::onSaveLogClicked()
{
    if (!m_log->count())
    {
        QMessageBox::information(this, "Empty Log", "No events to save.");
        return;
    }
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd_HH-mm-ss"));
    const QString suggested = QDir::homePath() + QStringLiteral("/monitor_log_") + stamp + QStringLiteral(".json");
    QString path = QFileDialog::getSaveFileName(
        this, "Save Log", suggested,
        "JSON (*.json);;All (*)");
    if (path.isEmpty()) return;

    if (m_log->saveToFile(path))
        m_statusLabel->setText(QString("Saved %1 events to: %2").arg(m_log->count()).arg(path));
    else
        QMessageBox::critical(this, "Save Failed", m_log->lastError());
}

// ============================================================
// SLOT: onLoadLogClicked
// ============================================================
void MainWindow::onLoadLogClicked()
{
    Diagnostics::breadcrumb("load log requested");
    if (m_loadInProgress) {
        m_statusLabel->setText(QStringLiteral("A log is already loading…"));
        return;
    }

    QString path = QFileDialog::getOpenFileName(
        this, "Load Log", QDir::homePath(), "JSON (*.json);;All (*)");
    if (path.isEmpty()) return;

    if (m_log->count() > 0 &&
        QMessageBox::question(this, "Replace?",
            QString("Replace %1 existing events?").arg(m_log->count()),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
        return;

    // Clear current view immediately
    m_treeBuiltRevision = 0;
    m_pending.clear();
    m_procInfoCache.clear();
    m_procInfoRequested.clear();
    m_log->clear();
    m_eventTable->setRowCount(0);
    if (m_processTree) m_processTree->clear();
    m_processTreeNodes.clear();
    updateStatusBar();

    m_loadInProgress = true;
    m_loadPath = path;
    m_loadPending.clear();
    m_loadIndex = 0;
    m_loadSkipped = 0;
    m_bulkLoading = true;

    if (m_loadBtn) m_loadBtn->setEnabled(false);
    if (m_startBtn) m_startBtn->setEnabled(false);
    m_statusLabel->setText(QStringLiteral("Loading log: 0% — starting…"));

    // Background thread for disk + JSON parse
    if (m_loadThread) {
        m_loadThread->quit();
        m_loadThread->wait(3000);
        delete m_loadThread;
        m_loadThread = nullptr;
        m_loadWorker = nullptr;
    }
    m_loadThread = new QThread(this);
    m_loadWorker = new LogLoadWorker();
    m_loadWorker->moveToThread(m_loadThread);
    connect(m_loadThread, &QThread::finished, m_loadWorker, &QObject::deleteLater);
    connect(m_loadWorker, &LogLoadWorker::progress,
            this, &MainWindow::onLoadProgress, Qt::QueuedConnection);
    connect(m_loadWorker, &LogLoadWorker::finished,
            this, &MainWindow::onLoadWorkerFinished, Qt::QueuedConnection);
    connect(m_loadThread, &QThread::started, m_loadWorker, [this, path]() {
        m_loadWorker->loadFile(path);
    });
    m_loadThread->start();
}

void MainWindow::onLoadProgress(int percent, const QString& message)
{
    // Worker phase is 0–98%; leave 98–100 for table fill.
    const int uiPct = qBound(0, percent, 98);
    m_statusLabel->setText(QStringLiteral("Loading log: %1% — %2").arg(uiPct).arg(message));
}

void MainWindow::onLoadWorkerFinished(bool ok, const QString& error)
{
    if (!ok) {
        m_loadInProgress = false;
        m_bulkLoading = false;
        if (m_loadBtn) m_loadBtn->setEnabled(true);
        if (m_startBtn) m_startBtn->setEnabled(!m_isMonitoring);
        if (m_loadThread) {
            m_loadThread->quit();
            m_loadThread->wait(5000);
            m_loadThread->deleteLater();
            m_loadThread = nullptr;
            m_loadWorker = nullptr;
        }
        QMessageBox::critical(this, "Load Failed",
                              error.isEmpty() ? QStringLiteral("Unknown error") : error);
        m_statusLabel->setText(QStringLiteral("Load failed."));
        return;
    }

    // Pull events from worker (still valid — worker lives until thread finishes)
    if (m_loadWorker) {
        m_loadPending = m_loadWorker->takeEvents();
        m_loadSkipped = m_loadWorker->skipped();
    }
    m_loadIndex = 0;

    // Seed path cache from loaded events (for icons without live OpenProcess)
    {
        QHash<int, ProcInfo> seeded;
        for (const ActivityEvent& ev : m_loadPending) {
            if (ev.pid <= 0) continue;
            auto it = seeded.find(ev.pid);
            if (it == seeded.end()) {
                ProcInfo info;
                info.path = resolveDevicePath(ev.fullPath);
                info.publisher = ev.publisher;
                info.signatureStatus = ev.signatureStatus;
                info.version = ev.fileVersion;
                info.service = ev.serviceName;
                info.cmdLine = ev.commandLine;
                info.user = ev.userName;
                seeded.insert(ev.pid, info);
            } else {
                if (it->path.isEmpty() && !ev.fullPath.isEmpty())
                    it->path = resolveDevicePath(ev.fullPath);
                if (it->publisher.isEmpty() && !ev.publisher.isEmpty())
                    it->publisher = ev.publisher;
                if (it->cmdLine.isEmpty() && !ev.commandLine.isEmpty())
                    it->cmdLine = ev.commandLine;
                if (it->user.isEmpty() && !ev.userName.isEmpty())
                    it->user = ev.userName;
            }
        }
        m_procInfoCache = seeded;
        for (auto it = seeded.constBegin(); it != seeded.constEnd(); ++it)
            m_procInfoRequested.insert(it.key());
    }

    // Stop worker thread — events are already in m_loadPending
    if (m_loadThread) {
        m_loadThread->quit();
        m_loadThread->wait(5000);
        m_loadThread->deleteLater();
        m_loadThread = nullptr;
        m_loadWorker = nullptr;
    }

    m_eventTable->setSortingEnabled(false);
    m_statusLabel->setText(QStringLiteral("Loading log: 98% — filling table…"));

    if (!m_loadPumpTimer) {
        m_loadPumpTimer = new QTimer(this);
        m_loadPumpTimer->setInterval(0); // run as fast as the event loop allows
        connect(m_loadPumpTimer, &QTimer::timeout, this, &MainWindow::pumpLoadBatch);
    }
    m_loadPumpTimer->start();
}

void MainWindow::pumpLoadBatch()
{
    if (!m_loadInProgress) {
        if (m_loadPumpTimer) m_loadPumpTimer->stop();
        return;
    }

    const int total = m_loadPending.size();
    const int batchSize = 250; // show rows progressively without freezing
    const bool hasCapture = !m_captureConditions.isEmpty();

    m_eventTable->setUpdatesEnabled(false);
    int processed = 0;
    while (m_loadIndex < total && processed < batchSize) {
        ActivityEvent& ev = m_loadPending[m_loadIndex];
        m_log->addEvent(ev);
        if (!hasCapture || eventPassesCaptureConditions(ev))
            appendRow(ev);
        ++m_loadIndex;
        ++processed;
    }
    m_eventTable->setUpdatesEnabled(true);

    if (total > 0) {
        // Table fill maps to 98% → 100% of status, but show event-level % too
        const int eventPct = int(100.0 * double(m_loadIndex) / double(total));
        const int overall = 98 + int(2.0 * double(m_loadIndex) / double(total));
        m_statusLabel->setText(
            QStringLiteral("Loading log: %1% — table %2 / %3 events (%4%)")
                .arg(qMin(overall, 99)).arg(m_loadIndex).arg(total).arg(eventPct));
    }

    if (m_loadIndex >= total) {
        if (m_loadPumpTimer) m_loadPumpTimer->stop();
        m_bulkLoading = false;
        m_loadInProgress = false;
        m_eventTable->setSortingEnabled(true);

        // Icons once per PID after table is filled
        if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
            QHash<int, QIcon> pidIcons;
            for (int r = 0; r < m_eventTable->rowCount(); ++r) {
                auto* pidCell = m_eventTable->item(r, COL_PID);
                if (!pidCell) continue;
                const int pid = pidCell->data(Qt::UserRole).toInt();
                if (pid <= 0) continue;
                if (!pidIcons.contains(pid)) {
                    applyProcessIconToRow(r, pid);
                    if (auto* proc = m_eventTable->item(r, COL_PROCESS))
                        pidIcons.insert(pid, proc->icon());
                    else
                        pidIcons.insert(pid, QIcon());
                } else if (!pidIcons.value(pid).isNull()) {
                    if (auto* proc = m_eventTable->item(r, COL_PROCESS))
                        proc->setIcon(pidIcons.value(pid));
                }
            }
        }

        if (m_cbGroupByProcess && m_cbGroupByProcess->isChecked())
            rebuildProcessTree();

        m_loadPending.clear();
        m_loadPending.shrink_to_fit();
        if (m_loadBtn) m_loadBtn->setEnabled(true);
        if (m_startBtn) m_startBtn->setEnabled(!m_isMonitoring);
        updateStatusBar();

        QString msg = QStringLiteral("Loaded %1 events from: %2")
                          .arg(m_log->count()).arg(m_loadPath);
        if (m_loadSkipped > 0)
            msg += QStringLiteral("  (%1 entries skipped)").arg(m_loadSkipped);
        m_statusLabel->setText(msg);
    }
}


// ============================================================
// SLOT: onClearLogClicked
// ============================================================
void MainWindow::onClearLogClicked()
{
    Diagnostics::breadcrumb("clear log requested");
    if (!m_log->count()) return;
    if (QMessageBox::question(this, "Clear?",
            QString("Remove all %1 events?").arg(m_log->count()),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    m_log->clear();
    m_treeBuiltRevision = 0;
    m_hostnameKnown.clear();
    m_pendingHostnames.clear();
    m_pendingProcInfo.clear();
    m_pending.clear();
    m_droppedForUi = m_droppedShown = 0;
    m_eventTable->setRowCount(0);
    m_processTree->clear();
    m_processTreeNodes.clear();
    updateStatusBar();
    m_statusLabel->setText("Log cleared.");
}

// ============================================================
// Directory slots
// ============================================================
void MainWindow::onAddDirectoryClicked()
{
    QString dir = QFileDialog::getExistingDirectory(
        this, "Select Folder", "C:\\",
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dir.isEmpty()) return;
    dir = QDir::toNativeSeparators(dir);
    for (int i = 0; i < m_dirList->count(); ++i)
        if (m_dirList->item(i)->text().compare(dir, Qt::CaseInsensitive) == 0) return;
    m_dirList->addItem(dir);
    m_statusLabel->setText("Added: " + dir);
}

void MainWindow::onRemoveDirectoryClicked()
{
    if (auto* it = m_dirList->currentItem()) delete it;
    else QMessageBox::information(this, "", "Select a folder first.");
}

// ============================================================
// Filter / options slots
// ============================================================
void MainWindow::onFilterChanged()
{
    scheduleUiPreferencesSave();
    if (m_isMonitoring)
    {
        auto s = readSettings();
        if (m_fileWatcher)   m_fileWatcher->setSettings(s);
        if (m_etwWatcher)    m_etwWatcher->setSettings(s);
        if (m_regDnsWatcher) m_regDnsWatcher->setSettings(s);
        if (m_sysMonitor)    m_sysMonitor->setSettings(s);
    }
    applyFiltersAndMaybeTree();   // checkbox clicks are infrequent — no need to debounce
}

void MainWindow::onProcessFilterChanged()
{
    if (m_isMonitoring && m_sysMonitor) m_sysMonitor->setSettings(readSettings());
    scheduleFilterApply();   // debounced — this fires on every keystroke
}

// ============================================================
// Process-tree view
// ============================================================
// Deliberately a *derived, rebuilt-on-demand* view rather than something
// kept incrementally in sync on every single event — it reads from
// `m_log`, which already keeps every event unconditionally regardless of
// which type checkboxes are on (see enqueueEvent/applyFiltersToTable).
// Rebuilding from that source of truth, instead of hooking into the
// already-delicate flushPendingEvents() hot path, means this feature can't
// regress the flat table it shares data with. The tradeoff is that it's
// not instantly live: while visible it refreshes every couple of seconds
// via m_processTreeTimer rather than per-event.
void MainWindow::onGroupByProcessToggled()
{
    const bool showTree = m_cbGroupByProcess->isChecked();
    m_eventTable->setVisible(!showTree);
    m_processTree->setVisible(showTree);
    if (m_expandTreeBtn)   m_expandTreeBtn->setVisible(showTree);
    if (m_collapseTreeBtn) m_collapseTreeBtn->setVisible(showTree);

    if (showTree) {
        m_treeBuiltRevision = 0;         // switching views must always show the tree
        rebuildProcessTree();
        if (!m_processTreeTimer) {
            m_processTreeTimer = new QTimer(this);
            connect(m_processTreeTimer, &QTimer::timeout, this, &MainWindow::rebuildProcessTree);
        }
        m_processTreeTimer->start(2000);
    } else if (m_processTreeTimer) {
        m_processTreeTimer->stop();
    }
}

QTreeWidgetItem* MainWindow::ensureProcessTreeNode(int pid, const QString& processName,
                                                   int parentPid, const QString& parentName)
{
    auto it = m_processTreeNodes.constFind(pid);
    if (it != m_processTreeNodes.constEnd()) return it.value();

    auto* node = new QTreeWidgetItem();
    const QString label = processName.isEmpty() ? QString("pid %1").arg(pid) : processName;
    node->setText(0, label);
    // DisplayRole as int so header sort is numeric (not "9" > "10").
    node->setData(1, Qt::DisplayRole, pid);
    // Marks this item as a PROCESS node (as opposed to a leaf event row) —
    // onProcessTreeItemDoubleClicked uses this to tell the two apart, and
    // it doubles as "the pid this node represents" for selection restore.
    node->setData(0, Qt::UserRole, pid);
    QFont bf = node->font(0); bf.setBold(true); node->setFont(0, bf);

    if (parentPid > 0) {
        QTreeWidgetItem* parentNode = ensureProcessTreeNode(parentPid, parentName, 0, QString());
        parentNode->addChild(node);
    } else {
        m_processTree->addTopLevelItem(node);
    }
    m_processTreeNodes.insert(pid, node);
    return node;
}

// Fill process-node metadata columns from the richest event we have for that PID.
static void fillProcessNodeMeta(QTreeWidgetItem* node, const ActivityEvent& ev)
{
    if (!node) return;
    auto setIfEmpty = [&](int col, const QString& v) {
        if (!v.isEmpty() && node->text(col).isEmpty())
            node->setText(col, v);
    };
    setIfEmpty(4, ev.publisher);
    setIfEmpty(5, ev.signatureStatus);
    setIfEmpty(6, ev.fullPath);
    setIfEmpty(7, ev.commandLine);
    setIfEmpty(8, ev.fileVersion);
    setIfEmpty(9, ev.serviceName);
    setIfEmpty(10, ev.userName);

    // Color the Signature cell like the flat table badge.
    if (!ev.signatureStatus.isEmpty()) {
        const QString s = ev.signatureStatus.toLower();
        QColor bg = QColor(240, 240, 240);
        if (s.contains(QLatin1String("verif")))
            bg = QColor(200, 230, 201);   // light green
        else if (s.contains(QLatin1String("untrust")) || s.contains(QLatin1String("invalid")))
            bg = QColor(255, 205, 210);   // light red
        else if (s.contains(QLatin1String("unsigned")))
            bg = QColor(255, 243, 224);   // light amber
        node->setBackground(5, QBrush(bg));
    }
}

void MainWindow::rebuildProcessTree()
{
    if (!m_processTree->isVisible()) return;   // nothing to do while hidden

    // Skip the full rebuild when the log has not changed since the last one.
    // The tree is derived entirely from the log, so an unchanged revision
    // means an identical tree.
    if (m_log->revision() == m_treeBuiltRevision && m_treeBuiltRevision != 0)
        return;
    m_treeBuiltRevision = m_log->revision();

    // Preserve scroll position, which PIDs were expanded, and the
    // selection across the clear()+rebuild below. Previously none of this
    // was preserved, so every periodic refresh (every 2s, or any filter/
    // search change) reset the view to the top — which is exactly what
    // made it feel like scrolling down "got yanked back up".
    //
    // Track EXPANDED pids (not collapsed): new processes default to collapsed
    // so "Collapse all" stays in effect as new activity arrives.
    //
    // Selection can be either a process node (UserRole = pid) or an event
    // leaf under it. Leaves used to be ignored, so selecting a row vanished
    // on every rebuild.
    const int scrollValue = m_processTree->verticalScrollBar()->value();
    QSet<int> expandedPids;
    for (auto it = m_processTreeNodes.constBegin(); it != m_processTreeNodes.constEnd(); ++it)
        if (it.value() && it.value()->isExpanded()) expandedPids.insert(it.key());
    int selectedPid = -1;
    QString selectedLeafKey;   // empty = process node itself was selected
    if (auto* sel = m_processTree->currentItem()) {
        const QVariant pidData = sel->data(0, Qt::UserRole);
        if (pidData.isValid()) {
            selectedPid = pidData.toInt();
        } else if (sel->parent()) {
            const QVariant parentPid = sel->parent()->data(0, Qt::UserRole);
            if (parentPid.isValid()) {
                selectedPid = parentPid.toInt();
                selectedLeafKey = sel->data(0, Qt::UserRole + 2).toString();
                if (selectedLeafKey.isEmpty())
                    selectedLeafKey = sel->text(0) + QLatin1Char('|') + sel->text(2)
                                    + QLatin1Char('|') + sel->text(3);
            }
        }
    }

    // Remember active sort so periodic rebuild does not throw the view back
    // to insertion order (sorting was effectively broken before).
    const int sortCol = m_processTree->sortColumn();
    const Qt::SortOrder sortOrder = m_processTree->header()->sortIndicatorOrder();
    const bool sortingOn = m_processTree->isSortingEnabled();

    m_processTree->setUpdatesEnabled(false);
    m_processTree->setSortingEnabled(false);   // avoid O(n log n) per insert
    m_processTree->clear();
    m_processTreeNodes.clear();

    // Pass 1: learn each PID's display name and parent PID. A process's own
    // ProcStart event is the only place parentPid/parentProcessName are
    // reliably populated (see the COL_PARENT comment above
    // insertEventRow), so this has to be a separate pass before we can
    // place anything in the hierarchy.
    struct Meta { QString name; int parentPid = 0; QString parentName; };
    QHash<int, Meta> meta;
    const auto& events = m_log->getAllEvents();
    for (const auto& ev : events) {
        if (ev.pid <= 0) continue;
        Meta& m = meta[ev.pid];
        if (m.name.isEmpty() && !ev.processName.isEmpty()) m.name = ev.processName;
        if (ev.type == ActivityEvent::Type::ProcStart && ev.parentPid > 0) {
            m.parentPid  = ev.parentPid;
            m.parentName = ev.parentProcessName;
        }
    }

    // Pass 2: build the hierarchy, then attach each event that passes the
    // same filters the flat table uses — type checkboxes, process-name
    // box, ignore list, AND the search box. The search check used to be
    // missing entirely here, which is why typing in Search previously had
    // no effect while grouped by process — it only ever touched the
    // (hidden) flat table. Note this checks process name/pid/type/details
    // together rather than honoring the table's per-column "search in X"
    // selector — a tree leaf is one combined row, not discrete cells, so
    // there's no clean equivalent of "search only the Details column" here.
    //
    // A process whose own events are all filtered out still gets a node IF
    // it's an ancestor of some process that does have visible events —
    // that falls out for free from ensureProcessTreeNode()'s recursive
    // parent-chain creation below, not from any explicit ancestor-keeping
    // logic.
    const QString procFilter = m_processFilter ? m_processFilter->text() : QString();
    const QString term = m_searchEdit ? m_searchEdit->text().trimmed() : QString();
    const bool hasTerm = !term.isEmpty();
    if (m_searchColCombo)
        m_searchColumn = m_searchColCombo->currentData().toInt();
    const int searchCol = m_searchColumn; // -1 = all

    // Map a column index to the event field string used for matching.
    auto fieldForCol = [](const ActivityEvent& ev, int col,
                          const QString& typeStr, const QString& timeStr) -> QString {
        switch (col) {
        case 0:  return timeStr;                                      // COL_TIME
        case 1:  return ev.pid > 0 ? QString::number(ev.pid) : QString(); // COL_PID
        case 2:  return ev.processName;                               // COL_PROCESS
        case 3:  return ev.parentProcessName;                         // COL_PARENT
        case 4:  return typeStr;                                      // COL_TYPE
        case 5:  return ev.details;                                   // COL_DETAILS
        case 6:  return ev.hostname;                                  // COL_HOSTNAME
        case 7:  return ev.dnsServer;                                 // COL_DNS_SERVER
        case 8:  return ev.operationStatus;                           // COL_STATUS
        case 9:  return ev.publisher;                                 // COL_PUBLISHER
        case 10: return ev.signatureStatus;                           // COL_SIGNATURE
        case 11: return ev.commandLine;                               // COL_CMDLINE
        case 12: return ev.fullPath;                                  // COL_PATH
        case 13: return ev.fileVersion;                               // COL_VERSION
        case 14: return ev.serviceName;                               // COL_SERVICE
        case 15: return ev.userName;                                  // COL_USER
        default: return {};
        }
    };

    // Hard cap on event leaves so a broad search cannot freeze the UI creating
    // tens of thousands of QTreeWidgetItems on the GUI thread.
    static const int kMaxTreeLeaves = 4000;
    int leavesAdded = 0;
    int matchCount = 0;
    bool hitCap = false;

    for (const auto& ev : events) {
        if (ev.pid <= 0) continue;
        if (!isEventTypeVisible(ev.type)) continue;
        if (!procFilter.isEmpty() && !ev.processName.contains(procFilter, Qt::CaseInsensitive))
            continue;
        if (isIgnored(ev.processName, ev.details)) continue;

        const QString typeStr = ActivityEvent::typeToString(ev.type);
        const QString timeStr = ev.timestamp.toString(QStringLiteral("HH:mm:ss.zzz"));
        if (hasTerm) {
            bool matches = false;
            if (searchCol >= 0) {
                // Specific column only
                matches = fieldForCol(ev, searchCol, typeStr, timeStr)
                              .contains(term, Qt::CaseInsensitive);
            } else {
                // All columns
                matches =
                    ev.processName.contains(term, Qt::CaseInsensitive)
                    || QString::number(ev.pid).contains(term)
                    || typeStr.contains(term, Qt::CaseInsensitive)
                    || ev.details.contains(term, Qt::CaseInsensitive)
                    || timeStr.contains(term, Qt::CaseInsensitive)
                    || ev.userName.contains(term, Qt::CaseInsensitive)
                    || ev.fullPath.contains(term, Qt::CaseInsensitive)
                    || ev.hostname.contains(term, Qt::CaseInsensitive)
                    || ev.parentProcessName.contains(term, Qt::CaseInsensitive)
                    || ev.commandLine.contains(term, Qt::CaseInsensitive)
                    || ev.publisher.contains(term, Qt::CaseInsensitive)
                    || ev.operationStatus.contains(term, Qt::CaseInsensitive);
            }
            if (!matches) continue;
        }
        ++matchCount;
        if (leavesAdded >= kMaxTreeLeaves) {
            hitCap = true;
            continue; // keep counting matches for status, skip item creation
        }

        const Meta& m = meta.value(ev.pid);
        QTreeWidgetItem* procNode = ensureProcessTreeNode(
            ev.pid, m.name.isEmpty() ? ev.processName : m.name, m.parentPid, m.parentName);

        // Enrich the process node with publisher / signature / path / cmdline
        // as soon as any event for that PID carries the data (ProcessInfoWorker
        // fills these asynchronously onto events).
        fillProcessNodeMeta(procNode, ev);
        // Skip icon I/O while a search filter is active — major cost on large logs.
        if (!hasTerm && m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()
            && procNode->icon(0).isNull()) {
            QString path = resolveDevicePath(ev.fullPath);
            if (path.isEmpty()) {
                auto cit = m_procInfoCache.constFind(ev.pid);
                if (cit != m_procInfoCache.constEnd())
                    path = resolveDevicePath(cit->path);
            }
            const QString pname = m.name.isEmpty() ? ev.processName : m.name;
            if (!path.isEmpty() && !pathMatchesExeName(path, pname))
                path.clear();
            const QIcon ic = iconForProcessPath(path, pname);
            if (!ic.isNull())
                procNode->setIcon(0, ic);
        }

        auto* leaf = new QTreeWidgetItem();
        leaf->setText(0, timeStr);
        leaf->setData(1, Qt::DisplayRole, ev.pid);
        leaf->setText(2, typeStr);
        leaf->setText(3, ev.details);
        leaf->setBackground(2, QBrush(QColor(ActivityEvent::typeToColor(ev.type))));
        // Stable key so selection can be restored after clear()+rebuild.
        // (UserRole on col 0 stays invalid so leaves are not treated as process nodes.)
        leaf->setData(0, Qt::UserRole + 2,
                      timeStr + QLatin1Char('|') + typeStr + QLatin1Char('|') + ev.details);
        // Event leaves leave the process-metadata columns empty so the eye
        // stays on the bold process row for Verified / Path / Cmd Line.
        procNode->addChild(leaf);
        ++leavesAdded;
    }

    if (hitCap && m_statusLabel) {
        m_statusLabel->setText(
            QStringLiteral("Group-by-process: showing %1 of %2 matches — refine search to see the rest")
                .arg(kMaxTreeLeaves).arg(matchCount));
    }

    // Restore expand state: only PIDs that were expanded stay expanded;
    // brand-new processes stay collapsed.
    for (auto it = m_processTreeNodes.constBegin(); it != m_processTreeNodes.constEnd(); ++it)
        if (it.value()) it.value()->setExpanded(expandedPids.contains(it.key()));

    QTreeWidgetItem* restoredItem = nullptr;
    if (selectedPid >= 0) {
        auto nodeIt = m_processTreeNodes.constFind(selectedPid);
        if (nodeIt != m_processTreeNodes.constEnd() && nodeIt.value()) {
            QTreeWidgetItem* proc = nodeIt.value();
            restoredItem = proc;
            if (!selectedLeafKey.isEmpty()) {
                for (int i = 0; i < proc->childCount(); ++i) {
                    QTreeWidgetItem* ch = proc->child(i);
                    if (ch && ch->data(0, Qt::UserRole + 2).toString() == selectedLeafKey) {
                        restoredItem = ch;
                        break;
                    }
                }
            }
            // Restore selection only — do not scrollToItem (keeps view still).
            m_processTree->setCurrentItem(restoredItem);
            restoredItem->setSelected(true);
        }
    }
    // Restore sort indicator and order, then re-enable sorting so a click on
    // a header actually reorders top-level process rows.
    if (sortingOn) {
        m_processTree->sortByColumn(sortCol >= 0 ? sortCol : 0, sortOrder);
        m_processTree->setSortingEnabled(true);
    }

    m_processTree->setUpdatesEnabled(true);
    // Always keep the previous scroll position; never jump to the selection.
    m_processTree->verticalScrollBar()->setValue(scrollValue);
}

void MainWindow::onProcessTreeItemDoubleClicked(QTreeWidgetItem* item, int /*column*/)
{
    if (!item) return;
    // Process node: UserRole holds pid. Event leaf: resolve via parent process node.
    QTreeWidgetItem* procNode = item;
    QVariant pidData = item->data(0, Qt::UserRole);
    if (!pidData.isValid() && item->parent()) {
        procNode = item->parent();
        pidData = procNode->data(0, Qt::UserRole);
    }
    if (!pidData.isValid()) return;
    const int pid = pidData.toInt();
    const QString name = procNode->text(0);
    showProcessDetailWindow(pid, name);
}

void MainWindow::onProcessTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = m_processTree->itemAt(pos);
    if (!item) return;
    QTreeWidgetItem* procNode = item;
    QVariant pidData = item->data(0, Qt::UserRole);
    if (!pidData.isValid() && item->parent()) {
        procNode = item->parent();
        pidData = procNode->data(0, Qt::UserRole);
    }
    if (!pidData.isValid()) return;

    const int pid = pidData.toInt();
    const QString name = procNode->text(0);
    QMenu menu(this);
    menu.addAction(QString("📋 Open events window for \"%1\"").arg(name), this, [this, pid, name]() {
        showProcessDetailWindow(pid, name);
    });
    menu.exec(m_processTree->viewport()->mapToGlobal(pos));
}

// ============================================================
// Per-process detail window
// ============================================================
// A separate, non-modal Qt::Window (not a blocking dialog — several can be
// open at once, and the main window stays fully usable) listing every
// event ever captured for one PID, pulled from m_log (so it includes
// history from before the window was opened, same source of truth as the
// process tree). Refreshes on the same 2s cadence as the tree rather than
// being wired into the live event stream directly, to avoid adding a
// second live-update path alongside flushPendingEvents()/rebuildProcessTree
// that would need its own careful testing.
QSet<int> MainWindow::collectProcessSubtreePids(int rootPid) const
{
    QHash<int, QList<int>> childrenOf;
    for (const auto& ev : m_log->getAllEvents())
        if (ev.type == ActivityEvent::Type::ProcStart && ev.parentPid > 0)
            childrenOf[ev.parentPid].append(ev.pid);

    QSet<int> result;
    QList<int> stack{rootPid};
    while (!stack.isEmpty()) {
        const int p = stack.takeLast();
        if (result.contains(p)) continue;   // already visited (also guards any pid-reuse cycle)
        result.insert(p);
        for (int child : childrenOf.value(p)) stack.append(child);
    }
    return result;
}

void MainWindow::showProcessDetailWindow(int pid, const QString& processName)
{
    // Already open for this pid — just bring it to front instead of
    // opening a duplicate.
    auto existing = m_processDetailWindows.constFind(pid);
    if (existing != m_processDetailWindows.constEnd() && existing.value()) {
        existing.value()->raise();
        existing.value()->activateWindow();
        return;
    }

    // nullptr parent → independent top-level HWND → own Windows taskbar button
    // (a parented QDialog is "owned" by the main window and shares its taskbar entry).
    auto* win = new QDialog(nullptr, Qt::Window);
    win->setAttribute(Qt::WA_DeleteOnClose);
    win->setAttribute(Qt::WA_QuitOnClose, false);
    win->setStyleSheet(appButtonStyleSheet());
    win->setWindowTitle(QString("Events for %1  (PID %2)").arg(processName).arg(pid));
    win->resize(820, 480);

    // The window now has two tabs. "Events" is the existing flat list, kept
    // exactly as it was. "Timeline" is the per-process narrative built by
    // ProcessTimelineBuilder. The Events content is built into its own page.
    auto* rootLayout = new QVBoxLayout(win);
    auto* tabs = new QTabWidget(win);
    rootLayout->addWidget(tabs);
    auto* eventsPage = new QWidget(tabs);
    auto* vl = new QVBoxLayout(eventsPage);
    tabs->addTab(eventsPage, QStringLiteral("Events"));
    auto* header = new QLabel(eventsPage);
    header->setStyleSheet("font-weight:bold; padding:2px;");
    vl->addWidget(header);

    auto* includeSubCb = new QCheckBox("Include sub-processes (recursive)", eventsPage);
    includeSubCb->setToolTip(
        "Off: only events where this exact process is the one that acted.\n"
        "On: also include every descendant process's events in this same\n"
        "window — children, grandchildren, and so on — with a Process\n"
        "column added so you can tell which one did what.");
    vl->addWidget(includeSubCb);

    auto* table = new QTableWidget(eventsPage);
    table->setColumnCount(4);
    table->setHorizontalHeaderLabels({"Time", "Type", "Details", "Process"});
    // Stretch Details (col 2) to fill the window. Do NOT use stretchLastSection:
    // the last column is Process, often hidden, which left Details only a few
    // characters wide.
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table->setColumnHidden(3, true);   // shown only when "Include sub-processes" is on
    table->setTextElideMode(Qt::ElideRight);
    table->setWordWrap(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    installOverflowTooltips(table);
    vl->addWidget(table, 3);

    // Child processes this one started — events are recorded under the
    // CHILD's own pid (ev.pid = child, ev.parentPid = this process), so
    // they'd otherwise never appear in a window filtered to ev.pid==pid.
    // Without this, a parent's own detail window looks like it did
    // nothing even when it's the thing that spawned everything else in the
    // tree under it — which is exactly the gap being fixed here.
    auto* childLabel = new QLabel("Child processes started by this process:", eventsPage);
    childLabel->setStyleSheet("font-weight:bold; padding-top:4px;");
    vl->addWidget(childLabel);
    auto* childList = new QListWidget(eventsPage);
    childList->setMaximumHeight(110);
    childList->setToolTip("Double-click to open that process's own events window.");
    vl->addWidget(childList, 1);
    connect(childList, &QListWidget::itemDoubleClicked, win, [this](QListWidgetItem* item) {
        if (!item) return;
        const int childPid = item->data(Qt::UserRole).toInt();
        const QString childName = item->data(Qt::UserRole + 1).toString();
        if (childPid > 0) showProcessDetailWindow(childPid, childName);
    });

    auto* btnRow = new QHBoxLayout();
    auto* exportBtn = new QPushButton("📄 Export to CSV...", eventsPage);
    btnRow->addWidget(exportBtn);
    btnRow->addStretch();
    auto* closeBtn = new QPushButton("Close", eventsPage);
    btnRow->addWidget(closeBtn);
    vl->addLayout(btnRow);
    connect(closeBtn, &QPushButton::clicked, win, &QDialog::close);

    // ---- Timeline tab ------------------------------------------------------
    auto* timelinePage = new QWidget(tabs);
    auto* tl = new QVBoxLayout(timelinePage);
    auto* lifetimeLabel = new QLabel(timelinePage);
    lifetimeLabel->setStyleSheet("font-weight:bold; font-size:12pt; padding:2px;");
    tl->addWidget(lifetimeLabel);

    auto* countsLabel = new QLabel(timelinePage);
    countsLabel->setWordWrap(true);
    countsLabel->setStyleSheet("color:#555; padding:2px;");
    tl->addWidget(countsLabel);

    auto* timelineList = new QListWidget(timelinePage);
    timelineList->setAlternatingRowColors(true);
    timelineList->setToolTip("Every event this process produced, oldest first.");
    tl->addWidget(timelineList, 3);

    auto* childHeader = new QLabel("Child processes (oldest first):", timelinePage);
    childHeader->setStyleSheet("font-weight:bold; padding-top:4px;");
    tl->addWidget(childHeader);
    auto* timelineChildren = new QListWidget(timelinePage);
    timelineChildren->setMaximumHeight(110);
    timelineChildren->setToolTip("Double-click to open that child's own timeline.");
    tl->addWidget(timelineChildren, 1);
    connect(timelineChildren, &QListWidget::itemDoubleClicked, win, [this](QListWidgetItem* item) {
        if (!item) return;
        const int childPid = item->data(Qt::UserRole).toInt();
        const QString childName = item->data(Qt::UserRole + 1).toString();
        if (childPid > 0) showProcessDetailWindow(childPid, childName);
    });

    tabs->addTab(timelinePage, QStringLiteral("Timeline"));

    // Build the timeline only when its tab is showing, and only when the log has
    // changed since the last build. The Events tab refreshes every 2 seconds and
    // a second full scan here would double that cost.
    struct TimelineState { quint64 builtRevision = 0; };
    auto tlState = std::make_shared<TimelineState>();
    auto refreshTimeline = [this, pid, tlState, lifetimeLabel, countsLabel,
                            timelineList, timelineChildren, tabs, timelinePage]()
    {
        if (tabs->currentWidget() != timelinePage) return;
        if (tlState->builtRevision == m_log->revision() && tlState->builtRevision != 0)
            return;
        tlState->builtRevision = m_log->revision();

        const ProcessTimeline t = ProcessTimelineBuilder::build(m_log->getAllEvents(), pid);
        timelineList->setUpdatesEnabled(false);
        timelineList->clear();
        timelineChildren->clear();

        if (t.pid == 0) {
            lifetimeLabel->setText("No activity recorded for this process yet.");
            countsLabel->clear();
            timelineList->setUpdatesEnabled(true);
            return;
        }

        const QString name = t.processName.isEmpty() ? QStringLiteral("(unknown)") : t.processName;
        const QString owner = t.userName.isEmpty()
            ? QStringLiteral("owner not yet read")
            : t.userName;
        lifetimeLabel->setText(QString("%1  (PID %2)  ·  user: %3  —  %4")
                                   .arg(name).arg(pid).arg(owner)
                                   .arg(ProcessTimelineBuilder::lifetimeText(t)));

        // Summary strip: one "count type" per activity seen.
        QStringList parts;
        for (auto it = t.countsByType.constBegin(); it != t.countsByType.constEnd(); ++it)
            parts << QString("%1 %2").arg(it.value()).arg(it.key());
        countsLabel->setText(parts.isEmpty()
            ? QStringLiteral("No events.")
            : QString("%1 event(s):  %2").arg(t.totalEvents()).arg(parts.join("  •  ")));

        if (t.parentPid > 0) {
            lifetimeLabel->setToolTip(QString("Started by %1 (PID %2)")
                                          .arg(t.parentName.isEmpty() ? QStringLiteral("?") : t.parentName)
                                          .arg(t.parentPid));
        }

        for (const ActivityEvent& ev : t.events) {
            QString det = ev.details;
            if (det.size() > 512)
                det = det.left(512) + QStringLiteral("…");
            auto* item = new QListWidgetItem(
                QString("%1   %2   %3")
                    .arg(ev.timestamp.toString("HH:mm:ss.zzz"))
                    .arg(ActivityEvent::typeToString(ev.type), -21)
                    .arg(det));
            QString tip = ev.details;
            if (tip.size() > 4096)
                tip = tip.left(4096) + QStringLiteral("\n… (truncated)");
            item->setToolTip(tip);
            item->setBackground(QBrush(QColor(ActivityEvent::typeToColor(ev.type))));
            timelineList->addItem(item);
        }
        timelineList->setUpdatesEnabled(true);
        if (timelineList->count() > 0) timelineList->scrollToBottom();

        for (const TimelineChild& c : t.children) {
            const QString state = c.stillRunning ? QStringLiteral("running") : QStringLiteral("exited");
            auto* item = new QListWidgetItem(
                QString("%1  (PID %2)  started %3  —  %4 event(s), %5")
                    .arg(c.processName.isEmpty() ? QStringLiteral("(unknown)") : c.processName)
                    .arg(c.pid)
                    .arg(c.started.toString("HH:mm:ss"))
                    .arg(c.eventCount)
                    .arg(state));
            item->setData(Qt::UserRole, c.pid);
            item->setData(Qt::UserRole + 1, c.processName);
            timelineChildren->addItem(item);
        }
    };
    // Build Timeline only when the user switches to that tab — no periodic
    // auto-refresh (avoids the list jumping while you read it).
    connect(tabs, &QTabWidget::currentChanged, win, [refreshTimeline](int) { refreshTimeline(); });

    // Refresh is a self-contained lambda (not a separate member function)
    // since it only ever needs to run against this one window/table/pid —
    // each open window gets its own timer and its own closure, so multiple
    // windows for different PIDs don't interfere with each other.
    auto refresh = [this, table, header, childList, includeSubCb, pid, processName]() {
        const bool includeSub = includeSubCb->isChecked();
        table->setColumnHidden(3, !includeSub);

        const QSet<int> subtreePids = includeSub ? collectProcessSubtreePids(pid) : QSet<int>{pid};

        const int scrollValue = table->verticalScrollBar()->value();
        const int selectedRow = table->currentRow();
        QString selectedTime = (selectedRow >= 0 && table->item(selectedRow, 0))
            ? table->item(selectedRow, 0)->text() : QString();

        table->setUpdatesEnabled(false);
        table->setSortingEnabled(false);
        table->setRowCount(0);
        childList->clear();

        // Prefer cached process-info user; fall back to any event that already has it.
        QString owner;
        {
            auto cit = m_procInfoCache.constFind(pid);
            if (cit != m_procInfoCache.constEnd() && !cit->user.isEmpty())
                owner = cit->user;
        }

        int count = 0;
        int newSelectedRow = -1;
        for (const auto& ev : m_log->getAllEvents()) {
            if (subtreePids.contains(ev.pid)) {
                if (owner.isEmpty() && ev.pid == pid && !ev.userName.isEmpty())
                    owner = ev.userName;
                const int row = table->rowCount();
                table->insertRow(row);
                auto* timeItem = new QTableWidgetItem(ev.timestamp.toString("HH:mm:ss.zzz"));
                auto* typeItem = new QTableWidgetItem(ActivityEvent::typeToString(ev.type));
                // Cap extremely long paths/details for the cell text (display + memory).
                static const int kMaxCellChars = 8192;
                QString detailsText = ev.details;
                if (detailsText.size() > kMaxCellChars)
                    detailsText = detailsText.left(kMaxCellChars) + QStringLiteral("…");
                auto* detItem  = new QTableWidgetItem(detailsText);
                auto* procItem = new QTableWidgetItem(
                    QString("%1 (%2)").arg(ev.processName).arg(ev.pid));
                const QColor bg(ActivityEvent::typeToColor(ev.type));
                timeItem->setBackground(QBrush(bg));
                typeItem->setBackground(QBrush(bg));
                detItem->setBackground(QBrush(bg));
                procItem->setBackground(QBrush(bg));
                table->setItem(row, 0, timeItem);
                table->setItem(row, 1, typeItem);
                table->setItem(row, 2, detItem);
                table->setItem(row, 3, procItem);
                if (!selectedTime.isEmpty() && timeItem->text() == selectedTime) newSelectedRow = row;
                ++count;
            }
            if (ev.type == ActivityEvent::Type::ProcStart && ev.parentPid == pid) {
                auto* item = new QListWidgetItem(
                    QString("%1  (PID %2)  at %3").arg(ev.processName).arg(ev.pid)
                        .arg(ev.timestamp.toString("HH:mm:ss.zzz")));
                item->setData(Qt::UserRole, ev.pid);
                item->setData(Qt::UserRole + 1, ev.processName);
                childList->addItem(item);
            }
        }

        table->setSortingEnabled(true);
        if (newSelectedRow >= 0) table->selectRow(newSelectedRow);
        table->setUpdatesEnabled(true);
        table->verticalScrollBar()->setValue(scrollValue);

        const QString ownerPart = owner.isEmpty()
            ? QString()
            : QString("  ·  user: %1").arg(owner);
        const QString namePart = processName.isEmpty()
            ? QString("PID %1").arg(pid)
            : QString("%1 (PID %2)").arg(processName).arg(pid);
        header->setText(includeSub
            ? QString("%1 — %2 event%3 across this process and %4 descendant%5%6")
                .arg(namePart).arg(count).arg(count == 1 ? "" : "s")
                .arg(subtreePids.size() - 1).arg(subtreePids.size() - 1 == 1 ? "" : "s")
                .arg(ownerPart)
            : QString("%1 — %2 event%3 captured for this process%4")
                .arg(namePart).arg(count).arg(count == 1 ? "" : "s")
                .arg(ownerPart));
    };

    connect(includeSubCb, &QCheckBox::toggled, win, refresh);

    // Exports EVERY field on ActivityEvent for this pid's events — not just
    // the Time/Type/Details columns shown in the table above — since
    // what's useful for a quick read in the UI and what's useful for
    // offline analysis (publisher, signature status, full path, command
    // line, etc.) aren't the same thing.
    connect(exportBtn, &QPushButton::clicked, win, [this, win, pid, processName, includeSubCb]() {
        const bool includeSub = includeSubCb->isChecked();
        const QSet<int> subtreePids = includeSub ? collectProcessSubtreePids(pid) : QSet<int>{pid};
        const QString suggested = QString("events_%1_pid%2%3.csv")
            .arg(processName.isEmpty() ? "process" : processName).arg(pid)
            .arg(includeSub ? "_with_subprocesses" : "");
        const QString path = QFileDialog::getSaveFileName(
            win, "Export Events to CSV", suggested, "CSV Files (*.csv)");
        if (path.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::warning(win, "Export Failed", QString("Couldn't write %1").arg(path));
            return;
        }

        auto csvField = [](const QString& s) {
            QString out = s;
            out.replace('"', "\"\"");
            return '"' + out + '"';
        };

        QTextStream out(&f);
        out << "Timestamp,PID,ProcessName,ParentPID,ParentProcessName,Type,Details,"
               "Hostname,FullPath,Publisher,SignatureStatus,FileVersion,ServiceName,CommandLine,UserName\n";
        int rows = 0;
        for (const auto& ev : m_log->getAllEvents()) {
            if (!subtreePids.contains(ev.pid)) continue;
            out << csvField(ev.timestamp.toString(Qt::ISODateWithMs)) << ','
                << ev.pid << ','
                << csvField(ev.processName) << ','
                << ev.parentPid << ','
                << csvField(ev.parentProcessName) << ','
                << csvField(ActivityEvent::typeToString(ev.type)) << ','
                << csvField(ev.details) << ','
                << csvField(ev.hostname) << ','
                << csvField(ev.fullPath) << ','
                << csvField(ev.publisher) << ','
                << csvField(ev.signatureStatus) << ','
                << csvField(ev.fileVersion) << ','
                << csvField(ev.serviceName) << ','
                << csvField(ev.commandLine) << ','
                << csvField(ev.userName) << '\n';
            ++rows;
        }
        f.close();
        QMessageBox::information(win, "Export Complete",
            QString("Wrote %1 event%2 to:\n%3").arg(rows).arg(rows == 1 ? "" : "s").arg(path));
    });

    refresh();

    auto* timer = new QTimer(win);
    connect(timer, &QTimer::timeout, win, refresh);
    timer->start(2000);

    m_processDetailWindows.insert(pid, win);
    connect(win, &QObject::destroyed, this, [this, pid]() { m_processDetailWindows.remove(pid); });

    win->show();
}

void MainWindow::onResolveIPsToggled()
{
    if (!m_cbResolveIPs->isChecked()) return;
    for (int r = 0; r < m_eventTable->rowCount(); ++r)
    {
        auto* h = m_eventTable->item(r, COL_HOSTNAME);
        if (!h) continue;
        QString ip = h->data(Qt::UserRole).toString();
        if (ip.isEmpty()) continue;

        bool isLocal = ip == "0.0.0.0" || ip == "255.255.255.255"
                    || ip == "::1"      || ip == "::"
                    || ip.startsWith("127.")
                    || ip.startsWith("169.254.")
                    || ip.startsWith("fe80:", Qt::CaseInsensitive);
        if (isLocal) { h->setText("local"); continue; }

        if (h->text().isEmpty() || h->text() == ip) h->setText("resolving…");
        m_dnsResolver->queueResolution(ip);
    }
}


QIcon MainWindow::iconForExePath(const QString& path)
{
    if (path.isEmpty()) return {};

    // Normalize so "C:\foo.exe", "c:/foo.exe", and device-path forms share one cache slot.
    QString key = resolveDevicePath(path).trimmed();
    if (key.isEmpty()) key = path.trimmed();
    key = QDir::toNativeSeparators(key);
    if (key.size() >= 2 && key.at(1) == QLatin1Char(':'))
        key[0] = key.at(0).toUpper();

    auto it = m_iconByPath.constFind(key);
    if (it != m_iconByPath.constEnd())
        return it.value();

    // One shared provider for the whole process — constructing it is relatively expensive.
    static QFileIconProvider s_provider;

    QIcon icon;
    QFileInfo fi(key);
    if (fi.exists() && fi.isFile()) {
        icon = s_provider.icon(fi);
    }
    // Cache hits and misses (empty) so we never re-stat / re-query the shell
    // for the same path during this session.
    m_iconByPath.insert(key, icon);
    return icon;
}

bool MainWindow::pathMatchesExeName(const QString& path, const QString& processName)
{
    if (path.isEmpty()) return false;
    if (processName.isEmpty()) return true; // no name to verify against
    const QString base = QFileInfo(path).fileName();
    if (base.isEmpty()) return false;
    const QString want = QFileInfo(processName).fileName();
    if (base.compare(want, Qt::CaseInsensitive) == 0)
        return true;
    // processName sometimes omits .exe
    if (!want.endsWith(QLatin1String(".exe"), Qt::CaseInsensitive)
        && base.compare(want + QLatin1String(".exe"), Qt::CaseInsensitive) == 0)
        return true;
    if (!base.endsWith(QLatin1String(".exe"), Qt::CaseInsensitive)
        && want.compare(base + QLatin1String(".exe"), Qt::CaseInsensitive) == 0)
        return true;
    return false;
}

QIcon MainWindow::iconForProcessPath(const QString& pathHint, const QString& expectedExeName)
{
    // Exact path only — never infer from process name (names collide).
    const QString path = resolveDevicePath(pathHint).trimmed();
    if (path.isEmpty())
        return {};
    // Reject stale paths left over after PID reuse (chrome path on brave.exe PID).
    if (!expectedExeName.isEmpty() && !pathMatchesExeName(path, expectedExeName))
        return {};
    return iconForExePath(path);
}

void MainWindow::applyProcessIconToRow(int row, int pid, const QString& pathHint)
{
    if (!m_eventTable || row < 0 || row >= m_eventTable->rowCount()) return;
    auto* procItem = m_eventTable->item(row, COL_PROCESS);
    if (!procItem) return;

    if (!m_cbShowProcessIcons || !m_cbShowProcessIcons->isChecked()) {
        procItem->setIcon(QIcon());
        return;
    }

    const QString processName = procItem->text();
    QString path = resolveDevicePath(pathHint);
    if (!path.isEmpty() && !processName.isEmpty()
        && !pathMatchesExeName(path, processName))
        path.clear(); // pathHint is for a different executable

    if (path.isEmpty()) {
        auto it = m_procInfoCache.constFind(pid);
        if (it != m_procInfoCache.constEnd()) {
            path = resolveDevicePath(it->path);
            // Stale cache after PID reuse: drop it and re-fetch
            if (!path.isEmpty() && !processName.isEmpty()
                && !pathMatchesExeName(path, processName)) {
                m_procInfoCache.remove(pid);
                m_procInfoRequested.remove(pid);
                path.clear();
                if (m_procInfoWorker)
                    m_procInfoWorker->queueFetch(pid);
            }
        }
    }
    if (path.isEmpty()) {
        if (auto* pathCell = m_eventTable->item(row, COL_PATH)) {
            path = pathCell->text();
            if (!path.isEmpty() && !processName.isEmpty()
                && !pathMatchesExeName(path, processName))
                path.clear();
        }
    }
    procItem->setIcon(iconForProcessPath(path, processName));
}

void MainWindow::applyProcessIconsToTree()
{
    if (!m_processTree) return;
    const bool show = m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked();
    for (auto it = m_processTreeNodes.constBegin(); it != m_processTreeNodes.constEnd(); ++it) {
        QTreeWidgetItem* node = it.value();
        if (!node) continue;
        if (!show) {
            node->setIcon(0, QIcon());
            continue;
        }
        QString path;
        auto cit = m_procInfoCache.constFind(it.key());
        if (cit != m_procInfoCache.constEnd())
            path = resolveDevicePath(cit->path);
        if (path.isEmpty())
            path = resolveDevicePath(node->text(6));   // Path column on process node
        QString pname = node->text(0);
        const int sp = pname.indexOf(QLatin1Char(' '));
        if (sp > 0) pname = pname.left(sp);
        if (!path.isEmpty() && !pathMatchesExeName(path, pname)) {
            m_procInfoCache.remove(it.key());
            path.clear();
        }
        node->setIcon(0, iconForProcessPath(path, pname));
    }
}

void MainWindow::onShowProcessIconsToggled()
{
    if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
        // Icons need exe paths — queue metadata for every PID currently in the table
        QSet<int> queued;
        for (int r = 0; r < m_eventTable->rowCount(); ++r) {
            auto* pidCell = m_eventTable->item(r, COL_PID);
            if (!pidCell) continue;
            const int pid = pidCell->data(Qt::UserRole).toInt();
            if (pid > 0 && !queued.contains(pid)) {
                m_procInfoWorker->queueFetch(pid);
                m_procInfoRequested.insert(pid);
                queued.insert(pid);
            }
            applyProcessIconToRow(r, pid);   // uses cache if path already known
        }
        applyProcessIconsToTree();
    } else {
        for (int r = 0; r < m_eventTable->rowCount(); ++r) {
            if (auto* procItem = m_eventTable->item(r, COL_PROCESS))
                procItem->setIcon(QIcon());
        }
        applyProcessIconsToTree();
    }
}

void MainWindow::onFetchProcInfoToggled()
{
    if (!m_cbFetchProcInfo->isChecked()) return;
    QSet<int> queued;
    for (int r = 0; r < m_eventTable->rowCount(); ++r)
    {
        auto* pidCell = m_eventTable->item(r, COL_PID);
        if (!pidCell) continue;
        int pid = pidCell->data(Qt::UserRole).toInt();
        if (pid > 0 && !queued.contains(pid))
        {
            m_procInfoWorker->queueFetch(pid);
            queued.insert(pid);
        }
    }
}

// ============================================================
// Search
// ============================================================
void MainWindow::onSearchTextChanged(const QString&)
{
    scheduleFilterApply();   // debounced — this fires on every keystroke
}

void MainWindow::onSearchColumnChanged(int /*comboIdx*/)
{
    m_searchColumn = m_searchColCombo->currentData().toInt();
    if (!m_searchEdit->text().isEmpty())
        applyFiltersAndMaybeTree();   // combo selection is infrequent — no need to debounce
}

// ============================================================
// Column filter management
// ============================================================
void MainWindow::onAddColumnFilter()
{
    Diagnostics::breadcrumb("column filter add requested");
    QString pat = m_filterPatternEdit->text().trimmed();
    if (pat.isEmpty()) return;

    const QString problem = validateUserRegex(pat);
    if (!problem.isEmpty())
    {
        QMessageBox::warning(this, "Invalid Regex", problem);
        return;
    }

    if (m_columnFilters.size() >= kMaxColumnFilters)
    {
        QMessageBox::information(this, "Filter limit reached",
            QString("You can have at most %1 column filters at once.\n"
                    "Remove some before adding more.").arg(kMaxColumnFilters));
        return;
    }

    int col = m_filterColCombo->currentData().toInt();
    QRegularExpression rx(pat, QRegularExpression::CaseInsensitiveOption);
    if (rx.isValid()) rx.optimize();
    m_columnFilters.append({col, pat, rx});
    m_filterPatternEdit->clear();
    rebuildFilterTagsUI();
    scheduleFilterApply();      // coalesce a burst of adds into one pass
}

// Identified by content, not list position: the ✕ buttons defer this call, so the
// list may have changed by the time it runs. A stale click can never remove a
// different filter.
void MainWindow::onRemoveColumnFilter(int column, const QString& pattern)
{
    Diagnostics::breadcrumb(QString("column filter removed: %1 %2").arg(column).arg(pattern));
    for (int i = 0; i < m_columnFilters.size(); ++i) {
        if (m_columnFilters[i].column == column && m_columnFilters[i].pattern == pattern) {
            m_columnFilters.removeAt(i);
            break;
        }
    }
    rebuildFilterTagsUI();
    scheduleFilterApply();
}

// ============================================================
// Capture condition management
// ============================================================
void MainWindow::onAddCaptureCondition()
{
    Diagnostics::breadcrumb("capture condition add requested");
    QString pat = m_capturePatternEdit->text().trimmed();
    if (pat.isEmpty()) return;

    const QString problem = validateUserRegex(pat);
    if (!problem.isEmpty())
    {
        QMessageBox::warning(this, "Invalid Regex", problem);
        return;
    }

    if (m_captureConditions.size() >= kMaxCaptureConditions)
    {
        QMessageBox::information(this, "Capture limit reached",
            QString("You can have at most %1 capture conditions.").arg(kMaxCaptureConditions));
        return;
    }

    int col = m_captureColCombo->currentData().toInt();
    QRegularExpression rx(pat, QRegularExpression::CaseInsensitiveOption);
    if (rx.isValid()) rx.optimize();
    m_captureConditions.append({col, pat, rx});
    m_capturePatternEdit->clear();
    rebuildCaptureTagsUI();

    m_statusLabel->setText(
        QString("Capture condition added — only events matching '%1' in %2 will be logged.")
            .arg(pat, COL_NAMES.value(col, "?")));
}

void MainWindow::onRemoveCaptureCondition(int column, const QString& pattern)
{
    for (int i = 0; i < m_captureConditions.size(); ++i) {
        if (m_captureConditions[i].column == column && m_captureConditions[i].pattern == pattern) {
            m_captureConditions.removeAt(i);
            break;
        }
    }
    rebuildCaptureTagsUI();

    if (m_captureConditions.isEmpty())
        m_statusLabel->setText("All capture conditions removed — capturing all events.");
}

// ============================================================
// View options
// ============================================================
void MainWindow::onToggleSidePanel(bool visible)
{
    m_leftPanel->setVisible(visible);
}

void MainWindow::onToggleToolbar(bool visible)
{
    if (m_mainToolbar) m_mainToolbar->setVisible(visible);
}

void MainWindow::onToggleStatusBar(bool visible)
{
    statusBar()->setVisible(visible);
}

// ============================================================
// Event receive slots
// ============================================================
void MainWindow::onFileEventDetected(ActivityEvent ev)
{ enqueueEvent(std::move(ev)); }

void MainWindow::onProcessEventDetected(ActivityEvent ev)
{ enqueueEvent(std::move(ev)); }

void MainWindow::onNetworkEventDetected(ActivityEvent ev)
{ enqueueEvent(std::move(ev)); }

void MainWindow::onStatusMessage(QString msg)
{
    m_statusLabel->setText(msg);
}

// A watcher thread finished. If we did not ask it to stop, it failed or
// ended on its own: say so and reflect it in the monitor state, instead of
// leaving the UI claiming capture is active.
void MainWindow::onWatcherFinished(const QString& name)
{
    if (m_stopping || !m_isMonitoring) return;
    ++m_unexpectedExits;
    m_statusLabel->setText(QString("WARNING: %1 stopped unexpectedly. "
                                   "Capture from that source has ended.").arg(name));
    if (m_unexpectedExits >= m_expectedWatchers) {
        // Nothing is capturing any more: reflect the real state.
        m_isMonitoring = false;
        updateUIState(false);
        m_monitorStateLabel->setText("● Failed");
        m_monitorStateLabel->setStyleSheet("color:#c62828;font-weight:bold;");
    }
}


// ============================================================
// Hostname learning for Network view (IP → name)
// ============================================================
// Sources:
//   1) DNS Query events with "name -> ip; ip2" in details
//   2) Network events that already have a resolved hostname
//   3) DnsResolver reverse lookups (via onHostnameResolved)
static QString dnsQueryNameFromDetails(const QString& details)
{
    // "example.com (A) -> 1.2.3.4" or "example.com (A) (failed: ...)"
    const QString left = details.section(QStringLiteral("->"), 0, 0).trimmed();
    if (left.isEmpty()) return {};
    // First token is the query name (stop at whitespace or '(')
    int end = 0;
    while (end < left.size()) {
        const QChar c = left.at(end);
        if (c.isSpace() || c == QLatin1Char('(')) break;
        ++end;
    }
    return left.left(end).trimmed();
}

static QStringList ipv4AddressesInText(const QString& text)
{
    QStringList out;
    // Simple IPv4 scan — good enough for DNS result lists
    static const QRegularExpression re(
        QStringLiteral(R"((\b(?:\d{1,3}\.){3}\d{1,3}\b))"));
    auto it = re.globalMatch(text);
    while (it.hasNext()) {
        const QString ip = it.next().captured(1);
        // Skip obvious non-routable garbage from bad matches is rare; keep all
        if (!out.contains(ip))
            out.append(ip);
    }
    return out;
}

void MainWindow::learnHostnamesFromEvent(const ActivityEvent& ev)
{
    if (ev.type == ActivityEvent::Type::DnsQuery) {
        const QString qname = dnsQueryNameFromDetails(ev.details);
        if (qname.isEmpty() || qname.contains(QLatin1Char(':'))) // skip bare IPv6-looking
            return;
        // Only the results section after "->" carries answer addresses
        const int arrow = ev.details.indexOf(QStringLiteral("->"));
        if (arrow < 0) return;
        QString results = ev.details.mid(arrow + 2);
        // Drop trailing coalesce notes like "(×2 recently)"
        const int paren = results.indexOf(QStringLiteral(" ("));
        if (paren > 0) results = results.left(paren);
        for (const QString& ip : ipv4AddressesInText(results)) {
            if (ip.startsWith(QLatin1String("0.")) || ip == QLatin1String("0.0.0.0"))
                continue;
            if (m_hostnameKnown.size() > 20000) m_hostnameKnown.clear();
            // Prefer a real DNS query name over a previous reverse PTR if missing
            if (!m_hostnameKnown.contains(ip) || m_hostnameKnown.value(ip) == ip)
                m_hostnameKnown.insert(ip, qname);
            if (m_behaviorMonitor)
                m_behaviorMonitor->setHostname(ip, qname);
        }
        return;
    }

    // Network / other events: hostname field filled by DnsResolver or log load
    if (!ev.hostname.isEmpty() && ev.hostname != ev.details) {
        QString ip = extractRemoteIP(ev.details);
        if (ip.isEmpty() && ev.isNetworkEvent()) {
            // details may be "a.b.c.d:port -> e.f.g.h:port"
            ip = extractRemoteIP(ev.details);
        }
        if (ip.isEmpty()) {
            // hostname column sometimes set while IP is only in details without "->"
            for (const QString& cand : ipv4AddressesInText(ev.details)) {
                if (cand != ev.hostname) { ip = cand; break; }
            }
        }
        if (!ip.isEmpty() && ev.hostname != ip) {
            if (m_hostnameKnown.size() > 20000) m_hostnameKnown.clear();
            m_hostnameKnown.insert(ip, ev.hostname);
            if (m_behaviorMonitor)
                m_behaviorMonitor->setHostname(ip, ev.hostname);
        }
    }
}

void MainWindow::syncHostnamesToBehaviorMonitor()
{
    if (!m_behaviorMonitor) return;
    for (auto it = m_hostnameKnown.constBegin(); it != m_hostnameKnown.constEnd(); ++it) {
        if (!it.key().isEmpty() && !it.value().isEmpty() && it.key() != it.value())
            m_behaviorMonitor->setHostname(it.key(), it.value());
    }
}

void MainWindow::enrichBehaviorHostnames(bool fullLogScan)
{
    if (!m_behaviorMonitor) return;

    // 1) Push everything we already know (cheap: hash copy into monitor)
    syncHostnamesToBehaviorMonitor();

    // 2) Full log rescan only when requested (window open / after load).
    // Doing this on every auto-refresh or Clear was O(events) on the UI thread
    // and made Clear feel like the app froze.
    if (fullLogScan && m_log) {
        const auto& events = m_log->getAllEvents();
        for (const ActivityEvent& ev : events) {
            if (ev.type == ActivityEvent::Type::DnsQuery || !ev.hostname.isEmpty())
                learnHostnamesFromEvent(ev);
        }
    }

    // 3) Reverse-DNS a limited batch of unknown remote IPs (if enabled)
    if (m_cbResolveIPs && m_cbResolveIPs->isChecked() && m_dnsResolver) {
        const auto rows = m_behaviorMonitor->snapshotByProcessHost();
        int queued = 0;
        for (const BehaviorRow& row : rows) {
            if (queued >= 32) break; // bound work per refresh
            if (row.remoteIP.isEmpty()) continue;
            if (row.protocol == QLatin1String("UDP")) continue;
            if (!row.remoteHost.isEmpty()) continue;
            if (m_hostnameKnown.contains(row.remoteIP)) {
                m_behaviorMonitor->setHostname(row.remoteIP, m_hostnameKnown.value(row.remoteIP));
                continue;
            }
            m_dnsResolver->queueResolution(row.remoteIP);
            ++queued;
        }
    }
}

// ============================================================
// SLOT: onHostnameResolved
// ============================================================
void MainWindow::onHostnameResolved(QString ip, QString hostname)
{
    if (m_behaviorMonitor)
        m_behaviorMonitor->setHostname(ip, hostname);

    // Do not replace a name we already have with the bare IP: a transient DNS
    // failure reports the IP as its fallback, which must not undo a good name.
    if (hostname == ip) return;          // no name learned; leave the row as the IP
    if (m_hostnameKnown.size() > 20000) m_hostnameKnown.clear();   // bound memory
    m_hostnameKnown.insert(ip, hostname);
    m_pendingHostnames.insert(ip, hostname);
    scheduleResultFlush();
}

// ============================================================
// SLOT: onProcessInfoReady
// ============================================================
void MainWindow::onProcessInfoReady(int pid, ProcInfo info)
{
    m_procInfoCache.insert(pid, info);      // later events of this PID use this directly
    m_pendingProcInfo.insert(pid, info);    // applied to the table in one batch
    scheduleResultFlush();
}

// Applies queued DNS and process-metadata results in one pass over the table
// and one pass over the log. Previously every result scanned all rows.
void MainWindow::scheduleResultFlush()
{
    if (m_resultFlushTimer && !m_resultFlushTimer->isActive())
        m_resultFlushTimer->start(kResultFlushMs);
}

void MainWindow::flushResultUpdates()
{
    if (!m_pendingHostnames.isEmpty()) {
        const auto host = m_pendingHostnames;
        m_pendingHostnames.clear();
        for (int r = 0; r < m_eventTable->rowCount(); ++r) {
            auto* h = m_eventTable->item(r, COL_HOSTNAME);
            if (!h) continue;
            const QString ip = h->data(Qt::UserRole).toString();
            auto it = host.constFind(ip);
            if (it != host.constEnd()) h->setText(it.value());
        }
        m_log->updateHostnames(host);
    }

    if (!m_pendingProcInfo.isEmpty()) {
        const auto infos = m_pendingProcInfo;
        m_pendingProcInfo.clear();
        for (int r = 0; r < m_eventTable->rowCount(); ++r) {
            auto* pidCell = m_eventTable->item(r, COL_PID);
            if (!pidCell) continue;
            auto it = infos.constFind(pidCell->data(Qt::UserRole).toInt());
            if (it == infos.constEnd()) continue;
            const ProcInfo& info = it.value();
            auto set = [&](int col, const QString& text) {
                if (auto* cell = m_eventTable->item(r, col)) cell->setText(text);
            };
            set(COL_PUBLISHER, info.publisher);
            set(COL_CMDLINE,   info.cmdLine);
            set(COL_PATH,      resolveDevicePath(info.path));
            set(COL_VERSION,   info.version);
            set(COL_SERVICE,   info.service);
            set(COL_USER,      info.user);
            if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
                const int pid = pidCell->data(Qt::UserRole).toInt();
                // Only this PID's rows with the same exact path get the icon
                // (path comes from info.path for this PID).
                applyProcessIconToRow(r, pid, info.path);
            }
            // Signature needs its badge colour and bold applied, so the cell is
            // rebuilt rather than only re-texted.
            if (auto* old = m_eventTable->item(r, COL_SIGNATURE)) {
                const QColor fallbackBg = old->background().color();
                m_eventTable->setItem(r, COL_SIGNATURE,
                                      signatureBadgeCell(info.signatureStatus, fallbackBg));
            }
        }
        for (auto it = infos.constBegin(); it != infos.constEnd(); ++it) {
            const ProcInfo& info = it.value();
            m_log->updateProcessInfo(it.key(), resolveDevicePath(info.path), info.publisher,
                                     info.signatureStatus, info.version, info.service,
                                     info.cmdLine, info.user);
            // Keep Group-by process tree User column in sync when info arrives late.
            if (auto nodeIt = m_processTreeNodes.constFind(it.key());
                nodeIt != m_processTreeNodes.constEnd() && nodeIt.value()) {
                QTreeWidgetItem* node = nodeIt.value();
                auto setIfEmpty = [&](int col, const QString& v) {
                    if (!v.isEmpty() && node->text(col).isEmpty())
                        node->setText(col, v);
                };
                setIfEmpty(4, info.publisher);
                setIfEmpty(5, info.signatureStatus);
                setIfEmpty(6, resolveDevicePath(info.path));
                setIfEmpty(7, info.cmdLine);
                setIfEmpty(8, info.version);
                setIfEmpty(9, info.service);
                setIfEmpty(10, info.user);
                if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
                    const QIcon ic = iconForProcessPath(resolveDevicePath(info.path));
                    if (!ic.isNull())
                        node->setIcon(0, ic);
                }
            }
        }
    }
}

// ============================================================
// SLOT: onTableDoubleClicked — detail dialog
// ============================================================
void MainWindow::onTableDoubleClicked(int row, int)
{
    if (row < 0 || row >= m_eventTable->rowCount()) return;

    auto txt = [&](int col) {
        auto* it = m_eventTable->item(row, col);
        return it ? it->text() : QString();
    };

    ActivityEvent::Type evType = ActivityEvent::typeFromString(txt(COL_TYPE));
    QString bg = ActivityEvent::typeToColor(evType);

    auto addRow = [](const QString& label, const QString& val) -> QString {
        if (val.isEmpty() || val == "?" || val == "resolving…") return {};
        return QString("<b>%1:</b> %2<br>").arg(label, val.toHtmlEscaped());
    };

    // Resolve device path in details for display
    QString detailsDisplay = resolveDevicePath(txt(COL_DETAILS));

    QString html;
    html += addRow("Time",        txt(COL_TIME));
    html += addRow("Type",        txt(COL_TYPE));
    html += addRow("PID",         txt(COL_PID));
    html += addRow("Process",     txt(COL_PROCESS));
    html += addRow("Parent",      txt(COL_PARENT));
    html += addRow("User",        txt(COL_USER));
    html += addRow("Details",     detailsDisplay);
    html += addRow("Hostname",    txt(COL_HOSTNAME));
    html += addRow("Publisher",   txt(COL_PUBLISHER));
    html += addRow("Signature",   txt(COL_SIGNATURE));
    html += addRow("Version",     txt(COL_VERSION));
    html += addRow("Service",     txt(COL_SERVICE));
    if (!txt(COL_PATH).isEmpty())
        html += addRow("Path",    txt(COL_PATH));
    if (!txt(COL_CMDLINE).isEmpty())
        html += QString("<br><b>Command Line:</b><br>"
                        "<tt style='font-size:11px;'>%1</tt>")
                    .arg(txt(COL_CMDLINE).toHtmlEscaped());

    // Top-level (no parent) so it appears as its own taskbar window.
    auto* dlg = new QDialog(nullptr, Qt::Window);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setAttribute(Qt::WA_QuitOnClose, false);
    dlg->setStyleSheet(appButtonStyleSheet());
    dlg->setWindowTitle(QStringLiteral("Event Details"));
    dlg->setMinimumWidth(560);

    auto* lay = new QVBoxLayout(dlg);
    auto* lbl = new QLabel(html, dlg);
    lbl->setWordWrap(true);
    lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lbl->setStyleSheet(
        QString("background:%1;padding:14px;border-radius:6px;").arg(bg));
    lay->addWidget(lbl);

    auto* btns = new QDialogButtonBox(QDialogButtonBox::Ok, dlg);
    if (auto* ok = btns->button(QDialogButtonBox::Ok)) {
        ok->setAutoDefault(false);
        ok->setDefault(false);
    }
    connect(btns, &QDialogButtonBox::accepted, dlg, &QDialog::close);
    lay->addWidget(btns);
    dlg->show();
    dlg->raise();
    dlg->activateWindow();
}

// ============================================================
// Statistics window — per-process counts, top talkers, by type
// ============================================================
// "By process"  = one row per running instance (name + PID).
// "By process name" = same executable name rolled up across all PIDs
//   (e.g. ten short-lived chrome.exe helpers become one line).
// ============================================================
void MainWindow::showStatisticsWindow()
{
    if (m_statisticsWindow) {
        m_statisticsWindow->raise();
        m_statisticsWindow->activateWindow();
        return;
    }

    // nullptr parent → separate taskbar button (see showProcessDetailWindow).
    auto* win = new QDialog(nullptr, Qt::Window);
    win->setAttribute(Qt::WA_DeleteOnClose);
    win->setAttribute(Qt::WA_QuitOnClose, false);
    win->setStyleSheet(appButtonStyleSheet());
    win->setWindowTitle(QStringLiteral("Event Statistics"));
    win->resize(860, 600);
    m_statisticsWindow = win;
    connect(win, &QObject::destroyed, this, [this]() { m_statisticsWindow = nullptr; });

    auto* root = new QVBoxLayout(win);

    auto* summary = new QLabel(win);
    summary->setWordWrap(true);
    summary->setStyleSheet(QStringLiteral("font-weight:bold; padding:4px; font-size:11pt;"));
    root->addWidget(summary);

    // ---- Process name filter ----
    auto* filterRow = new QHBoxLayout();
    filterRow->addWidget(new QLabel(QStringLiteral("Filter process:"), win));
    auto* filterEdit = new QLineEdit(win);
    filterEdit->setPlaceholderText(QStringLiteral("Type part of a process name (e.g. chrome, svchost)…"));
    filterEdit->setClearButtonEnabled(true);
    filterEdit->setToolTip(QStringLiteral(
        "Shows only processes whose name contains this text (case-insensitive).\n"
        "Applies to every tab. Clear the box to show all."));
    filterRow->addWidget(filterEdit, 1);
    root->addLayout(filterRow);

    auto* tabs = new QTabWidget(win);
    root->addWidget(tabs, 1);

    // ============================================================
    // Tab 1: Processes (tree) — expand a process to see ops by type
    // ============================================================
    auto* procPage = new QWidget(tabs);
    auto* procLay = new QVBoxLayout(procPage);
    auto* procHint = new QLabel(
        QStringLiteral(
            "<b>By process</b> = one row per process instance (name + PID).<br>"
            "Expand a row to see how many of each operation that process produced "
            "(File Read, DNS Query, Net Connect, …). "
            "Double-click a process row to open its event list."),
        procPage);
    procHint->setWordWrap(true);
    procHint->setStyleSheet(QStringLiteral("color:#444; padding:2px;"));
    procLay->addWidget(procHint);

    auto* procTree = new QTreeWidget(procPage);
    procTree->setColumnCount(4);
    procTree->setHeaderLabels(
        {QStringLiteral("Process / Operation"), QStringLiteral("Count"),
         QStringLiteral("%"), QStringLiteral("User")});
    procTree->setColumnWidth(0, 340);
    procTree->setColumnWidth(1, 80);
    procTree->setColumnWidth(2, 70);
    procTree->setAlternatingRowColors(true);
    procTree->setUniformRowHeights(true);
    procTree->setRootIsDecorated(true);
    procTree->setSortingEnabled(true);
    procTree->sortByColumn(1, Qt::DescendingOrder);
    procTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    procLay->addWidget(procTree, 1);
    tabs->addTab(procPage, QStringLiteral("By process"));

    // ============================================================
    // Tab 2: By process name (aggregated)
    // ============================================================
    auto* namePage = new QWidget(tabs);
    auto* nameLay = new QVBoxLayout(namePage);
    auto* nameHint = new QLabel(
        QStringLiteral(
            "<b>By process name</b> = same executable name across all PIDs combined.<br>"
            "Example: five short-lived <tt>conhost.exe</tt> instances become one line with "
            "total events and distinct PID count. Expand for operation breakdown."),
        namePage);
    nameHint->setWordWrap(true);
    nameHint->setStyleSheet(QStringLiteral("color:#444; padding:2px;"));
    nameLay->addWidget(nameHint);

    auto* nameTree = new QTreeWidget(namePage);
    nameTree->setColumnCount(4);
    nameTree->setHeaderLabels(
        {QStringLiteral("Process name / Operation"), QStringLiteral("Count"),
         QStringLiteral("%"), QStringLiteral("Distinct PIDs")});
    nameTree->setColumnWidth(0, 340);
    nameTree->setColumnWidth(1, 80);
    nameTree->setColumnWidth(2, 70);
    nameTree->setAlternatingRowColors(true);
    nameTree->setUniformRowHeights(true);
    nameTree->setRootIsDecorated(true);
    nameTree->setSortingEnabled(true);
    nameTree->sortByColumn(1, Qt::DescendingOrder);
    nameLay->addWidget(nameTree, 1);
    tabs->addTab(namePage, QStringLiteral("By process name"));

    // ============================================================
    // Tab 3: By event type (global)
    // ============================================================
    auto* typePage = new QWidget(tabs);
    auto* typeLay = new QVBoxLayout(typePage);
    auto* typeHint = new QLabel(
        QStringLiteral("Totals for each event type across the whole log (respects the process filter above)."),
        typePage);
    typeHint->setStyleSheet(QStringLiteral("color:#555;"));
    typeLay->addWidget(typeHint);
    auto* typeTable = new QTableWidget(typePage);
    typeTable->setColumnCount(3);
    typeTable->setHorizontalHeaderLabels(
        {QStringLiteral("Event type"), QStringLiteral("Count"), QStringLiteral("%")});
    typeTable->horizontalHeader()->setStretchLastSection(true);
    typeTable->setColumnWidth(0, 240);
    typeTable->setColumnWidth(1, 90);
    typeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    typeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    typeTable->setSortingEnabled(true);
    typeTable->setAlternatingRowColors(true);
    typeLay->addWidget(typeTable, 1);
    tabs->addTab(typePage, QStringLiteral("By event type"));

    // ============================================================
    // Tab 4: Top 25
    // ============================================================
    auto* topPage = new QWidget(tabs);
    auto* topLay = new QVBoxLayout(topPage);
    auto* topHint = new QLabel(
        QStringLiteral("Top 25 process instances by event count. Double-click to open that process’s events."),
        topPage);
    topHint->setStyleSheet(QStringLiteral("color:#555;"));
    topLay->addWidget(topHint);
    auto* topList = new QListWidget(topPage);
    topList->setAlternatingRowColors(true);
    topLay->addWidget(topList, 1);
    tabs->addTab(topPage, QStringLiteral("Top 25"));

    // Double-click or Enter → process detail window
    auto openProc = [this](int pid, const QString& name) {
        if (pid > 0) showProcessDetailWindow(pid, name);
    };
    auto openProcFromTreeItem = [openProc](QTreeWidgetItem* item) {
        if (!item) return;
        // Prefer parent process row when activating a child type row
        QTreeWidgetItem* node = item->parent() ? item->parent() : item;
        const int pid = node->data(0, Qt::UserRole).toInt();
        const QString name = node->data(0, Qt::UserRole + 1).toString();
        openProc(pid, name);
    };
    connect(procTree, &QTreeWidget::itemDoubleClicked, win,
            [openProcFromTreeItem](QTreeWidgetItem* item, int) { openProcFromTreeItem(item); });
    // Enter / keypad Enter activates the current item (same as double-click)
    connect(procTree, &QTreeWidget::itemActivated, win,
            [openProcFromTreeItem](QTreeWidgetItem* item, int) { openProcFromTreeItem(item); });
    connect(topList, &QListWidget::itemDoubleClicked, win, [openProc](QListWidgetItem* item) {
        if (!item) return;
        openProc(item->data(Qt::UserRole).toInt(),
                 item->data(Qt::UserRole + 1).toString());
    });
    connect(topList, &QListWidget::itemActivated, win, [openProc](QListWidgetItem* item) {
        if (!item) return;
        openProc(item->data(Qt::UserRole).toInt(),
                 item->data(Qt::UserRole + 1).toString());
    });

    // Open a static snapshot of all events of the clicked type (no live update).
    auto openEventsByType = [this](const QString& typeName) {
        if (typeName.isEmpty()) return;

        auto* dlg = new QDialog(nullptr, Qt::Window);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->setAttribute(Qt::WA_QuitOnClose, false);
        dlg->setStyleSheet(appButtonStyleSheet());
        dlg->setWindowTitle(QStringLiteral("Events — %1 (snapshot)").arg(typeName));
        dlg->resize(960, 560);

        auto* lay = new QVBoxLayout(dlg);
        auto* note = new QLabel(
            QStringLiteral("Snapshot of <b>%1</b> events at open time. "
                           "Close and reopen to load newer events.")
                .arg(typeName.toHtmlEscaped()),
            dlg);
        note->setTextFormat(Qt::RichText);
        note->setWordWrap(true);
        lay->addWidget(note);

        auto* filterRow = new QHBoxLayout();
        filterRow->addWidget(new QLabel(QStringLiteral("Search:"), dlg));
        auto* searchEdit = new QLineEdit(dlg);
        searchEdit->setPlaceholderText(
            QStringLiteral("Filter this list (process, PID, details, user, path…)"));
        searchEdit->setClearButtonEnabled(true);
        filterRow->addWidget(searchEdit, 1);
        auto* matchLabel = new QLabel(dlg);
        matchLabel->setStyleSheet(QStringLiteral("color:#1565c0; min-width:80px;"));
        filterRow->addWidget(matchLabel);
        lay->addLayout(filterRow);

        auto* table = new QTableWidget(dlg);
        table->setColumnCount(7);
        table->setHorizontalHeaderLabels({
            QStringLiteral("Time"), QStringLiteral("PID"), QStringLiteral("Process"),
            QStringLiteral("Details"), QStringLiteral("User"),
            QStringLiteral("Path"), QStringLiteral("Status")
        });
        table->horizontalHeader()->setStretchLastSection(true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->setWordWrap(false);
        table->setTextElideMode(Qt::ElideRight);
        table->setColumnWidth(0, 110);
        table->setColumnWidth(1, 55);
        table->setColumnWidth(2, 120);
        table->setColumnWidth(3, 280);
        table->setColumnWidth(4, 120);
        table->setColumnWidth(5, 180);
        installOverflowTooltips(table);
        lay->addWidget(table, 1);

        // Build snapshot once — do not refresh from live log
        table->setSortingEnabled(false);
        table->setUpdatesEnabled(false);
        const auto& events = m_log->getAllEvents();
        int n = 0;
        for (const ActivityEvent& ev : events) {
            if (ActivityEvent::typeToString(ev.type) != typeName)
                continue;
            const int r = table->rowCount();
            table->insertRow(r);
            table->setItem(r, 0, new QTableWidgetItem(
                ev.timestamp.toString(QStringLiteral("HH:mm:ss.zzz"))));
            auto* pidItem = new QTableWidgetItem;
            pidItem->setData(Qt::DisplayRole, ev.pid);
            pidItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            table->setItem(r, 1, pidItem);
            table->setItem(r, 2, new QTableWidgetItem(ev.processName));
            table->setItem(r, 3, new QTableWidgetItem(ev.details));
            table->setItem(r, 4, new QTableWidgetItem(ev.userName));
            table->setItem(r, 5, new QTableWidgetItem(ev.fullPath));
            table->setItem(r, 6, new QTableWidgetItem(ev.operationStatus));
            ++n;
        }
        table->setUpdatesEnabled(true);
        table->setSortingEnabled(true);
        matchLabel->setText(QStringLiteral("%1 events").arg(n));

        // Client-side filter (snapshot only)
        auto applySearch = [table, searchEdit, matchLabel, n]() {
            const QString q = searchEdit->text().trimmed();
            int visible = 0;
            for (int r = 0; r < table->rowCount(); ++r) {
                bool show = q.isEmpty();
                if (!show) {
                    for (int c = 0; c < table->columnCount(); ++c) {
                        auto* it = table->item(r, c);
                        if (it && it->text().contains(q, Qt::CaseInsensitive)) {
                            show = true;
                            break;
                        }
                    }
                }
                table->setRowHidden(r, !show);
                if (show) ++visible;
            }
            matchLabel->setText(q.isEmpty()
                ? QStringLiteral("%1 events").arg(n)
                : QStringLiteral("%1 / %2").arg(visible).arg(n));
        };
        QObject::connect(searchEdit, &QLineEdit::textChanged, dlg, [applySearch](const QString&) {
            applySearch();
        });

        auto* btnRow = new QHBoxLayout();
        auto* closeBtn = new QPushButton(QStringLiteral("Close"), dlg);
        closeBtn->setAutoDefault(false);
        closeBtn->setDefault(false);
        btnRow->addStretch();
        btnRow->addWidget(closeBtn);
        lay->addLayout(btnRow);
        QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::close);

        dlg->show();
        dlg->raise();
        dlg->activateWindow();
    };

    auto openTypeFromTable = [openEventsByType](QTableWidget* table, int row) {
        if (row < 0 || !table) return;
        auto* it = table->item(row, 0);
        if (!it) return;
        QString typeName = it->data(Qt::UserRole).toString();
        if (typeName.isEmpty())
            typeName = it->text();
        openEventsByType(typeName);
    };
    // Only cellDoubleClicked — itemActivated also fires on double-click and
    // was opening the same window twice.
    typeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(typeTable, &QTableWidget::cellDoubleClicked, win,
            [typeTable, openTypeFromTable](int row, int) {
        openTypeFromTable(typeTable, row);
    });

    auto* btnRow = new QHBoxLayout();
    auto* refreshBtn = new QPushButton(QStringLiteral("Refresh"), win);
    auto* expandBtn = new QPushButton(QStringLiteral("Expand all"), win);
    auto* collapseBtn = new QPushButton(QStringLiteral("Collapse all"), win);
    auto* autoUpdateCb = new QCheckBox(QStringLiteral("Auto-update"), win);
    autoUpdateCb->setChecked(true);
    autoUpdateCb->setToolTip(QStringLiteral(
        "When checked, statistics refresh every 3 seconds.\n"
        "Uncheck to freeze the view while you inspect rows; use Refresh to update manually."));
    auto* closeBtn = new QPushButton(QStringLiteral("Close"), win);
    // QDialog makes QPushButtons autoDefault: Enter would click Refresh and
    // rebuild the tree. Turn that off so Enter opens the selected process instead.
    for (QPushButton* b : {refreshBtn, expandBtn, collapseBtn, closeBtn}) {
        b->setAutoDefault(false);
        b->setDefault(false);
    }
    btnRow->addWidget(refreshBtn);
    btnRow->addWidget(expandBtn);
    btnRow->addWidget(collapseBtn);
    btnRow->addWidget(autoUpdateCb);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);
    connect(closeBtn, &QPushButton::clicked, win, &QDialog::close);
    connect(expandBtn, &QPushButton::clicked, win, [procTree, nameTree]() {
        procTree->expandAll();
        nameTree->expandAll();
    });
    connect(collapseBtn, &QPushButton::clicked, win, [procTree, nameTree]() {
        procTree->collapseAll();
        nameTree->collapseAll();
    });

    auto numText = [](int n) { return QString::number(n); };
    auto pctText = [](double p) { return QString::number(p, 'f', 1) + QLatin1Char('%'); };

    // Shared filter text (updated by the line edit; refresh reads it)
    auto filterText = std::make_shared<QString>();

    auto refresh = [this, summary, procTree, nameTree, typeTable, topList,
                    filterText, numText, pctText]() {
        const QString filter = filterText->trimmed();
        const auto& events = m_log->getAllEvents();

        // key = "pid\x1fname"  -> total count and per-type counts
        QHash<QString, int> byPidTotal;
        QHash<QString, QHash<QString, int>> byPidType; // pk -> (typeName -> count)
        QHash<QString, QString> pidToName;
        QHash<QString, QString> pidToUser;
        QHash<int, QString> pidToPath;   // first known exe path per PID (for icons)

        QHash<QString, int> byNameTotal;
        QHash<QString, QHash<QString, int>> byNameType;
        QHash<QString, QSet<int>> nameToPids;

        QHash<QString, int> byType;

        int matchedEvents = 0;
        for (const ActivityEvent& ev : events) {
            const QString pname = ev.processName.isEmpty()
                                      ? QStringLiteral("(unknown)")
                                      : ev.processName;
            if (!filter.isEmpty() &&
                !pname.contains(filter, Qt::CaseInsensitive))
                continue;

            ++matchedEvents;
            const QString typeName = ActivityEvent::typeToString(ev.type);
            const QString pk = QString::number(ev.pid) + QLatin1Char('\x1f') + pname;

            byPidTotal[pk] += 1;
            byPidType[pk][typeName] += 1;
            pidToName.insert(pk, pname);
            if (!ev.userName.isEmpty() && !ev.userName.startsWith(QLatin1Char('(')))
                pidToUser.insert(pk, ev.userName);
            if (!ev.fullPath.isEmpty() && !pidToPath.contains(ev.pid))
                pidToPath.insert(ev.pid, resolveDevicePath(ev.fullPath));

            byNameTotal[pname] += 1;
            byNameType[pname][typeName] += 1;
            nameToPids[pname].insert(ev.pid);

            byType[typeName] += 1;
        }

        const int totalAll = events.size();
        const int total = matchedEvents > 0 ? matchedEvents : 0;

        QString firstTs, lastTs;
        if (!events.isEmpty()) {
            firstTs = events.first().timestamp.toString(QStringLiteral("HH:mm:ss"));
            lastTs  = events.last().timestamp.toString(QStringLiteral("HH:mm:ss"));
        }
        if (totalAll == 0) {
            summary->setText(QStringLiteral(
                "No events in the log yet. Start monitoring or load a saved log."));
        } else if (!filter.isEmpty()) {
            summary->setText(
                QStringLiteral("%1 / %2 events match filter \"%3\"  ·  %4 process instances  ·  %5 names  ·  span %6 – %7")
                    .arg(total).arg(totalAll).arg(filter)
                    .arg(byPidTotal.size()).arg(byNameTotal.size())
                    .arg(firstTs).arg(lastTs));
        } else {
            summary->setText(
                QStringLiteral("%1 events  ·  %2 process instances  ·  %3 process names  ·  span %4 – %5")
                    .arg(total).arg(byPidTotal.size()).arg(byNameTotal.size())
                    .arg(firstTs).arg(lastTs));
        }

        auto sortedKeys = [](const QHash<QString, int>& counts) {
            QList<QPair<QString, int>> rows;
            rows.reserve(counts.size());
            for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
                rows.append({it.key(), it.value()});
            std::sort(rows.begin(), rows.end(),
                      [](const QPair<QString, int>& a, const QPair<QString, int>& b) {
                          return a.second > b.second;
                      });
            return rows;
        };

        const bool showIcons = m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked();
        auto iconForPid = [&](int pid) -> QIcon {
            if (!showIcons || pid <= 0) return {};
            QString path = pidToPath.value(pid);
            if (path.isEmpty()) {
                auto cit = m_procInfoCache.constFind(pid);
                if (cit != m_procInfoCache.constEnd())
                    path = resolveDevicePath(cit->path);
            }
            return iconForProcessPath(path);
        };
        auto iconForName = [&](const QString& pname) -> QIcon {
            if (!showIcons) return {};
            // Prefer a PID under this name that has a known full path
            const auto pids = nameToPids.value(pname);
            for (int pid : pids) {
                const QIcon ic = iconForPid(pid);
                if (!ic.isNull()) return ic;
            }
            return {};
        };

        // ---- Process tree (instance) ----
        {
            const bool wasSorting = procTree->isSortingEnabled();
            procTree->setSortingEnabled(false);
            procTree->setUpdatesEnabled(false);
            // Remember expanded PIDs
            QSet<int> expandedPids;
            for (int i = 0; i < procTree->topLevelItemCount(); ++i) {
                auto* it = procTree->topLevelItem(i);
                if (it && it->isExpanded())
                    expandedPids.insert(it->data(0, Qt::UserRole).toInt());
            }
            procTree->clear();

            for (const auto& pair : sortedKeys(byPidTotal)) {
                const QString& pk = pair.first;
                const int count = pair.second;
                const int sep = pk.indexOf(QLatin1Char('\x1f'));
                const int pid = pk.left(sep).toInt();
                const QString name = pidToName.value(pk);
                const QString user = pidToUser.value(pk);
                const double pct = total > 0 ? (100.0 * count / total) : 0.0;

                auto* parent = new QTreeWidgetItem();
                parent->setText(0, QStringLiteral("%1  (PID %2)").arg(name).arg(pid));
                parent->setText(1, numText(count));
                parent->setData(1, Qt::UserRole, count);
                parent->setText(2, pctText(pct));
                parent->setText(3, user);
                parent->setData(0, Qt::UserRole, pid);
                parent->setData(0, Qt::UserRole + 1, name);
                QFont bf = parent->font(0);
                bf.setBold(true);
                parent->setFont(0, bf);
                {
                    const QIcon ic = iconForPid(pid);
                    if (!ic.isNull())
                        parent->setIcon(0, ic);
                }

                // Children = operation types for this process
                const auto& typeMap = byPidType.value(pk);
                QList<QPair<QString, int>> typeRows = sortedKeys(typeMap);
                for (const auto& tr : typeRows) {
                    auto* child = new QTreeWidgetItem(parent);
                    child->setText(0, tr.first);
                    child->setText(1, numText(tr.second));
                    child->setData(1, Qt::UserRole, tr.second);
                    const double tp = count > 0 ? (100.0 * tr.second / count) : 0.0;
                    child->setText(2, pctText(tp));
                    const auto t = ActivityEvent::typeFromString(tr.first);
                    child->setBackground(0, QBrush(QColor(ActivityEvent::typeToColor(t))));
                }

                procTree->addTopLevelItem(parent);
                if (expandedPids.contains(pid))
                    parent->setExpanded(true);
            }
            procTree->setUpdatesEnabled(true);
            procTree->setSortingEnabled(wasSorting);
            if (wasSorting)
                procTree->sortByColumn(1, Qt::DescendingOrder);
        }

        // ---- Name tree (aggregated) ----
        {
            const bool wasSorting = nameTree->isSortingEnabled();
            nameTree->setSortingEnabled(false);
            nameTree->setUpdatesEnabled(false);
            QSet<QString> expandedNames;
            for (int i = 0; i < nameTree->topLevelItemCount(); ++i) {
                auto* it = nameTree->topLevelItem(i);
                if (it && it->isExpanded())
                    expandedNames.insert(it->text(0));
            }
            nameTree->clear();

            for (const auto& pair : sortedKeys(byNameTotal)) {
                const QString& pname = pair.first;
                const int count = pair.second;
                const double pct = total > 0 ? (100.0 * count / total) : 0.0;
                const int nPids = nameToPids.value(pname).size();

                auto* parent = new QTreeWidgetItem();
                parent->setText(0, pname);
                parent->setText(1, numText(count));
                parent->setData(1, Qt::UserRole, count);
                parent->setText(2, pctText(pct));
                parent->setText(3, numText(nPids));
                QFont bf = parent->font(0);
                bf.setBold(true);
                parent->setFont(0, bf);
                {
                    const QIcon ic = iconForName(pname);
                    if (!ic.isNull())
                        parent->setIcon(0, ic);
                }

                const auto& typeMap = byNameType.value(pname);
                for (const auto& tr : sortedKeys(typeMap)) {
                    auto* child = new QTreeWidgetItem(parent);
                    child->setText(0, tr.first);
                    child->setText(1, numText(tr.second));
                    child->setData(1, Qt::UserRole, tr.second);
                    const double tp = count > 0 ? (100.0 * tr.second / count) : 0.0;
                    child->setText(2, pctText(tp));
                    const auto t = ActivityEvent::typeFromString(tr.first);
                    child->setBackground(0, QBrush(QColor(ActivityEvent::typeToColor(t))));
                }

                nameTree->addTopLevelItem(parent);
                if (expandedNames.contains(pname))
                    parent->setExpanded(true);
            }
            nameTree->setUpdatesEnabled(true);
            nameTree->setSortingEnabled(wasSorting);
            if (wasSorting)
                nameTree->sortByColumn(1, Qt::DescendingOrder);
        }

        // ---- Type table ----
        {
            typeTable->setSortingEnabled(false);
            typeTable->setUpdatesEnabled(false);
            typeTable->setRowCount(0);
            int r = 0;
            for (const auto& pair : sortedKeys(byType)) {
                const double pct = total > 0 ? (100.0 * pair.second / total) : 0.0;
                typeTable->insertRow(r);
                auto* typeItem = new QTableWidgetItem(pair.first);
                const auto ty = ActivityEvent::typeFromString(pair.first);
                typeItem->setBackground(QBrush(QColor(ActivityEvent::typeToColor(ty))));
                typeItem->setData(Qt::UserRole, pair.first);
                typeTable->setItem(r, 0, typeItem);
                auto* cItem = new QTableWidgetItem;
                cItem->setData(Qt::DisplayRole, pair.second);
                cItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                typeTable->setItem(r, 1, cItem);
                auto* pItem = new QTableWidgetItem(pctText(pct));
                pItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                typeTable->setItem(r, 2, pItem);
                ++r;
            }
            typeTable->setUpdatesEnabled(true);
            typeTable->setSortingEnabled(true);
            typeTable->sortItems(1, Qt::DescendingOrder);
        }

        // ---- Top 25 ----
        {
            topList->setUpdatesEnabled(false);
            topList->clear();
            const auto rows = sortedKeys(byPidTotal);
            const int limit = qMin(25, rows.size());
            for (int i = 0; i < limit; ++i) {
                const QString& pk = rows[i].first;
                const int count = rows[i].second;
                const int sep = pk.indexOf(QLatin1Char('\x1f'));
                const int pid = pk.left(sep).toInt();
                const QString name = pidToName.value(pk);
                const double pct = total > 0 ? (100.0 * count / total) : 0.0;
                // Build a short type summary for the top line
                QStringList parts;
                for (const auto& tr : sortedKeys(byPidType.value(pk))) {
                    parts << QStringLiteral("%1× %2").arg(tr.second).arg(tr.first);
                    if (parts.size() >= 4) break;
                }
                auto* item = new QListWidgetItem(
                    QStringLiteral("%1.  %2  (PID %3)  —  %4 events (%5%)\n    %6")
                        .arg(i + 1).arg(name).arg(pid).arg(count)
                        .arg(pct, 0, 'f', 1)
                        .arg(parts.join(QStringLiteral(" · "))));
                item->setData(Qt::UserRole, pid);
                item->setData(Qt::UserRole + 1, name);
                {
                    const QIcon ic = iconForPid(pid);
                    if (!ic.isNull())
                        item->setIcon(ic);
                }
                topList->addItem(item);
            }
            topList->setUpdatesEnabled(true);
        }
    };

    connect(refreshBtn, &QPushButton::clicked, win, refresh);
    connect(filterEdit, &QLineEdit::textChanged, win, [filterText, refresh](const QString& t) {
        *filterText = t;
        refresh();
    });
    auto* timer = new QTimer(win);
    connect(timer, &QTimer::timeout, win, refresh);
    timer->start(3000);
    connect(autoUpdateCb, &QCheckBox::toggled, win, [timer](bool on) {
        if (on)
            timer->start(3000);
        else
            timer->stop();
    });
    refresh();

    win->show();
}


// ============================================================
// Network behavior window (download / upload / streaming)
// ============================================================
void MainWindow::showBehaviorWindow()
{
    if (m_behaviorWindow) {
        m_behaviorWindow->raise();
        m_behaviorWindow->activateWindow();
        return;
    }
    if (!m_behaviorMonitor)
        m_behaviorMonitor = new NetworkBehaviorMonitor(this);
    if (!m_behaviorMonitor->isRunning())
        m_behaviorMonitor->start();
    enrichBehaviorHostnames(true);   // one full DNS harvest when opening Network

    auto* win = new QDialog(nullptr, Qt::Window);
    win->setAttribute(Qt::WA_DeleteOnClose);
    win->setAttribute(Qt::WA_QuitOnClose, false);
    win->setStyleSheet(appButtonStyleSheet());
    win->setWindowTitle(QStringLiteral("Network — TCP/UDP · Download / Upload / Streaming"));
    win->resize(1000, 620);
    m_behaviorWindow = win;
    connect(win, &QObject::destroyed, this, [this]() { m_behaviorWindow = nullptr; });

    auto* root = new QVBoxLayout(win);
    auto* note = new QLabel(
        QStringLiteral(
            "<b>TCP</b>: byte counters when Windows allows "
            "(GetPerTcpConnectionEStats, mainly IPv4). "
            "IPv6 TCP is listed even without bytes. "
            "<b>UDP</b>: local endpoints only (no remote/bytes — includes QUIC). "
            "YouTube often uses <b>UDP/QUIC</b>, so it may show as UDP endpoints "
            "or Active TCP rather than “Streaming”.<br>"
            "Run as Administrator for better byte stats on more processes."),
        win);
    note->setWordWrap(true);
    note->setTextFormat(Qt::RichText);
    root->addWidget(note);

    // Filters
    auto* filterRow = new QHBoxLayout();
    filterRow->addWidget(new QLabel(QStringLiteral("Filter:"), win));
    auto* filterPid = new QLineEdit(win);
    filterPid->setPlaceholderText(QStringLiteral("PID"));
    filterPid->setClearButtonEnabled(true);
    filterPid->setMaximumWidth(90);
    auto* filterProc = new QLineEdit(win);
    filterProc->setPlaceholderText(QStringLiteral("Process name"));
    filterProc->setClearButtonEnabled(true);
    auto* filterRemote = new QLineEdit(win);
    filterRemote->setPlaceholderText(QStringLiteral("Remote / host / port"));
    filterRemote->setClearButtonEnabled(true);
    filterRow->addWidget(filterPid);
    filterRow->addWidget(filterProc, 1);
    filterRow->addWidget(filterRemote, 1);
    root->addLayout(filterRow);

    auto filterText = std::make_shared<QString>();
    auto filterPidText = std::make_shared<QString>();
    auto filterRemoteText = std::make_shared<QString>();

    auto* tabs = new QTabWidget(win);
    root->addWidget(tabs, 1);

    auto makeTable = [&](QWidget* parent) -> QTableWidget* {
        auto* table = new QTableWidget(parent);
        table->setColumnCount(8);
        table->setHorizontalHeaderLabels(
            {QStringLiteral("Process"), QStringLiteral("PID"),
             QStringLiteral("Proto"), QStringLiteral("Remote"),
             QStringLiteral("In"), QStringLiteral("Out"),
             QStringLiteral("Duration"), QStringLiteral("Classification")});
        table->horizontalHeader()->setStretchLastSection(true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->setIconSize(QSize(16, 16));
        table->setColumnWidth(0, 150);
        table->setColumnWidth(1, 55);
        table->setColumnWidth(2, 50);
        table->setColumnWidth(3, 220);
        table->setColumnWidth(4, 90);
        table->setColumnWidth(5, 90);
        table->setColumnWidth(6, 70);
        return table;
    };

    auto* procPage = new QWidget(win);
    auto* procLay = new QVBoxLayout(procPage);
    auto* procTable = makeTable(procPage);
    procTable->setColumnHidden(2, true); // proto less useful on aggregate
    procTable->setColumnHidden(3, true);
    procLay->addWidget(procTable);
    tabs->addTab(procPage, QStringLiteral("Per process"));

    auto* hostPage = new QWidget(win);
    auto* hostLay = new QVBoxLayout(hostPage);
    auto* hostTable = makeTable(hostPage);
    hostLay->addWidget(hostTable);
    tabs->addTab(hostPage, QStringLiteral("Per process + host"));

    // ---- Connection history (grouped by process name + PID) ----
    auto* histPage = new QWidget(win);
    auto* histLay = new QVBoxLayout(histPage);
    histLay->addWidget(new QLabel(
        QStringLiteral("TCP/UDP connections seen this session, grouped by process. "
                       "<b>Live</b> = still in the OS table; <b>Disconnected</b> = closed since last sample. "
                       "UDP rows are local binds (no remote peer in the system table)."),
        histPage));
    auto* histTree = new QTreeWidget(histPage);
    histTree->setColumnCount(10);
    histTree->setHeaderLabels({
        QStringLiteral("Process / Connection"), QStringLiteral("PID"),
        QStringLiteral("Proto"), QStringLiteral("Local"),
        QStringLiteral("Remote"), QStringLiteral("State"),
        QStringLiteral("In"), QStringLiteral("Out"),
        QStringLiteral("Duration"), QStringLiteral("Last seen")
    });
    histTree->setAlternatingRowColors(true);
    histTree->setUniformRowHeights(true);
    histTree->setSortingEnabled(true);
    histTree->setIconSize(QSize(16, 16));
    histTree->header()->setStretchLastSection(true);
    histTree->setColumnWidth(0, 200);
    histTree->setColumnWidth(1, 55);
    histTree->setColumnWidth(2, 50);
    histTree->setColumnWidth(3, 140);
    histTree->setColumnWidth(4, 200);
    histTree->setColumnWidth(5, 90);
    histTree->setColumnWidth(6, 80);
    histTree->setColumnWidth(7, 80);
    histTree->setColumnWidth(8, 70);
    histLay->addWidget(histTree, 1);
    tabs->addTab(histPage, QStringLiteral("Connection history"));

    // ---- Listening ports ----
    auto* listenPage = new QWidget(win);
    auto* listenLay = new QVBoxLayout(listenPage);
    listenLay->addWidget(new QLabel(
        QStringLiteral("TCP <b>LISTEN</b> sockets and UDP local binds, grouped by process. "
                       "State shows whether the endpoint is still present."),
        listenPage));
    auto* listenTree = new QTreeWidget(listenPage);
    listenTree->setColumnCount(6);
    listenTree->setHeaderLabels({
        QStringLiteral("Process / Port"), QStringLiteral("PID"),
        QStringLiteral("Proto"), QStringLiteral("Local address"),
        QStringLiteral("State"), QStringLiteral("Last seen")
    });
    listenTree->setAlternatingRowColors(true);
    listenTree->setUniformRowHeights(true);
    listenTree->setSortingEnabled(true);
    listenTree->setIconSize(QSize(16, 16));
    listenTree->header()->setStretchLastSection(true);
    listenTree->setColumnWidth(0, 200);
    listenTree->setColumnWidth(1, 55);
    listenTree->setColumnWidth(2, 50);
    listenTree->setColumnWidth(3, 180);
    listenTree->setColumnWidth(4, 100);
    listenLay->addWidget(listenTree, 1);
    tabs->addTab(listenPage, QStringLiteral("Listening ports"));

    // Right-click Copy menu on all Network views
    auto showNetCopyMenu = [](QWidget* anchor, const QPoint& globalPos,
                              int pid, const QString& processName,
                              const QString& remoteIP, quint16 remotePort,
                              const QString& hostname) {
        QMenu menu(anchor);
        auto addCopy = [&](const QString& label, const QString& value) {
            QAction* a = menu.addAction(label);
            a->setEnabled(!value.isEmpty());
            QObject::connect(a, &QAction::triggered, anchor, [value]() {
                QApplication::clipboard()->setText(value);
            });
        };
        addCopy(QStringLiteral("Copy process name"), processName);
        addCopy(QStringLiteral("Copy PID"),
                pid > 0 ? QString::number(pid) : QString());
        menu.addSeparator();
        addCopy(QStringLiteral("Copy remote host (IP)"), remoteIP);
        QString hostPort;
        if (!remoteIP.isEmpty()) {
            hostPort = remotePort
                ? (remoteIP + QLatin1Char(':') + QString::number(remotePort))
                : remoteIP;
        }
        addCopy(QStringLiteral("Copy host with port"), hostPort);
        addCopy(QStringLiteral("Copy hostname"), hostname);
        if (!hostname.isEmpty() && remotePort) {
            addCopy(QStringLiteral("Copy hostname with port"),
                    hostname + QLatin1Char(':') + QString::number(remotePort));
        }
        menu.exec(globalPos);
    };

    auto wireTableCopy = [showNetCopyMenu](QTableWidget* table) {
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QWidget::customContextMenuRequested, table,
                         [table, showNetCopyMenu](const QPoint& pos) {
            const int row = table->rowAt(pos.y());
            if (row < 0) return;
            auto* nameItem = table->item(row, 0);
            if (!nameItem) return;
            const int pid = nameItem->data(Qt::UserRole).toInt();
            const QString processName = nameItem->data(Qt::UserRole + 1).toString();
            const QString remoteIP = nameItem->data(Qt::UserRole + 2).toString();
            const quint16 remotePort = quint16(nameItem->data(Qt::UserRole + 3).toUInt());
            const QString hostname = nameItem->data(Qt::UserRole + 4).toString();
            showNetCopyMenu(table, table->viewport()->mapToGlobal(pos),
                            pid, processName, remoteIP, remotePort, hostname);
        });
    };
    wireTableCopy(procTable);
    wireTableCopy(hostTable);

    auto wireTreeCopy = [showNetCopyMenu](QTreeWidget* tree) {
        tree->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tree, &QWidget::customContextMenuRequested, tree,
                         [tree, showNetCopyMenu](const QPoint& pos) {
            QTreeWidgetItem* item = tree->itemAt(pos);
            if (!item) return;
            // Prefer leaf data; parent nodes only have pid + process name
            const int pid = item->data(0, Qt::UserRole).toInt();
            const QString processName = item->data(0, Qt::UserRole + 1).toString().isEmpty()
                ? item->text(0) : item->data(0, Qt::UserRole + 1).toString();
            const QString remoteIP = item->data(0, Qt::UserRole + 2).toString();
            const quint16 remotePort = quint16(item->data(0, Qt::UserRole + 3).toUInt());
            const QString hostname = item->data(0, Qt::UserRole + 4).toString();
            showNetCopyMenu(tree, tree->viewport()->mapToGlobal(pos),
                            pid, processName, remoteIP, remotePort, hostname);
        });
    };
    wireTreeCopy(histTree);
    wireTreeCopy(listenTree);

    auto* btnRow = new QHBoxLayout();
    auto* refreshBtn = new QPushButton(QStringLiteral("Refresh"), win);
    auto* clearBtn = new QPushButton(QStringLiteral("Clear"), win);
    clearBtn->setToolTip(QStringLiteral("Clear accumulated network samples (starts fresh)."));
    auto* expandBtn = new QPushButton(QStringLiteral("Expand all"), win);
    expandBtn->setToolTip(QStringLiteral("Expand all process groups in Connection history and Listening ports."));
    auto* collapseBtn = new QPushButton(QStringLiteral("Collapse all"), win);
    collapseBtn->setToolTip(QStringLiteral("Collapse all process groups in Connection history and Listening ports."));
    auto* autoCb = new QCheckBox(QStringLiteral("Auto-update"), win);
    autoCb->setChecked(true);
    autoCb->setToolTip(QStringLiteral(
        "When off, tables stay frozen until you press Refresh\n"
        "(background sampling still runs so data is ready when you refresh)."));
    auto* closeBtn = new QPushButton(QStringLiteral("Close"), win);
    for (QPushButton* b : {refreshBtn, clearBtn, expandBtn, collapseBtn, closeBtn}) {
        b->setAutoDefault(false);
        b->setDefault(false);
    }
    btnRow->addWidget(refreshBtn);
    btnRow->addWidget(clearBtn);
    btnRow->addWidget(expandBtn);
    btnRow->addWidget(collapseBtn);
    btnRow->addWidget(autoCb);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);

    auto* totalsLabel = new QLabel(win);
    totalsLabel->setTextFormat(Qt::RichText);
    totalsLabel->setStyleSheet(QStringLiteral(
        "QLabel { background:#f5f5f5; border-top:1px solid #ccc; padding:6px 8px; "
        "font-weight:bold; color:#333; }"));
    totalsLabel->setText(QStringLiteral("Total traffic: —"));
    totalsLabel->setToolTip(QStringLiteral(
        "Sum of In + Out byte counters accumulated since Network sampling started "
        "(or last Clear). Only TCP connections where Windows exposes EStats bytes "
        "are included; UDP has no byte stats."));
    root->addWidget(totalsLabel);

    connect(closeBtn, &QPushButton::clicked, win, &QDialog::close);
    connect(expandBtn, &QPushButton::clicked, win, [histTree, listenTree]() {
        histTree->expandAll();
        listenTree->expandAll();
    });
    connect(collapseBtn, &QPushButton::clicked, win, [histTree, listenTree]() {
        histTree->collapseAll();
        listenTree->collapseAll();
    });

    auto fmtBytes = [](quint64 n) -> QString {
        if (n < 1024) return QString::number(n) + QStringLiteral(" B");
        if (n < 1024ull * 1024) return QString::number(n / 1024.0, 'f', 1) + QStringLiteral(" KB");
        if (n < 1024ull * 1024 * 1024)
            return QString::number(n / (1024.0 * 1024.0), 'f', 2) + QStringLiteral(" MB");
        return QString::number(n / (1024.0 * 1024.0 * 1024.0), 'f', 2) + QStringLiteral(" GB");
    };

    // Numeric sort for size columns (overrides string sort of "1.2 MB")
    class SizeItem : public QTableWidgetItem {
    public:
        explicit SizeItem(const QString& text, quint64 bytes)
            : QTableWidgetItem(text)
        {
            setData(Qt::UserRole, QVariant::fromValue(qulonglong(bytes)));
            setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        }
        bool operator<(const QTableWidgetItem& other) const override
        {
            return data(Qt::UserRole).toULongLong() < other.data(Qt::UserRole).toULongLong();
        }
    };
    class IntItem : public QTableWidgetItem {
    public:
        explicit IntItem(int v) : QTableWidgetItem(QString::number(v))
        {
            setData(Qt::UserRole, v);
            setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        }
        bool operator<(const QTableWidgetItem& other) const override
        {
            return data(Qt::UserRole).toInt() < other.data(Qt::UserRole).toInt();
        }
    };

    auto fillTable = [this, fmtBytes, filterText, filterPidText, filterRemoteText](
                         QTableWidget* table, const QVector<BehaviorRow>& rows, bool withRemote) {
        const QString fProc = filterText->trimmed();
        const QString fPid = filterPidText->trimmed();
        const QString fRem = filterRemoteText->trimmed();

        const bool showIcons = m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked();

        table->setSortingEnabled(false);
        table->setUpdatesEnabled(false);
        table->setRowCount(0);
        int r = 0;
        for (const BehaviorRow& row : rows) {
            if (!fPid.isEmpty() && !QString::number(row.pid).contains(fPid))
                continue;
            if (!fProc.isEmpty() && !row.processName.contains(fProc, Qt::CaseInsensitive))
                continue;
            if (withRemote && !fRem.isEmpty()) {
                const QString blob = row.remoteIP + QLatin1Char(' ') + row.remoteHost
                    + QLatin1Char(' ') + QString::number(row.remotePort)
                    + QLatin1Char(' ') + row.protocol;
                if (!blob.contains(fRem, Qt::CaseInsensitive))
                    continue;
            } else if (!withRemote && !fRem.isEmpty()) {
                // process tab: remote filter not applicable — skip filter
            }

            table->insertRow(r);
            auto* nameItem = new QTableWidgetItem(row.processName);
            if (showIcons) {
                QString path;
                auto cit = m_procInfoCache.constFind(row.pid);
                if (cit != m_procInfoCache.constEnd())
                    path = resolveDevicePath(cit->path);
                const QIcon ic = iconForProcessPath(path);
                if (!ic.isNull())
                    nameItem->setIcon(ic);
            }
            // Structured fields for right-click Copy menu (on process cell)
            nameItem->setData(Qt::UserRole, row.pid);
            nameItem->setData(Qt::UserRole + 1, row.processName);
            nameItem->setData(Qt::UserRole + 2, row.remoteIP);
            nameItem->setData(Qt::UserRole + 3, row.remotePort);
            nameItem->setData(Qt::UserRole + 4, row.remoteHost);
            table->setItem(r, 0, nameItem);
            table->setItem(r, 1, new IntItem(row.pid));
            table->setItem(r, 2, new QTableWidgetItem(row.protocol.isEmpty()
                                                          ? QStringLiteral("—")
                                                          : row.protocol));
            QString remote;
            if (withRemote) {
                if (row.protocol == QLatin1String("UDP")) {
                    remote = QStringLiteral("bind %1:%2")
                                 .arg(row.remoteIP.isEmpty() ? QStringLiteral("?") : row.remoteIP)
                                 .arg(row.remotePort);
                } else {
                    const QString ep = row.remotePort
                        ? (row.remoteIP + QLatin1Char(':') + QString::number(row.remotePort))
                        : row.remoteIP;
                    remote = ep;
                    if (!row.remoteHost.isEmpty())
                        remote = row.remoteHost + QStringLiteral(" (") + ep + QLatin1Char(')');
                }
            }
            auto* remoteItem = new QTableWidgetItem(remote);
            remoteItem->setData(Qt::UserRole, row.remoteIP);
            remoteItem->setData(Qt::UserRole + 1, row.remotePort);
            remoteItem->setData(Qt::UserRole + 2, row.remoteHost);
            table->setItem(r, 3, remoteItem);
            table->setItem(r, 4, new SizeItem(
                row.hasByteStats || row.bytesIn || row.bytesOut ? fmtBytes(row.bytesIn)
                                                                : QStringLiteral("—"),
                row.bytesIn));
            table->setItem(r, 5, new SizeItem(
                row.hasByteStats || row.bytesIn || row.bytesOut ? fmtBytes(row.bytesOut)
                                                                : QStringLiteral("—"),
                row.bytesOut));
            auto* durItem = new IntItem(int(row.durationSec));
            {
                const qint64 sec = row.durationSec;
                QString dur = QStringLiteral("—");
                if (sec > 0) {
                    if (sec < 60)
                        dur = QString::number(sec) + QStringLiteral("s");
                    else if (sec < 3600)
                        dur = QStringLiteral("%1m %2s").arg(sec / 60).arg(sec % 60);
                    else
                        dur = QStringLiteral("%1h %2m").arg(sec / 3600).arg((sec % 3600) / 60);
                }
                durItem->setText(dur);
            }
            table->setItem(r, 6, durItem);
            auto* cls = new QTableWidgetItem(row.classification);
            if (row.classification.contains(QLatin1String("Download")))
                cls->setBackground(QBrush(QColor(QStringLiteral("#E3F2FD"))));
            else if (row.classification.contains(QLatin1String("Upload")))
                cls->setBackground(QBrush(QColor(QStringLiteral("#FFF3E0"))));
            else if (row.classification.contains(QLatin1String("Streaming")))
                cls->setBackground(QBrush(QColor(QStringLiteral("#E8F5E9"))));
            else if (row.classification.contains(QLatin1String("UDP")))
                cls->setBackground(QBrush(QColor(QStringLiteral("#F3E5F5"))));
            table->setItem(r, 7, cls);
            ++r;
        }
        table->setUpdatesEnabled(true);
        table->setSortingEnabled(true);
    };

    auto refresh = [this, procTable, hostTable, histTree, listenTree, fillTable,
                    filterText, filterPidText, filterRemoteText, totalsLabel, fmtBytes]() {
        if (!m_behaviorMonitor) return;
        enrichBehaviorHostnames(false);   // no full log scan
        fillTable(procTable, m_behaviorMonitor->snapshotByProcess(), false);
        fillTable(hostTable, m_behaviorMonitor->snapshotByProcessHost(), true);

        // Bottom totals: sum of all per-process byte counters
        {
            quint64 totIn = 0, totOut = 0;
            int nWithBytes = 0;
            for (const BehaviorRow& row : m_behaviorMonitor->snapshotByProcess()) {
                totIn  += row.bytesIn;
                totOut += row.bytesOut;
                if (row.hasByteStats || row.bytesIn || row.bytesOut)
                    ++nWithBytes;
            }
            const quint64 total = totIn + totOut;
            totalsLabel->setText(
                QStringLiteral("Total traffic: <span style='color:#1565c0'>%1</span>"
                               "  ·  In: <span style='color:#2e7d32'>%2</span>"
                               "  ·  Out: <span style='color:#e65100'>%3</span>"
                               "  ·  processes with bytes: %4")
                    .arg(fmtBytes(total))
                    .arg(fmtBytes(totIn))
                    .arg(fmtBytes(totOut))
                    .arg(nWithBytes));
        }

        const QString fProc = filterText->trimmed();
        const QString fPid = filterPidText->trimmed();
        const QString fRem = filterRemoteText->trimmed();

        auto passFilter = [&](int pid, const QString& name, const QString& remoteBlob) {
            if (!fPid.isEmpty() && !QString::number(pid).contains(fPid)) return false;
            if (!fProc.isEmpty() && !name.contains(fProc, Qt::CaseInsensitive)) return false;
            if (!fRem.isEmpty() && !remoteBlob.contains(fRem, Qt::CaseInsensitive)) return false;
            return true;
        };

        // ---- Connection history tree ----
        {
            const bool wasSort = histTree->isSortingEnabled();
            histTree->setSortingEnabled(false);
            histTree->setUpdatesEnabled(false);
            QSet<int> expandedPids;
            for (int i = 0; i < histTree->topLevelItemCount(); ++i) {
                auto* it = histTree->topLevelItem(i);
                if (it && it->isExpanded())
                    expandedPids.insert(it->data(0, Qt::UserRole).toInt());
            }
            histTree->clear();

            QHash<int, QTreeWidgetItem*> parents;
            const auto hist = m_behaviorMonitor->snapshotConnectionHistory();
            for (const ConnHistoryRow& c : hist) {
                QString remote = c.remoteIP.isEmpty()
                    ? QStringLiteral("(local bind)")
                    : (c.remotePort
                           ? c.remoteIP + QLatin1Char(':') + QString::number(c.remotePort)
                           : c.remoteIP);
                if (!c.remoteHost.isEmpty() && !c.remoteIP.isEmpty())
                    remote = c.remoteHost + QStringLiteral(" (") + remote + QLatin1Char(')');
                const QString local = c.localPort
                    ? c.localIP + QLatin1Char(':') + QString::number(c.localPort)
                    : c.localIP;
                if (!passFilter(c.pid, c.processName,
                                remote + QLatin1Char(' ') + local + QLatin1Char(' ') + c.protocol))
                    continue;

                QTreeWidgetItem* parent = parents.value(c.pid);
                if (!parent) {
                    parent = new QTreeWidgetItem();
                    parent->setText(0, c.processName);
                    parent->setData(1, Qt::DisplayRole, c.pid);
                    parent->setData(0, Qt::UserRole, c.pid);
                    parent->setData(0, Qt::UserRole + 1, c.processName);
                    QFont bf = parent->font(0);
                    bf.setBold(true);
                    parent->setFont(0, bf);
                    if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
                        QString path;
                        auto cit = m_procInfoCache.constFind(c.pid);
                        if (cit != m_procInfoCache.constEnd())
                            path = resolveDevicePath(cit->path);
                        const QIcon ic = iconForProcessPath(path);
                        if (!ic.isNull())
                            parent->setIcon(0, ic);
                    }
                    histTree->addTopLevelItem(parent);
                    parents.insert(c.pid, parent);
                }
                auto* leaf = new QTreeWidgetItem(parent);
                leaf->setText(0, c.protocol + QStringLiteral("  ") + local + QStringLiteral(" → ") + remote);
                leaf->setData(0, Qt::UserRole, c.pid);
                leaf->setData(0, Qt::UserRole + 1, c.processName);
                leaf->setData(0, Qt::UserRole + 2, c.remoteIP);
                leaf->setData(0, Qt::UserRole + 3, c.remotePort);
                leaf->setData(0, Qt::UserRole + 4, c.remoteHost);
                leaf->setData(1, Qt::DisplayRole, c.pid);
                leaf->setText(2, c.protocol);
                leaf->setText(3, local);
                leaf->setText(4, remote);
                leaf->setText(5, c.live ? QStringLiteral("Live") : QStringLiteral("Disconnected"));
                if (c.live)
                    leaf->setBackground(5, QBrush(QColor(QStringLiteral("#E8F5E9"))));
                else
                    leaf->setBackground(5, QBrush(QColor(QStringLiteral("#FFEBEE"))));
                // Traffic size when EStats provided deltas
                {
                    const bool has = c.bytesIn || c.bytesOut;
                    auto fmt = [](quint64 n) -> QString {
                        if (n < 1024) return QString::number(n) + QStringLiteral(" B");
                        if (n < 1024ull * 1024)
                            return QString::number(n / 1024.0, 'f', 1) + QStringLiteral(" KB");
                        if (n < 1024ull * 1024 * 1024)
                            return QString::number(n / (1024.0 * 1024.0), 'f', 2) + QStringLiteral(" MB");
                        return QString::number(n / (1024.0 * 1024.0 * 1024.0), 'f', 2) + QStringLiteral(" GB");
                    };
                    leaf->setText(6, has ? fmt(c.bytesIn) : QStringLiteral("—"));
                    leaf->setData(6, Qt::UserRole, qulonglong(c.bytesIn));
                    leaf->setText(7, has ? fmt(c.bytesOut) : QStringLiteral("—"));
                    leaf->setData(7, Qt::UserRole, qulonglong(c.bytesOut));
                }
                // Duration: first seen → last seen (or now if still live)
                {
                    qint64 sec = 0;
                    if (c.firstSeen.isValid()) {
                        const QDateTime end = c.live ? QDateTime::currentDateTime()
                                                     : (c.lastSeen.isValid() ? c.lastSeen : c.firstSeen);
                        sec = c.firstSeen.secsTo(end);
                        if (sec < 0) sec = 0;
                    }
                    QString dur;
                    if (sec < 60)
                        dur = QString::number(sec) + QStringLiteral("s");
                    else if (sec < 3600)
                        dur = QStringLiteral("%1m %2s").arg(sec / 60).arg(sec % 60);
                    else
                        dur = QStringLiteral("%1h %2m").arg(sec / 3600).arg((sec % 3600) / 60);
                    leaf->setData(8, Qt::UserRole, qlonglong(sec));
                    leaf->setText(8, dur);
                }
                leaf->setText(9, c.lastSeen.toString(QStringLiteral("HH:mm:ss")));
            }
            for (auto it = parents.constBegin(); it != parents.constEnd(); ++it) {
                if (expandedPids.contains(it.key()))
                    it.value()->setExpanded(true);
            }
            histTree->setUpdatesEnabled(true);
            histTree->setSortingEnabled(wasSort);
        }

        // ---- Listening ports tree ----
        {
            const bool wasSort = listenTree->isSortingEnabled();
            listenTree->setSortingEnabled(false);
            listenTree->setUpdatesEnabled(false);
            QSet<int> expandedPids;
            for (int i = 0; i < listenTree->topLevelItemCount(); ++i) {
                auto* it = listenTree->topLevelItem(i);
                if (it && it->isExpanded())
                    expandedPids.insert(it->data(0, Qt::UserRole).toInt());
            }
            listenTree->clear();

            QHash<int, QTreeWidgetItem*> parents;
            const auto listens = m_behaviorMonitor->snapshotListeners();
            for (const ListenRow& L : listens) {
                const QString local = L.localPort
                    ? L.localIP + QLatin1Char(':') + QString::number(L.localPort)
                    : L.localIP;
                if (!passFilter(L.pid, L.processName, local + QLatin1Char(' ') + L.protocol))
                    continue;

                QTreeWidgetItem* parent = parents.value(L.pid);
                if (!parent) {
                    parent = new QTreeWidgetItem();
                    parent->setText(0, L.processName);
                    parent->setData(1, Qt::DisplayRole, L.pid);
                    parent->setData(0, Qt::UserRole, L.pid);
                    parent->setData(0, Qt::UserRole + 1, L.processName);
                    QFont bf = parent->font(0);
                    bf.setBold(true);
                    parent->setFont(0, bf);
                    if (m_cbShowProcessIcons && m_cbShowProcessIcons->isChecked()) {
                        QString path;
                        auto cit = m_procInfoCache.constFind(L.pid);
                        if (cit != m_procInfoCache.constEnd())
                            path = resolveDevicePath(cit->path);
                        const QIcon ic = iconForProcessPath(path);
                        if (!ic.isNull())
                            parent->setIcon(0, ic);
                    }
                    listenTree->addTopLevelItem(parent);
                    parents.insert(L.pid, parent);
                }
                auto* leaf = new QTreeWidgetItem(parent);
                leaf->setText(0, L.protocol + QStringLiteral("  ") + local);
                leaf->setData(0, Qt::UserRole, L.pid);
                leaf->setData(0, Qt::UserRole + 1, L.processName);
                leaf->setData(0, Qt::UserRole + 2, L.localIP);   // local as "remote" N/A
                leaf->setData(0, Qt::UserRole + 3, L.localPort);
                leaf->setData(0, Qt::UserRole + 4, QString());
                leaf->setData(1, Qt::DisplayRole, L.pid);
                leaf->setText(2, L.protocol);
                leaf->setText(3, local);
                leaf->setText(4, L.live ? QStringLiteral("Listening") : QStringLiteral("Closed"));
                if (L.live)
                    leaf->setBackground(4, QBrush(QColor(QStringLiteral("#E3F2FD"))));
                else
                    leaf->setBackground(4, QBrush(QColor(QStringLiteral("#FFEBEE"))));
                leaf->setText(5, L.lastSeen.toString(QStringLiteral("HH:mm:ss")));
            }
            for (auto it = parents.constBegin(); it != parents.constEnd(); ++it) {
                if (expandedPids.contains(it.key()))
                    it.value()->setExpanded(true);
            }
            listenTree->setUpdatesEnabled(true);
            listenTree->setSortingEnabled(wasSort);
        }
    };

    auto onFilter = [filterText, filterPidText, filterRemoteText, filterProc, filterPid, filterRemote, refresh]() {
        *filterText = filterProc->text();
        *filterPidText = filterPid->text();
        *filterRemoteText = filterRemote->text();
        refresh();
    };
    connect(filterProc, &QLineEdit::textChanged, win, [onFilter](const QString&) { onFilter(); });
    connect(filterPid, &QLineEdit::textChanged, win, [onFilter](const QString&) { onFilter(); });
    connect(filterRemote, &QLineEdit::textChanged, win, [onFilter](const QString&) { onFilter(); });

    connect(refreshBtn, &QPushButton::clicked, win, refresh);
    connect(clearBtn, &QPushButton::clicked, win,
            [this, procTable, hostTable, histTree, listenTree, totalsLabel, fmtBytes]() {
        if (m_behaviorMonitor)
            m_behaviorMonitor->clear();
        // Fast UI wipe only — avoid full refresh/enrich (was lagging the app)
        procTable->setSortingEnabled(false);
        hostTable->setSortingEnabled(false);
        procTable->setRowCount(0);
        hostTable->setRowCount(0);
        histTree->clear();
        listenTree->clear();
        procTable->setSortingEnabled(true);
        hostTable->setSortingEnabled(true);
        totalsLabel->setText(
            QStringLiteral("Total traffic: <span style='color:#1565c0'>%1</span>"
                           "  ·  In: <span style='color:#2e7d32'>%2</span>"
                           "  ·  Out: <span style='color:#e65100'>%3</span>"
                           "  ·  processes with bytes: 0")
                .arg(fmtBytes(0)).arg(fmtBytes(0)).arg(fmtBytes(0)));
    });
    auto* timer = new QTimer(win);
    // Timer only drives UI when Auto-update is on
    connect(timer, &QTimer::timeout, win, [autoCb, refresh]() {
        if (autoCb->isChecked())
            refresh();
    });
    timer->start(2000);
    connect(autoCb, &QCheckBox::toggled, win, [timer](bool on) {
        if (on) timer->start(2000);
        else timer->stop();
    });
    // Background sampler emits updated every second — only repaint when auto is on
    if (m_behaviorMonitor) {
        connect(m_behaviorMonitor, &NetworkBehaviorMonitor::updated, win,
                [autoCb, refresh]() {
            if (autoCb->isChecked())
                refresh();
        });
    }

    refresh();
    win->show();
    win->raise();
    win->activateWindow();
}
