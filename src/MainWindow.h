#pragma once
// ============================================================
// MainWindow.h  —  Application main window
// ============================================================
// COLUMNS (all 12 are toggleable via right-click on the header):
//   0  Timestamp     — always visible by default
//   1  PID           — always visible by default
//   2  Process       — always visible by default
//   3  Parent        — always visible by default
//   4  Type          — always visible by default
//   5  Details       — always visible by default
//   6  Hostname      — visible by default (DNS resolved)
//   7  Publisher     — visible by default (from ProcessInfoWorker)
//   8  Cmd Line      — visible by default (from ProcessInfoWorker)
//   9  Path          — hidden by default
//  10  Version       — hidden by default
//  11  Service       — hidden by default
// ============================================================

#include "ActivityEvent.h"
#include "MonitorSettings.h"
#include "ActivityLog.h"
#include "FileWatcher.h"
#include "EtwFileWatcher.h"
#include "EtwRegistryDnsWatcher.h"
#include "SystemMonitor.h"
#include "DnsResolver.h"
#include "ProcessInfoWorker.h"
#include "NetworkBehaviorMonitor.h"

#include <QMainWindow>
#include <QList>
#include <QHash>
#include <QSet>
#include <QTimer>
#include <QThread>
#include <QJsonObject>
#include <QIcon>
#include <QVector>
#include <deque>
#include <QFile>
#include <QRegularExpression>

class QTableWidget;
class QTableWidgetItem;
class QColor;
class QTreeWidget;
class QTreeWidgetItem;
class QDialog;
class QListWidget;
class QPushButton;
class QCheckBox;
class QLineEdit;
class QPlainTextEdit;
class QLabel;
class QSpinBox;
class QCloseEvent;
class QPoint;
class QComboBox;
class QSplitter;
class QGroupBox;
class QWidget;
class QAction;

// ---- Capture condition ----
// A row is only added to the log when the "Details" column value
// matches at least one active capture condition (if any are set).
struct CaptureCondition {
    int     column;   // Column index (COL_* constant)
    QString pattern;  // Regex pattern
    QRegularExpression compiled;   // built once when added; invalid = matches nothing
};

// ---- Column filter ----
// Rows whose value in `column` matches `pattern` are hidden.
struct ColumnFilter {
    int     column;   // Column index (COL_* constant)
    QString pattern;  // Regex pattern (case-insensitive)
    QRegularExpression compiled;   // built once when added; invalid = matches nothing
};

// Limits on how many filters can be active. Each one is checked against every
// row on every filter pass, so an unbounded list is what made the window lag.
static constexpr int kMaxColumnFilters    = 64;
static constexpr int kMaxCaptureConditions = 32;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onStartClicked();
    void onStopClicked();
    void onSaveLogClicked();
    void onLoadLogClicked();
    void onLoadProgress(int percent, const QString& message);
    void onLoadWorkerFinished(bool ok, const QString& error);
    void pumpLoadBatch();
    void onClearLogClicked();
    void onAddDirectoryClicked();
    void onRemoveDirectoryClicked();

    void onFilterChanged();
    void onGroupByProcessToggled();
    void applyFiltersAndMaybeTree();   // applyFiltersToTable() + tree refresh if visible
    void scheduleFilterApply();        // debounced trigger for applyFiltersAndMaybeTree()
    void onSavePresetClicked();
    void onDeletePresetClicked();
    void onPresetComboChanged(int index);
    void onProcessFilterChanged();
    void onResolveIPsToggled();
    void onFetchProcInfoToggled();

    // Right-click on ANY column header → toggle-visibility menu
    void onHeaderContextMenu(const QPoint& pos);
    void onEventTableContextMenu(const QPoint& pos);
    void onManageIgnoreList();

    // Events from background threads (all queued = UI-thread safe)
    void onFileEventDetected(ActivityEvent event);
    void onProcessEventDetected(ActivityEvent event);
    void onNetworkEventDetected(ActivityEvent event);
    void onStatusMessage(QString message);
    void onWatcherFinished(const QString& name);

    // DNS result
    void onHostnameResolved(QString ip, QString hostname);

    // Process metadata result
    void onProcessInfoReady(int pid, ProcInfo info);
    void flushResultUpdates();
    void scheduleResultFlush();

    // Table double-click
    void onTableDoubleClicked(int row, int col);

    // Search / filter toolbar
    void onSearchTextChanged(const QString& text);
    void onSearchColumnChanged(int idx);

    // Column filter management
    void onAddColumnFilter();
    void onRemoveColumnFilter(int column, const QString& pattern);

    // Capture condition management
    void onAddCaptureCondition();
    void onRemoveCaptureCondition(int column, const QString& pattern);

    // View menu actions
    void onToggleSidePanel(bool visible);
    void onToggleToolbar(bool visible);
    void onToggleStatusBar(bool visible);
    void showStatisticsWindow();

private:
    void setupUI();
    void setupToolbar();
    void setupLeftPanel(QWidget* parent);
    void setupEventTable(QWidget* parent);
    void setupStatusBar()  ;
    void setupSearchBar(QWidget* parent);
    void setupFilterBar(QWidget* parent);
    void setupMenuBar();
    void connectSignals();

    void   addEventToTable(const ActivityEvent& event);   // = enqueueEvent()

    // ---- Batched UI updates (keeps the UI responsive under heavy load) ----
    void   enqueueEvent(ActivityEvent ev);     // cheap, GUI thread
    void   appendCircularLogLine(const ActivityEvent& ev);
    void   closeCircularLog();
    void   saveUiPreferences();
    void   loadUiPreferences();
    void   scheduleUiPreferencesSave();
    QFile* m_circularFile    = nullptr;   // held open for the session
    qint64 m_circularBytes   = 0;         // bytes written to the current file
    qint64 m_circularMaxBytes = 50LL * 1024 * 1024;  // from settings
    QString m_circularLogPath;            // empty = default location
    void   flushPendingEvents();               // time-boxed batch insert
    void   appendRow(const ActivityEvent& ev); // one row, no sort/scroll/status work
    void   trimTable();                        // drop oldest rows above the cap
    void   applyCachedProcInfo(ActivityEvent& ev) const;
    MonitorSettings readSettings() const;
    void   updateUIState(bool monitoring);
    void   updateStatusBar();
    void   updateNetTrafficStatus();
    bool   isEventTypeVisible(ActivityEvent::Type type) const;
    void   applyFiltersToTable();
    bool   rowPassesColumnFilters(int row) const;
    bool   rowPassesCompiled(int row, const QList<ColumnFilter>& filters) const;
    bool   rowPassesSearch(int row) const;
    bool   eventPassesCaptureConditions(const ActivityEvent& ev) const;
    static QString extractRemoteIP(const QString& details);
    static QString resolveDevicePath(const QString& path);
    static QTableWidgetItem* signatureBadgeCell(const QString& status, const QColor& fallbackBg);
    void   rebuildFilterTagsUI();
    void   rebuildCaptureTagsUI();

    // ---- Background threads ----
    FileWatcher*          m_fileWatcher    = nullptr;
    EtwFileWatcher*       m_etwWatcher     = nullptr;
    EtwRegistryDnsWatcher* m_regDnsWatcher = nullptr;
    SystemMonitor*         m_sysMonitor    = nullptr;
    DnsResolver*       m_dnsResolver    = nullptr;
    ProcessInfoWorker* m_procInfoWorker = nullptr;

    // ---- Data ----
    ActivityLog* m_log;
    bool         m_isMonitoring   = false;
    bool         m_isAdmin        = false;
    bool         m_stopping       = false;   // true while a deliberate Stop runs
    int          m_expectedWatchers = 0;     // watchers started for this session
    int          m_unexpectedExits  = 0;     // watchers that ended without Stop

    // ---- Layout splitter (needed to toggle side panel) ----
    QSplitter*   m_mainSplitter   = nullptr;
    QWidget*     m_leftPanel      = nullptr;
    QWidget*     m_rightPanel     = nullptr;

    // ---- Left panel ----
    QListWidget* m_dirList;
    QPushButton* m_addDirBtn;
    QPushButton* m_removeDirBtn;
    QCheckBox*   m_cbFileWrite;
    QCheckBox*   m_cbFileDelete;
    QCheckBox*   m_cbFileRename;
    QCheckBox*   m_cbFileOpen;
    QCheckBox*   m_cbFileRead;
    QCheckBox*   m_cbNetConnect;
    QCheckBox*   m_cbNetListen;
    QCheckBox*   m_cbProcStart;
    QCheckBox*   m_cbProcStop;
    QCheckBox*   m_cbFileQuery;
    QCheckBox*   m_cbRegCreateKey;
    QCheckBox*   m_cbRegSetValue;
    QCheckBox*   m_cbRegDeleteValue;
    QCheckBox*   m_cbRegDeleteKey;
    QCheckBox*   m_cbRegRenameKey;
    QCheckBox*   m_cbDnsQuery;
    QCheckBox*   m_cbNetConnectLive;
    QCheckBox*   m_cbNetDisconnectLive;

    // ---- Filter presets (saved to filter_presets.json next to the exe) ----
    QComboBox*   m_presetCombo     = nullptr;
    QPushButton* m_presetSaveBtn   = nullptr;
    QPushButton* m_presetDeleteBtn = nullptr;
    QHash<QString, QJsonObject> m_filterPresets;   // preset name -> {checkboxKey: bool}
    QString filterPresetsFilePath() const;
    QMap<QString, QCheckBox*> filterCheckboxRegistry() const;
    void loadFilterPresetsFromDisk();
    void saveFilterPresetsToDisk() const;
    void applyFilterPreset(const QString& name);
    void refreshPresetCombo();

    // ---- Persistent ignore list (ignore_list.json next to the exe) ----
    // Patterns are matched case-insensitively against a row's process name
    // OR its Details text; a match hides the row everywhere (table and
    // process tree), the same way the type checkboxes do, and persists
    // across restarts — unlike the per-session coalescing elsewhere, this
    // is a permanent "I don't care about this" the user has to add
    // (right-click a row, or Tools -> Manage Ignore List) and remove
    // explicitly.
    QStringList m_ignoreList;
    QString ignoreListFilePath() const;
    void loadIgnoreListFromDisk();
    void saveIgnoreListToDisk() const;
    bool isIgnored(const QString& processName, const QString& details) const;
    QCheckBox*   m_cbResolveIPs;
    QCheckBox*   m_cbFetchProcInfo;
    QCheckBox*   m_cbShowProcessIcons = nullptr;
    QHash<QString, QIcon> m_iconByPath;   // normalized full exe path -> icon (exact path only)
    bool m_bulkLoading = false;         // skip per-row icon/fetch work during Load Log
    bool m_loadInProgress = false;
    QThread* m_loadThread = nullptr;
    class LogLoadWorker* m_loadWorker = nullptr;
    QVector<ActivityEvent> m_loadPending;
    int m_loadIndex = 0;
    int m_loadSkipped = 0;
    QString m_loadPath;
    QTimer* m_loadPumpTimer = nullptr;
    QIcon iconForExePath(const QString& path);
    // Icon only when the exact executable path is known (never by process name).
    // If expectedExeName is set, path is rejected when its basename differs
    // (avoids PID-reuse showing Chrome icon on Brave, etc.).
    QIcon iconForProcessPath(const QString& pathHint, const QString& expectedExeName = {});
    static bool pathMatchesExeName(const QString& path, const QString& processName);
    void applyProcessIconToRow(int row, int pid, const QString& pathHint = {});
    void applyProcessIconsToTree();
    void onShowProcessIconsToggled();
    QLineEdit*   m_processFilter;
    QPlainTextEdit* m_pathIncludeEdit = nullptr;
    QPlainTextEdit* m_pathExcludeEdit = nullptr;
    QCheckBox*   m_cbHideSuccessfulOps = nullptr;
    QCheckBox*   m_cbCircularLog = nullptr;
    QSpinBox*    m_pollInterval;
    QLabel*      m_adminLabel;

    // ---- Toolbar ----
    QToolBar*    m_mainToolbar    = nullptr;
    QPushButton* m_startBtn;
    QPushButton* m_stopBtn;
    QPushButton* m_saveBtn;
    QPushButton* m_loadBtn;
    QPushButton* m_clearBtn;
    QPushButton* m_statsBtn = nullptr;
    QPushButton* m_behaviorBtn = nullptr;
    NetworkBehaviorMonitor* m_behaviorMonitor = nullptr;
    QDialog* m_behaviorWindow = nullptr;
    void showBehaviorWindow();
    void learnHostnamesFromEvent(const ActivityEvent& ev);
    void syncHostnamesToBehaviorMonitor();
    void enrichBehaviorHostnames(bool fullLogScan = false);

    // ---- Search bar (above table) ----
    QWidget*   m_searchBarWidget  = nullptr;
    QLineEdit* m_searchEdit       = nullptr;
    QComboBox* m_searchColCombo   = nullptr;
    QComboBox* m_typeFilterCombo  = nullptr;  // display filter: one event type or all
    QLabel*    m_searchMatchLabel = nullptr;
    int        m_searchColumn     = -1;  // -1 = all columns
    QPushButton* m_expandTreeBtn  = nullptr;
    QPushButton* m_collapseTreeBtn = nullptr;

    // ---- Column filter bar ----
    QWidget*    m_filterBarWidget  = nullptr;
    QWidget*    m_filterTagsWidget = nullptr;   // holds tags
    QComboBox*  m_filterColCombo   = nullptr;
    QLineEdit*  m_filterPatternEdit= nullptr;
    QList<ColumnFilter> m_columnFilters;

    // ---- Capture conditions bar ----
    QWidget*    m_captureBarWidget  = nullptr;
    QWidget*    m_captureTagsWidget = nullptr;
    QComboBox*  m_captureColCombo   = nullptr;
    QLineEdit*  m_capturePatternEdit= nullptr;
    QList<CaptureCondition> m_captureConditions;

    // ---- Table ----
    QTableWidget* m_eventTable;

    // ---- Process-tree view (alternate to the flat table) ----
    QCheckBox*    m_cbGroupByProcess = nullptr;
    QCheckBox*    m_cbAutoScroll     = nullptr;
    QTreeWidget*  m_processTree      = nullptr;
    QTimer*       m_processTreeTimer = nullptr;   // periodic refresh while tree is visible
    QHash<int, QTreeWidgetItem*> m_processTreeNodes;   // pid -> its node in the tree
    void rebuildProcessTree();
    quint64 m_treeBuiltRevision = 0;     // log revision the tree was last built from

    // Coalesced UI-side results (applied on a timer, not per result)
    QHash<QString, QString> m_pendingHostnames;
    QHash<int, ProcInfo>    m_pendingProcInfo;
    QHash<QString, QString> m_hostnameKnown;   // ip -> best name seen so far
    QTimer*                 m_resultFlushTimer = nullptr;
    static constexpr int    kResultFlushMs = 250;
    QTreeWidgetItem* ensureProcessTreeNode(int pid, const QString& processName,
                                           int parentPid, const QString& parentName);
    void onProcessTreeItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onProcessTreeContextMenu(const QPoint& pos);
    void showProcessDetailWindow(int pid, const QString& processName);
    QDialog* m_statisticsWindow = nullptr;   // single shared stats window (if open)
    // pid itself plus every descendant (children, grandchildren, ...),
    // walked from ProcStart events' parentPid links — same source the
    // process tree and the "child processes started" list already use.
    // Shares their PID-reuse limitation: a PID recycled by Windows during
    // the session is treated as one continuous identity, not two.
    QSet<int> collectProcessSubtreePids(int rootPid) const;
    QHash<int, QDialog*> m_processDetailWindows;   // pid -> its open detail window, if any

    // ---- Batching state ----
    std::deque<ActivityEvent> m_pending;       // events waiting to become rows
    QTimer*   m_flushTimer     = nullptr;
    QTimer*   m_filterDebounceTimer = nullptr;   // debounces search/process-filter typing
    QTimer*   m_uiPrefsTimer = nullptr;          // debounced auto-save of filter checkboxes
    quint64   m_droppedForUi   = 0;            // rows skipped because the UI was behind
    quint64   m_droppedShown   = 0;
    qint64    m_rowSeq         = 0;            // monotonically increasing row id
    qint64    m_lastSortMs     = 0;
    bool      m_sortingWanted  = true;         // user-visible sorting state
    bool      m_sortDirty      = false;
    QHash<int, ProcInfo> m_procInfoCache;      // pid -> metadata (filled once per pid)
    QSet<int>            m_procInfoRequested;

    // ---- Status bar ----
    QLabel* m_statusLabel;
    QLabel* m_countLabel;
    QLabel* m_netTrafficLabel = nullptr;  // total network In/Out from behavior monitor
    QLabel* m_visibleCountLabel;
    QLabel* m_monitorStateLabel;

    // ---- View menu actions ----
    QAction* m_actSidePanel  = nullptr;
    QAction* m_actToolbar    = nullptr;
    QAction* m_actStatusBar  = nullptr;
};
