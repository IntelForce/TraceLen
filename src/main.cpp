// ============================================================
// main.cpp  —  Program entry point
// ============================================================
// Every C++ program starts here in main().
// Qt requires a QApplication object before anything else is created.
// On Windows, Qt also initialises COM and Winsock automatically
// inside QApplication's constructor, so all our Windows APIs
// (ntohs, getnameinfo, GetExtendedTcpTable…) work from this point on.
// ============================================================

#include <QApplication>
#include <QToolTip>
#include <QPalette>
#include <QColor>
#include "MainWindow.h"
#include "Diagnostics.h"

// ============================================================
// applyWhiteTheme()
// ============================================================
// By default Qt inherits the operating system's colour theme.
// On Windows 11 with dark mode enabled that makes the app dark.
// We override every colour role to force a clean white/light look
// regardless of the system setting.
//
// HOW QPalette WORKS:
//   Qt draws every widget using a set of named "colour roles":
//     Window       — background of the main window and panels
//     Base         — background of input widgets (table, text box)
//     Button       — face colour of buttons
//     Highlight    — selection highlight (e.g., selected table row)
//     … and many more.
//   By setting all roles on a QPalette and calling app.setPalette(),
//   we override the OS theme for the entire application.
static void applyWhiteTheme(QApplication& app)
{
    // "Fusion" is Qt's own clean, flat style that works equally well
    // on all Windows versions and respects our custom palette perfectly.
    // The alternative "windowsvista" style partially ignores our palette.
    app.setStyle("Fusion");

    QPalette p;

    // ---- Surfaces ----
    p.setColor(QPalette::Window,          QColor("#FFFFFF")); // panel backgrounds
    p.setColor(QPalette::WindowText,      QColor("#1A1A1A")); // text on panels
    p.setColor(QPalette::Base,            QColor("#FFFFFF")); // table/input bg
    p.setColor(QPalette::AlternateBase,   QColor("#F7F7F7")); // alternate row
    p.setColor(QPalette::Text,            QColor("#1A1A1A")); // text in inputs
    p.setColor(QPalette::BrightText,      QColor("#C62828")); // error text

    // ---- Buttons ----
    p.setColor(QPalette::Button,          QColor("#F0F0F0"));
    p.setColor(QPalette::ButtonText,      QColor("#1A1A1A"));
    p.setColor(QPalette::Mid,             QColor("#DDDDDD")); // 3-D shading
    p.setColor(QPalette::Dark,            QColor("#BBBBBB"));
    p.setColor(QPalette::Shadow,          QColor("#999999"));

    // ---- Selection ----
    p.setColor(QPalette::Highlight,       QColor("#1565C0")); // selected row bg
    p.setColor(QPalette::HighlightedText, QColor("#FFFFFF")); // selected row text

    // ---- Misc ----
    p.setColor(QPalette::Link,            QColor("#1565C0"));
    p.setColor(QPalette::LinkVisited,     QColor("#6A1B9A"));
    p.setColor(QPalette::ToolTipBase,     QColor("#FFFDE7")); // pale yellow
    p.setColor(QPalette::ToolTipText,     QColor("#212121"));

    // ---- Disabled-state colours ----
    // When a widget is greyed out, Qt uses the "Disabled" colour group.
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor("#9E9E9E"));
    p.setColor(QPalette::Disabled, QPalette::Text,       QColor("#9E9E9E"));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#9E9E9E"));
    p.setColor(QPalette::Disabled, QPalette::Highlight,  QColor("#BDBDBD"));
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor("#FFFFFF"));
    // Keep tooltips readable even when hovering a disabled filter checkbox
    p.setColor(QPalette::Disabled, QPalette::ToolTipBase, QColor("#FFFDE7"));
    p.setColor(QPalette::Disabled, QPalette::ToolTipText, QColor("#212121"));

    app.setPalette(p);

    // QToolTip is a separate top-level window. On some Windows themes the
    // system tooltip palette stays black (black text on black). Force it.
    {
        QPalette tipPal = QToolTip::palette();
        const QColor tipBg("#FFFDE7");
        const QColor tipFg("#212121");
        for (int i = 0; i < QPalette::NColorGroups; ++i) {
            const auto g = static_cast<QPalette::ColorGroup>(i);
            tipPal.setColor(g, QPalette::ToolTipBase, tipBg);
            tipPal.setColor(g, QPalette::ToolTipText, tipFg);
            tipPal.setColor(g, QPalette::Window, tipBg);
            tipPal.setColor(g, QPalette::WindowText, tipFg);
            tipPal.setColor(g, QPalette::Base, tipBg);
            tipPal.setColor(g, QPalette::Text, tipFg);
            tipPal.setColor(g, QPalette::Button, tipBg);
            tipPal.setColor(g, QPalette::ButtonText, tipFg);
        }
        QToolTip::setPalette(tipPal);
        QFont tipFont = app.font();
        tipFont.setPointSize(qMax(10, tipFont.pointSize()));
        QToolTip::setFont(tipFont);
    }

    // ---- Fine-grained stylesheet tweaks ----
    // QPalette covers most UI elements, but some details need QSS
    // (Qt Style Sheets) — similar to CSS but for Qt widgets.
    app.setStyleSheet(R"(
        QMainWindow, QDialog { background: #FFFFFF; }

        QToolBar {
            background: #F5F5F5;
            border-bottom: 1px solid #E0E0E0;
            spacing: 4px;
            padding: 3px 6px;
        }

        QStatusBar {
            background: #F5F5F5;
            border-top: 1px solid #E0E0E0;
            font-size: 12px;
        }

        QGroupBox {
            font-weight: bold;
            border: 1px solid #DDDDDD;
            border-radius: 5px;
            margin-top: 8px;
            background: #FAFAFA;
            padding-top: 4px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
            color: #444;
        }

        QTableWidget {
            background: #FFFFFF;
            gridline-color: #EEEEEE;
            selection-background-color: #1565C0;
            selection-color: #FFFFFF;
            border: 1px solid #DDDDDD;
        }
        QHeaderView::section {
            background: #F0F0F0;
            border: 1px solid #DDDDDD;
            padding: 5px 8px;
            font-weight: bold;
            color: #333;
        }
        QHeaderView::section:hover {
            background: #E8E8E8;
        }

        QListWidget {
            background: #FFFFFF;
            border: 1px solid #DDDDDD;
            border-radius: 3px;
        }
        QListWidget::item:selected {
            background: #1565C0;
            color: #FFFFFF;
        }

        QLineEdit, QSpinBox {
            background: #FFFFFF;
            border: 1px solid #CCCCCC;
            border-radius: 3px;
            padding: 4px 7px;
            color: #1A1A1A;
        }
        QLineEdit:focus, QSpinBox:focus {
            border-color: #1565C0;
        }

        QCheckBox { spacing: 6px; }
        QCheckBox::indicator {
            width: 15px; height: 15px;
            border: 1px solid #AAAAAA;
            border-radius: 3px;
            background: #FFFFFF;
        }
        QCheckBox::indicator:checked {
            background: #1565C0;
            border-color: #1565C0;
        }
        QCheckBox::indicator:disabled {
            background: #EEEEEE;
            border-color: #CCCCCC;
        }

        QScrollBar:vertical {
            background: #F5F5F5;
            width: 10px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical {
            background: #BDBDBD;
            border-radius: 5px;
            min-height: 24px;
        }
        QScrollBar::handle:vertical:hover { background: #9E9E9E; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

        QScrollBar:horizontal {
            background: #F5F5F5;
            height: 10px;
            border-radius: 5px;
        }
        QScrollBar::handle:horizontal {
            background: #BDBDBD;
            border-radius: 5px;
            min-width: 24px;
        }

        QSplitter::handle { background: #E0E0E0; width: 1px; }

        QToolTip {
            background-color: #FFFDE7;
            color: #212121;
            border: 1px solid #F9A825;
            padding: 6px 8px;
            border-radius: 3px;
            opacity: 255;
            font-size: 12px;
        }

        QMenu {
            background: #FFFFFF;
            border: 1px solid #DDDDDD;
        }
        QMenu::item { padding: 5px 20px; }
        QMenu::item:selected { background: #1565C0; color: #FFFFFF; }

        QPushButton {
            border-radius: 4px;
        }
        QPushButton:disabled {
            background: #EEEEEE !important;
            color: #AAAAAA !important;
        }

        QDialogButtonBox QPushButton {
            background: #F0F0F0;
            border: 1px solid #CCCCCC;
            border-radius: 4px;
            padding: 5px 16px;
            color: #1A1A1A;
            font-weight: normal;
        }
        QDialogButtonBox QPushButton:hover { background: #E0E0E0; }
    )");
}

// ============================================================
// main()
// ============================================================
int main(int argc, char* argv[])
{
    // QApplication MUST be the very first Qt object.
    // It sets up the event system and on Windows calls WSAStartup()
    // so that all Winsock functions work from this point forward.
    QApplication app(argc, argv);

    QApplication::setApplicationName("TraceLen");
    QApplication::setApplicationVersion(QStringLiteral(PM_APP_VERSION));
    QApplication::setOrganizationName("TraceLen");

    // Diagnostics need the app name and version (for the log folder and the
    // report header), so they are installed right after QApplication exists.
    // Anything that crashes before this point is too early to be relevant.
    Diagnostics::install();
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &Diagnostics::markCleanExit);

    // Force white theme before showing any window.
    // Must be called after QApplication is constructed.
    applyWhiteTheme(app);

    // Tooltips can still pick up a dark system palette on some Windows builds.
    // Re-assert light tip colors one more time right before the window appears.
    {
        QPalette tipPal;
        const QColor tipBg(255, 253, 231);   // #FFFDE7
        const QColor tipFg(33, 33, 33);      // #212121
        for (int i = 0; i < QPalette::NColorGroups; ++i) {
            const auto g = static_cast<QPalette::ColorGroup>(i);
            tipPal.setColor(g, QPalette::ToolTipBase, tipBg);
            tipPal.setColor(g, QPalette::ToolTipText, tipFg);
            tipPal.setColor(g, QPalette::Window, tipBg);
            tipPal.setColor(g, QPalette::WindowText, tipFg);
            tipPal.setColor(g, QPalette::Base, tipBg);
            tipPal.setColor(g, QPalette::Text, tipFg);
            tipPal.setColor(g, QPalette::Button, tipBg);
            tipPal.setColor(g, QPalette::ButtonText, tipFg);
            tipPal.setColor(g, QPalette::BrightText, tipFg);
        }
        QToolTip::setPalette(tipPal);
        app.setStyleSheet(app.styleSheet() + QStringLiteral(
            "\nQToolTip { background-color: #FFFDE7; color: #212121; "
            "border: 1px solid #F9A825; padding: 6px 8px; font-size: 12px; }"));
    }

    MainWindow window;
    window.show();

    // app.exec() runs the event loop until the user closes the window.
    // Returns 0 on normal exit.
    return app.exec();
}
