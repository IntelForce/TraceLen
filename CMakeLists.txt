# ============================================================
# CMakeLists.txt  —  TraceLen (Windows)
# ============================================================
#
# BUILD INSTRUCTIONS:
#   1. Open "Qt MinGW terminal" from Start Menu (Qt 5.15 or Qt 6)
#   2. cd C:\path\to\TraceLen
#   3. rmdir /s /q build   (if build folder exists from before)
#   4. mkdir build && cd build
#   5. cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\6.11.2\mingw_64"
#   6. mingw32-make -j4
#   7. windeployqt TraceLen.exe
#   8. TraceLen.exe
#
#   For full file-operation monitoring (with PID info):
#   Run TraceLen.exe as Administrator.
# ============================================================

cmake_minimum_required(VERSION 3.16)
project(TraceLen VERSION 2.3.0)

# Version is passed to C++ as a macro so main.cpp and the log writer
# never disagree again.
add_compile_definitions(PM_APP_VERSION="${PROJECT_VERSION}"
                        PM_LOG_FORMAT_VERSION="2.3")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# ---- Qt: prefer Qt6, fall back to Qt5 ----
# Tries Qt 6 first, then Qt 5. Both are fully supported.
# Pass -DCMAKE_PREFIX_PATH=<path to Qt kit> if auto-detection fails.
find_package(Qt6 QUIET COMPONENTS Core Widgets Network)
if(NOT Qt6_FOUND)
    find_package(Qt5 QUIET COMPONENTS Core Widgets Network)
endif()
if(Qt6_FOUND)
    message(STATUS "Using Qt6 ${Qt6_VERSION}")
    set(QT_LIBS Qt6::Core Qt6::Widgets Qt6::Network)
elseif(Qt5_FOUND)
    message(STATUS "Using Qt5 ${Qt5_VERSION}")
    set(QT_LIBS Qt5::Core Qt5::Widgets Qt5::Network)
else()
    message(FATAL_ERROR "Neither Qt 5 nor Qt 6 (Core, Widgets, Network) was found. "
                        "Pass -DCMAKE_PREFIX_PATH=<path to Qt kit>.")
endif()

# ---- Source files ----
set(SOURCES
    src/main.cpp
    src/ActivityLog.cpp
    src/FileWatcher.cpp
    src/EtwFileWatcher.cpp
    src/EtwRegistryDnsWatcher.cpp
    src/SystemMonitor.cpp
    src/DnsResolver.cpp
    src/ProcessInfoWorker.cpp
    src/ProcessTimeline.cpp
    src/Diagnostics.cpp
    src/LogLoadWorker.cpp
    src/NetworkBehaviorMonitor.cpp
    src/MainWindow.cpp
)

# WIN32 = no console window on launch (GUI app)
add_executable(TraceLen WIN32 ${SOURCES})

# ---- Windows libraries ----
# Qt               — GUI framework + network (QHostInfo for DNS)
# ws2_32           — Winsock 2 (ntohs used in SystemMonitor)
# iphlpapi         — IP Helper (GetExtendedTcpTable, GetExtendedUdpTable)
# psapi            — Process Status (QueryFullProcessImageNameW)
# advapi32         — Service control (EnumServicesStatusExW) + ETW (StartTrace etc.)
# tdh              — ETW event schema decoding (TdhGetEventInformation)
# version          — File version info (GetFileVersionInfoW, VerQueryValueW)
target_link_libraries(TraceLen
    ${QT_LIBS}
    ws2_32
    iphlpapi
    psapi
    advapi32
    tdh
    version
    wintrust   # Authenticode verification (WinVerifyTrust)
    crypt32    # certificate parsing helpers used alongside wintrust
)

target_include_directories(TraceLen PRIVATE src)
message(STATUS "TraceLen ${PROJECT_VERSION} configured")
