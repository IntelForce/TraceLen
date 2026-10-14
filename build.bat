@echo off
REM ============================================================
REM build.bat - One-click build script for TraceLen
REM ============================================================
REM Run this script from a Qt MinGW terminal:
REM   Start Menu → Qt 5.x.x → Qt 5.x.x MinGW 64-bit
REM
REM USAGE:
REM   build.bat                   (auto-detect Qt)
REM   build.bat C:\Qt\5.15.2\mingw81_64   (specify Qt path manually)
REM ============================================================

setlocal

REM ---- Check arguments ----
if not "%1"=="" (
    set QT_PATH=%1
    echo Using specified Qt path: %QT_PATH%
    goto :build
)

REM ---- Try common Qt installation paths ----
for %%D in (
    "C:\Qt\5.15.2\mingw81_64"
    "C:\Qt\5.15.13\mingw81_64"
    "C:\Qt\5.15.0\mingw81_64"
    "C:\Qt\5.14.2\mingw81_64"
    "C:\Qt\5.12.12\mingw73_64"
    "%USERPROFILE%\Qt\5.15.2\mingw81_64"
) do (
    if exist %%D\bin\qmake.exe (
        set QT_PATH=%%~D
        echo Found Qt at: %%~D
        goto :build
    )
)

echo.
echo *** Qt5 not found in common locations. ***
echo.
echo Please run this script with your Qt path as an argument:
echo     build.bat C:\Qt\5.15.2\mingw81_64
echo.
echo Or open the Qt MinGW terminal from the Start Menu and run:
echo     cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH=C:\Qt\5.15.2\mingw81_64
echo.
pause
exit /b 1

:build
REM ---- Create build directory ----
if not exist build mkdir build
cd build

REM ---- Run CMake to generate Makefiles ----
echo.
echo Running CMake...
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="%QT_PATH%" -DCMAKE_BUILD_TYPE=Release

if errorlevel 1 (
    echo.
    echo *** CMake failed! See errors above. ***
    pause
    exit /b 1
)

REM ---- Compile the project ----
echo.
echo Compiling...
mingw32-make -j4

if errorlevel 1 (
    echo.
    echo *** Compilation failed! See errors above. ***
    pause
    exit /b 1
)

REM ---- Copy Qt DLLs so the .exe can run standalone ----
echo.
echo Copying Qt runtime DLLs...
"%QT_PATH%\bin\windeployqt.exe" TraceLen.exe

echo.
echo ============================================================
echo  BUILD SUCCESSFUL!
echo  Executable: build\TraceLen.exe
echo ============================================================
echo.
echo Run TraceLen.exe to start the application.
echo NOTE: Run as Administrator for full process monitoring access.
echo.
pause
