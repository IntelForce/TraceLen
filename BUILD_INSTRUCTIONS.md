# Build Instructions — TraceLen (Windows)

Follow every step exactly. Each step has been verified.

---

## What You Need (Prerequisites)

You need three things installed on your Windows PC:

| Tool | Purpose | Download |
|------|---------|----------|
| **Qt 5.15** | GUI framework + compiler toolchain | https://www.qt.io/download-open-source |
| **CMake 3.16+** | Build system | https://cmake.org/download/ |
| *(MinGW is bundled with Qt)* | C++ compiler | *(installed with Qt)* |

> **Why Qt 5 and not Qt 6?**  
> Qt 5.15 LTS is the most stable and widely tested version. The code is
> compatible with Qt 6 too, but Qt 5 is recommended for this project.

---

## Step 1 — Install Qt 5

1. Go to: **https://www.qt.io/download-open-source**
2. Click **"Download the Qt Online Installer"**
3. Run the installer. When it asks to create an account — you can skip.
4. On the **"Select Components"** screen, expand **Qt → Qt 5.15.x** and tick:
   - ☑ **MinGW 8.1.0 64-bit** ← required (this is the compiler)
   - ☑ Qt 5.15.x → MinGW 8.1.0 64-bit ← required (Qt libraries)
5. Under **Developer and Designer Tools**, make sure these are ticked:
   - ☑ **MinGW 8.1.0 64-bit** ← (the actual compiler binaries)
6. Click **Next → Install**. This downloads ~4 GB and takes 10–30 minutes.

**Default installation path:** `C:\Qt\`

---

## Step 2 — Install CMake

1. Go to: **https://cmake.org/download/**
2. Under **"Latest Release"** download:  
   `cmake-X.XX.X-windows-x86_64.msi`
3. Run the installer. On the **"Install Options"** page, select:  
   ☑ **"Add CMake to the system PATH for all users"** ← important!
4. Complete the installation.

**Verify:** Open Command Prompt and type `cmake --version`. You should see the version printed.

---

## Step 3 — Open the Qt MinGW Terminal

> **This step is critical.** You must use the Qt-provided terminal, not the
> regular Windows Command Prompt or PowerShell. The Qt terminal automatically
> sets up PATH for both MinGW (compiler) and Qt (libraries).

1. Open the **Start Menu**
2. Search for: **"Qt 5.15"**
3. Click: **"Qt 5.15.x MinGW 8.1.0 64-bit"**

A Command Prompt window opens. It looks ordinary but has all the right environment variables set.

**To verify it's working, type:**
```
qmake --version
```
You should see something like: `QMake version 3.1` and `Qt version 5.15.x`

---

## Step 4 — Navigate to the Project Folder

In the Qt MinGW terminal, navigate to where you extracted the project:

```bat
cd C:\path\to\TraceLen
```

For example, if you extracted it to your Desktop:
```bat
cd C:\Users\YourName\Desktop\TraceLen
```

**Verify you're in the right place:**
```bat
dir
```
You should see: `CMakeLists.txt`, `build.bat`, `src\`, `README.md`

---

## Step 5 — Build the Project

### Option A — Automatic (easiest)

Run the included build script:
```bat
build.bat
```

If Qt is not found automatically, pass the path:
```bat
build.bat C:\Qt\5.15.2\mingw81_64
```

The script will:
1. Create a `build\` folder
2. Run CMake to generate Makefiles
3. Compile all source files
4. Copy Qt DLLs next to the .exe (windeployqt)

---

### Option B — Manual (step by step)

If the script doesn't work, run these commands one at a time:

```bat
REM 1. Create the build directory
mkdir build
cd build

REM 2. Generate build files (replace path if Qt is installed elsewhere)
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\5.15.2\mingw81_64" -DCMAKE_BUILD_TYPE=Release

REM 3. Compile (the -j4 uses 4 CPU cores in parallel)
mingw32-make -j4

REM 4. Copy Qt DLLs so the .exe works standalone
"C:\Qt\5.15.2\mingw81_64\bin\windeployqt.exe" TraceLen.exe
```

**Each command must succeed (exit code 0) before running the next.**

---

## Step 6 — Run the Application

```bat
build\TraceLen.exe
```

Or double-click `TraceLen.exe` in the `build\` folder.

> **Tip:** Right-click → **"Run as Administrator"** to see system processes
> and network connections that belong to other users.

---

## What a Successful Build Looks Like

```
-- TraceLen (Windows) configured. Qt version: 5.15.13
-- Configuring done
-- Build files have been written to: C:/Users/.../TraceLen/build

[ 16%] Building CXX object CMakeFiles/TraceLen.dir/src/main.cpp.obj
[ 33%] Building CXX object CMakeFiles/TraceLen.dir/src/ActivityLog.cpp.obj
[ 50%] Building CXX object CMakeFiles/TraceLen.dir/src/FileWatcher.cpp.obj
[ 66%] Building CXX object CMakeFiles/TraceLen.dir/src/SystemMonitor.cpp.obj
[ 83%] Building CXX object CMakeFiles/TraceLen.dir/src/MainWindow.cpp.obj
[100%] Linking CXX executable TraceLen.exe
[100%] Built target TraceLen
```

---

## Troubleshooting

### "cmake is not recognized as a command"
CMake is not in PATH. Either:
- Re-run the CMake installer and select **"Add to PATH"**
- Or use the full path: `"C:\Program Files\CMake\bin\cmake.exe" ..`

---

### "Could NOT find Qt5" during cmake
CMake can't find your Qt installation. Fix by specifying the path:
```bat
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\5.15.2\mingw81_64"
```
Replace `5.15.2` and `mingw81_64` with whatever version/folder you see inside `C:\Qt\`.

---

### "mingw32-make is not recognized"
You're not in the Qt MinGW terminal. Close the window and open:  
**Start Menu → Qt 5.15.x → Qt 5.15.x MinGW 8.1.0 64-bit**

---

### The .exe opens and immediately closes
Qt DLLs are missing. Run:
```bat
cd build
"C:\Qt\5.15.2\mingw81_64\bin\windeployqt.exe" TraceLen.exe
```
Then try again.

---

### "The application was unable to start (0xc000007b)"
This means a 32-bit DLL was mixed with a 64-bit .exe (or vice versa).
Make sure you used the **64-bit** MinGW toolchain (`mingw81_64`, not `mingw81_32`).
Delete the `build\` folder and redo Steps 4–5.

---

### "Access Denied" when monitoring certain processes
Some system processes (like `System`, `lsass.exe`, antivirus) require
Administrator privileges to be queried. Run the app as Administrator.

---

### No events appearing after clicking Start
1. Make sure you added a directory (click **+ Add Directory**)
2. Check that the directory you added actually exists
3. Try creating, editing, or deleting a file inside the watched directory
4. File events (Write, Delete, Rename) appear immediately
5. Process/Network events appear within the poll interval (default 1 second)

---

## Building a Distributable Package

After building, the `build\` folder (after running windeployqt) is self-contained.
To share the app with others:

1. Run windeployqt as shown above
2. Zip the entire `build\` folder
3. The other user just extracts and double-clicks `TraceLen.exe`
   (no Qt installation needed on their machine)

---

## Quick Reference

| Command | What it does |
|---------|-------------|
| `cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\5.15.2\mingw81_64"` | Generate build files |
| `mingw32-make -j4` | Compile the project |
| `windeployqt TraceLen.exe` | Copy required Qt DLLs |
| `TraceLen.exe` | Run the application |

