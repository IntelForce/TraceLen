# Investigating a TraceLen crash

This guide covers two ways to find out why the app crashed: what Windows already
records (works with any build, no code changes), and what the new version writes
itself.

## Part 1 — What Windows already recorded (do this first)

Windows logs every application crash, even when the app shows nothing.

1. Press **Win + R**, type `eventvwr.msc`, press Enter.
2. Go to **Windows Logs → Application**.
3. Look for entries with **Source = Application Error** (Event ID **1000**), and
   **Source = Windows Error Reporting** (Event ID **1001**), dated at the crash.
4. Open the Event ID 1000 entry. The **General** text contains:
   - **Faulting application name**: `TraceLen.exe` (confirms it's us)
   - **Faulting module name**: the DLL or EXE where the crash happened
   - **Exception code**: what kind of crash it was (table below)
   - **Fault offset**: the position inside that module

### What the exception code means

| Code | Meaning | What usually causes it here |
|------|---------|------------------------------|
| `c0000005` | Access violation | Using an object after it was deleted, or a bad pointer |
| `c00000fd` | Stack overflow | Runaway recursion |
| `c0000409` | Stack buffer overrun / fast-fail | Memory corruption caught by Windows |
| `c0000374` | Heap corruption | A write past the end of an allocation |
| `e06d7363` | Uncaught C++ exception | An exception nothing caught |

### What the faulting module tells you

- **`TraceLen.exe`**: the bug is in our code. Note the fault offset.
- **`Qt5Widgets.dll` / `Qt5Core.dll` / `Qt6*.dll`**: usually our code calling Qt
  wrongly (for example, deleting a widget while it is still handling a click).
- **`ntdll.dll`, `KERNELBASE.dll`**: often memory corruption from our code; the
  real cause is earlier than the crash.

A crash with a **Qt** module and an access violation right after a filter or
button action matches the filter-removal bug fixed in this version.

## Part 2 — Files the new version writes

Folder: `%LOCALAPPDATA%\TraceLen\logs\`
(Paste that into the Explorer address bar.)

| File | What it is |
|------|------------|
| `session_YYYYMMDD_HHMMSS.log` | Everything from one run: Qt warnings and errors with source file and line, and every user action. Flushed line by line, so the last line before a crash is on disk. |
| `crash_YYYYMMDD_HHMMSS.txt` | Written at the crash: exception name and code, faulting address and module, the recent actions, app/Qt/OS versions. |
| `crash_YYYYMMDD_HHMMSS.dmp` | Minidump of the crashing process. Open it in Visual Studio to see the exact stack. |

When the app starts after a crash, the status bar says the app closed
unexpectedly and gives this folder. The same notice appears after an
"End task" in Task Manager or a power cut, because the app cannot tell those apart.

### Reading the session log before a crash

Open the newest `session_*.log` and look at the **last 20 lines**:

- `[action] ...` lines show what you did most recently.
- `WARN` and `ERROR` lines are Qt messages, for example warnings about widgets or
  invalid regular expressions.
- A final `CRASH exception ...` line means the crash handler ran.
- No `=== session end (clean) ===` line and no `CRASH` line means the app was
  killed from outside (Task Manager, power loss, or a freeze followed by a kill).

### Opening the minidump

1. Install **Visual Studio** (Community is free) with the **Desktop development
   with C++** workload.
2. **File → Open → File**, choose the `.dmp` file.
3. On the summary page, click **Debug with Native Only**.
4. The **Call Stack** window shows the crashing function. Use the
   `TraceLen.exe` build that matches the crash (same version, same build).
   Debug symbols (`.pdb`) must come from the same build, so keep the `.pdb` that
   CMake produces next to the `.exe`.

## Part 3 — Turn on Windows crash dumps for every app (optional)

If Part 1 is not enough and you want dumps even when the app's own handler does
not run, enable Windows Error Reporting local dumps. Run this in an
**administrator** Command Prompt:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\TraceLen.exe" /v DumpFolder /t REG_EXPAND_SZ /d "C:\CrashDumps" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\TraceLen.exe" /v DumpType /t REG_DWORD /d 2 /f
```

Create `C:\CrashDumps` first. Dumps then appear there for `TraceLen.exe`
crashes, even if the app itself never got to write one. Remove the keys when done:

```
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\TraceLen.exe" /f
```

## Part 4 — Reproducing "too many filters"

1. Start the app, let it capture for a minute.
2. Add filters one at a time, noting when it starts to lag.
3. Note the number of filters and the number of rows in the table (status bar).
4. Check the `session_*.log` for `WARN`/`ERROR` lines at that moment.

If a crash happens during this, the `.txt` report names the module and the
breadcrumbs show the exact sequence of filter actions that led to it.
