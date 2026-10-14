# TraceLen

**Real-time process, file, registry, DNS, and network activity monitor for Windows.**

A desktop tool that shows *which process* did *what* — with paths, users, signatures, connection history, and traffic estimates — in a single Qt UI.

[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](#requirements)
[![Qt](https://img.shields.io/badge/Qt-5%20%2F%206-green.svg)](#build)
[![License](https://img.shields.io/badge/license-see%20repo-lightgrey.svg)](#license)

---


## About

This project was built primarily with AI assistance (end-to-end design, implementation, and etc..). Human review and testing are still recommended before production use.

## Why this exists

Most Windows monitors specialize in one layer:

| Tool | Strength | Gap |
|------|----------|-----|
| **Process Monitor (ProcMon)** | Deep file/registry/process traces | Heavy ETL workflow; limited live network “behavior” view |
| **TCPView / Resource Monitor** | Connections & bandwidth | Weak process timeline / file / DNS correlation |
| **Wireshark** | Packet detail | Not process-centric for everyday investigation |
| **Sysmon** | Durable security logging | Config-heavy; not an interactive live UI |

**TraceLen** aims at the middle ground: **live investigation UI** with **process-centric** file, registry, DNS, and network views — including session connection history and coarse download/upload classification — without requiring a separate analysis toolchain for everyday use.

---

## Features

### Capture (live)

- **Processes** — start / stop, parent process, command line (when available)
- **Files** — create, write, rename, delete; open/read/query with Administrator + ETW
- **Registry** — create/set/delete/rename (Administrator + ETW)
- **DNS** — queries and results tied to the requesting process (Administrator + ETW)
- **Network** — connects, listens, live connect/disconnect (ETW); TCP/UDP tables for endpoints

### Investigation UI

- Flat event table with **search** (per column or all), **type filter**, ignore list
- **Group by process** tree (expand/collapse, icons, selection preserved across updates)
- **Statistics** — counts by process, by process name, by event type; open a **snapshot** of all events of one type
- **Process detail** window — events for one PID, children, timeline
- Double-click / Enter opens details; subwindows get **separate taskbar** entries

### Network window

- **Per process** and **per process + remote host** traffic views  
- **Connection history** (live vs disconnected), duration, optional In/Out when Admin  
- **Listening ports**  
- Hostname enrichment from DNS events + optional reverse lookup  
- Status-bar **network totals** (↓ / ↑) when elevated  

> **Note:** Accurate per-connection byte sizes use Windows TCP EStats and work reliably **as Administrator**. Without Admin, connection lists still work; size totals are disabled so numbers do not look random.

### Persistence & performance

- Save / load event logs (JSON); load runs in the **background** with progress  
- Optional **continuous event backup** file (timestamped `.jsonl` next to the app)  
- Filter **presets**, auto-saved **UI preferences** (checkboxes, columns, widths)  
- Caps and debouncing so large logs (tens of thousands of events) stay usable  

---

## Architecture (short)

```
┌─────────────┐   ETW (Admin)    ┌──────────────────┐
│  Kernel /   │ ───────────────► │ EtwFileWatcher   │
│  providers  │                  │ EtwRegistryDns…  │──┐
└─────────────┘                  └──────────────────┘  │
                                                       ▼
┌─────────────┐   directory watch ┌──────────────────┐  ┌────────────┐
│  Folders    │ ───────────────► │ FileWatcher      │─►│ ActivityLog │─► UI / JSON
└─────────────┘   (optional)     └──────────────────┘  └────────────┘
                                                          ▲
┌─────────────┐   TCP/UDP tables ┌──────────────────┐     │
│  IP Helper  │ ───────────────► │ SystemMonitor /  │─────┘
│  + EStats   │                  │ NetworkBehavior  │
└─────────────┘                  └──────────────────┘
```

- **Administrator:** system-wide ETW + reliable traffic sizes  
- **Standard user:** process/network snapshots + **folder watch list** for local file changes  

---

## Requirements

- **Windows 10 / 11** (x64)
- **Qt 5.15+** or **Qt 6** (Core, Widgets, Network)
- **MinGW** or MSVC toolchain matching your Qt kit  
- **Administrator** recommended for full file/registry/DNS/ETW and accurate network sizes  

---

## Build

```bat
mkdir build
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\6.11.2\mingw_64"
cmake --build . -j4
windeployqt TraceLen.exe
```

See [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) for more detail.

---

## Usage

1. Prefer **Run as administrator** for full visibility.  
2. Turn on the event types you care about in **What to capture**.  
3. Click **Start**.  
4. Use **Search**, **event type**, and **Group by process** to narrow the list.  
5. Open **Statistics** or **Network** for aggregates and connection history.  
6. **Save** a log, or enable **Keep a backup file of events** for a continuous `.jsonl` backup.

Without Admin, add folders under **Which folders should report file activity?** if you need file-change events in specific directories.

---

## Configuration files (next to the executable)

| File | Purpose |
|------|---------|
| `ui_preferences.json` | Checkboxes, column visibility/widths, options (auto-saved) |
| `filter_presets.json` | Named capture presets |
| `TraceLen_events_*.jsonl` | Optional continuous event backup |

---

## How it differs (summary)

- **Interactive first** — built for live triage, not only offline ETL review  
- **Cross-domain** — process + file + registry + DNS + network in one place  
- **Network session view** — history, listeners, and coarse behavior labels, not only a socket table  
- **Portable prefs** — JSON beside the binary; easy to carry with a USB build  
- **Honest limits** — Admin vs non-Admin capabilities and traffic accuracy are explicit in the UI  

---

## Limitations

- Not a packet capture tool (use Wireshark for payload-level analysis)  
- Not a boot-time logger out of the box (use Windows Autologger + ETL for early boot)  
- In-memory event list is capped for UI responsiveness; use save/backup for long runs  
- UDP traffic volume is not fully represented in byte totals (EStats is TCP-oriented)  

---

## Project layout

```
src/
  main.cpp / MainWindow.*     UI shell
  ActivityLog.*               Event store + JSON
  EtwFileWatcher.*            File / process ETW
  EtwRegistryDnsWatcher.*     Registry + DNS ETW
  FileWatcher.*               Directory change notifications
  SystemMonitor.*             Polling process / TCP tables
  NetworkBehaviorMonitor.*    Traffic + connection history
  ProcessInfoWorker.*         Path, publisher, signature
  …
```

---

## Contributing

Issues and PRs focused on correctness, performance under large logs, and clearer UX are welcome. Please describe OS build, Admin vs non-Admin, and steps to reproduce.

---


