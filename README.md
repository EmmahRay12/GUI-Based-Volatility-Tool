# MiniVol — Simplified Memory Forensics Tool
**Inspired by Volatility Framework | v1.0.0 | Educational Use Only**

---

## Quick Start

### Install dependencies
```bash
pip install -r requirements.txt
```

### CLI Mode
```bash
python minivol.py info              # System + RAM info
python minivol.py pslist            # All running processes
python minivol.py pslist --suspicious   # Only suspicious processes
python minivol.py pstree            # Process tree (parent → child)
python minivol.py netscan           # Network connections
python minivol.py dlllist           # All loaded DLLs/modules
python minivol.py dlllist --pid 1234    # DLLs for specific PID
python minivol.py malfind           # Malware/anomaly detection
python minivol.py report            # Generate JSON report (default)
python minivol.py report --format txt   # Text report
python minivol.py report --format csv   # CSV report
python minivol.py report --output ./reports  # Save to folder
```

### Web UI Mode
```bash
python minivol_web.py
# Open: http://localhost:5000
```

---

## Features

| Module       | Command     | Description                                  |
|-------------|-------------|----------------------------------------------|
| System Info  | `info`      | RAM, OS, uptime, hostname                    |
| Process List | `pslist`    | PID, PPID, name, status, memory, flags       |
| Process Tree | `pstree`    | Parent-child hierarchy                       |
| Network Scan | `netscan`   | TCP/UDP connections, remote IPs, ports       |
| DLL List     | `dlllist`   | Loaded libraries per process                 |
| Mal Find     | `malfind`   | Heuristic malware/anomaly detection          |
| Report       | `report`    | Full forensic report (JSON / TXT / CSV)      |

---

## Malware Detection Heuristics

MiniVol detects the following suspicious indicators:

- **Suspicious process names** — known malware/tool names
- **Processes with no executable path** — possible code injection
- **High memory usage** — > 30% RAM usage
- **Excessive threads** — > 200 threads
- **Orphan processes** — parent PID doesn't exist
- **Temp directory executables** — running from %TEMP%, AppData
- **Multiple instances of single-instance processes** — lsass.exe, csrss.exe, etc.
- **Suspicious network ports** — C2 common ports: 4444, 1337, 31337, etc.
- **Possible C2 connections** — ESTABLISHED connections on suspicious ports

---

## Project Structure

```
minivol/
├── minivol.py          # Core library + CLI entry point
├── minivol_web.py      # Flask web server for GUI
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Technologies Used

| Component   | Library/Tool     |
|------------|------------------|
| Language   | Python 3.8+      |
| Processes  | psutil           |
| Web UI     | Flask + Vanilla JS |
| Data       | pandas           |
| CLI Colors | colorama         |
| Reports    | json, csv        |

---

## Disclaimer

This tool is intended for **educational and academic purposes only**.
Use only on systems you own or have explicit permission to analyze.
Do not use for unauthorized access or illegal activities.

---

*MiniVol — Making memory forensics accessible for students and beginners*
