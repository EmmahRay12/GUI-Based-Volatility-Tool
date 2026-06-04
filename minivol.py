#!/usr/bin/env python3
"""
MiniVol - Simplified Memory Forensics Tool
Inspired by Volatility Framework

Usage:
    python minivol.py pslist
    python minivol.py pstree
    python minivol.py netscan
    python minivol.py dlllist [--pid PID]
    python minivol.py malfind
    python minivol.py report [--format json|txt]
    python minivol.py info
"""

import os
import sys
import json
import time
import platform
import datetime
import argparse
import subprocess
import hashlib
import socket
import struct
import psutil
import pandas as pd
from colorama import init, Fore, Back, Style

init(autoreset=True)

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────

VERSION = "1.0.0"
TOOL_NAME = "MiniVol"

BANNER = f"""
{Fore.GREEN}
  __  __ _       _ __   __    _ 
 |  \\/  (_)_ __ (_)\\ \\ / /__ | |
 | |\\/| | | '_ \\| | \\ V / _ \\| |
 | |  | | | | | | |  | | (_) | |
 |_|  |_|_|_| |_|_|  |_|\\___/|_|
{Style.RESET_ALL}
{Fore.CYAN}  Memory Forensics Tool v{VERSION}{Style.RESET_ALL}
{Fore.YELLOW}  Inspired by Volatility Framework{Style.RESET_ALL}
{Fore.WHITE}  Educational Use Only{Style.RESET_ALL}
{'─' * 45}
"""

# Suspicious process names (common malware names / indicators)
SUSPICIOUS_NAMES = {
    "mimikatz", "meterpreter", "nc", "netcat", "ncat",
    "psexec", "pwdump", "fgdump", "wce", "gsecdump",
    "procdump", "lsass", "cmd", "powershell", "wscript",
    "cscript", "mshta", "regsvr32", "rundll32", "svchost",
    "conhost", "dllhost", "taskhost", "msconfig", "regedit",
    "keylogger", "rootkit", "backdoor", "rat", "trojan",
    "cryptominer", "xmrig", "minerd", "nssm", "wmihost",
}

# Known safe system processes
KNOWN_SAFE = {
    "system", "idle", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "explorer.exe", "dwm.exe",
    "taskmgr.exe", "searchindexer.exe", "spoolsv.exe",
}

# Network ports considered suspicious
SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 8080, 9001, 9002, 6667, 6666,
    5555, 2222, 12345, 54321, 1234, 9999, 7777,
}

# ─────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{Fore.CYAN}{'═' * 55}")
    print(f"  {Fore.GREEN}{title}")
    print(f"{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}")

def print_row(label: str, value, color=Fore.WHITE):
    print(f"  {Fore.YELLOW}{label:<20}{color}{value}{Style.RESET_ALL}")

def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_file_hash(filepath: str) -> str:
    """Calculate MD5 hash of a file."""
    try:
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"

# ─────────────────────────────────────────────
#  MODULE 1: SYSTEM INFO
# ─────────────────────────────────────────────

class SystemInfo:
    """Gather live system and memory information."""

    @staticmethod
    def collect() -> dict:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time

        return {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown",
            "python_version": platform.python_version(),
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": str(uptime).split(".")[0],
            "analysis_time": timestamp(),
            "memory": {
                "total": vm.total,
                "available": vm.available,
                "used": vm.used,
                "percent": vm.percent,
                "total_fmt": format_bytes(vm.total),
                "available_fmt": format_bytes(vm.available),
                "used_fmt": format_bytes(vm.used),
            },
            "swap": {
                "total": swap.total,
                "used": swap.used,
                "percent": swap.percent,
                "total_fmt": format_bytes(swap.total),
                "used_fmt": format_bytes(swap.used),
            },
        }

    @classmethod
    def display(cls):
        info = cls.collect()
        print_header("SYSTEM INFORMATION")
        print_row("Hostname:", info["hostname"])
        print_row("OS:", info["os"])
        print_row("Architecture:", info["architecture"])
        print_row("Boot Time:", info["boot_time"])
        print_row("Uptime:", info["uptime"])
        print_row("Analysis Time:", info["analysis_time"])

        print(f"\n  {Fore.CYAN}── Memory ──────────────────────────────{Style.RESET_ALL}")
        m = info["memory"]
        bar_len = 30
        filled = int(bar_len * m["percent"] / 100)
        bar_color = Fore.RED if m["percent"] > 80 else (Fore.YELLOW if m["percent"] > 60 else Fore.GREEN)
        bar = f"{bar_color}{'█' * filled}{Fore.WHITE}{'░' * (bar_len - filled)}{Style.RESET_ALL}"
        print(f"  {Fore.YELLOW}{'RAM Usage':<20}{Style.RESET_ALL}{bar} {bar_color}{m['percent']}%{Style.RESET_ALL}")
        print_row("Total RAM:", m["total_fmt"])
        print_row("Used RAM:", m["used_fmt"])
        print_row("Available RAM:", m["available_fmt"])

        s = info["swap"]
        print_row("Swap Total:", s["total_fmt"])
        print_row("Swap Used:", s["used_fmt"])


# ─────────────────────────────────────────────
#  MODULE 2: PROCESS LIST (pslist)
# ─────────────────────────────────────────────

class ProcessList:
    """Enumerate all running processes with detailed metadata."""

    SUSPICIOUS_FLAGS = {
        "no_path": "Executable path missing (possible injection)",
        "suspicious_name": "Name matches known malware indicator",
        "high_memory": "Abnormally high memory usage",
        "many_threads": "Unusually high thread count",
        "no_parent": "No parent process (orphan)",
        "hidden_cwd": "CWD in temp/hidden directory",
    }

    @staticmethod
    def collect() -> list:
        processes = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "status",
             "username", "create_time", "num_threads", "memory_percent",
             "memory_info", "cpu_percent", "cwd"]
        ):
            try:
                info = proc.info
                flags = []

                name = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                mem_pct = info.get("memory_percent") or 0
                threads = info.get("num_threads") or 0
                ppid = info.get("ppid") or 0
                cwd = ""
                try:
                    cwd = proc.cwd()
                except Exception:
                    pass

                # Suspicious checks
                if not exe:
                    flags.append("no_path")
                if any(s in name for s in SUSPICIOUS_NAMES):
                    flags.append("suspicious_name")
                if mem_pct > 30:
                    flags.append("high_memory")
                if threads > 200:
                    flags.append("many_threads")
                if ppid == 0 and info["pid"] not in (0, 4):
                    flags.append("no_parent")
                if cwd and any(t in cwd.lower() for t in ["temp", "tmp", "appdata\\local\\temp"]):
                    flags.append("hidden_cwd")

                create_dt = datetime.datetime.fromtimestamp(
                    info.get("create_time") or time.time()
                ).strftime("%Y-%m-%d %H:%M:%S")

                mem_info = info.get("memory_info")
                rss = mem_info.rss if mem_info else 0

                processes.append({
                    "pid": info["pid"],
                    "ppid": ppid,
                    "name": info.get("name") or "N/A",
                    "exe": exe or "N/A",
                    "cmdline": " ".join(info.get("cmdline") or []) or "N/A",
                    "status": info.get("status") or "N/A",
                    "username": info.get("username") or "N/A",
                    "created": create_dt,
                    "threads": threads,
                    "memory_percent": round(mem_pct, 2),
                    "memory_rss": rss,
                    "memory_rss_fmt": format_bytes(rss),
                    "cpu_percent": info.get("cpu_percent") or 0,
                    "cwd": cwd or "N/A",
                    "suspicious": bool(flags),
                    "flags": flags,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return sorted(processes, key=lambda x: x["pid"])

    @classmethod
    def display(cls, filter_suspicious: bool = False):
        processes = cls.collect()
        if filter_suspicious:
            processes = [p for p in processes if p["suspicious"]]

        print_header(f"PROCESS LIST (pslist) — {len(processes)} processes")

        col_fmt = f"  {{:<7}} {{:<7}} {{:<25}} {{:<12}} {{:<10}} {{:<8}} {{}}"
        header = col_fmt.format("PID", "PPID", "Name", "Status", "Threads", "Mem%", "Flags")
        print(f"{Fore.CYAN}{header}")
        print(f"  {'─' * 85}{Style.RESET_ALL}")

        for p in processes:
            flag_str = ",".join(p["flags"]) if p["flags"] else ""
            color = Fore.RED if p["suspicious"] else Fore.WHITE
            sus_marker = f" {Fore.RED}⚠{Style.RESET_ALL}" if p["suspicious"] else ""

            line = col_fmt.format(
                p["pid"],
                p["ppid"],
                (p["name"][:24] if len(p["name"]) > 24 else p["name"]) + sus_marker,
                p["status"],
                p["threads"],
                f"{p['memory_percent']}%",
                f"{Fore.RED}{flag_str}{Style.RESET_ALL}" if flag_str else "",
            )
            print(f"{color}{line}{Style.RESET_ALL}")

        sus_count = sum(1 for p in processes if p["suspicious"])
        print(f"\n  {Fore.YELLOW}Total: {len(processes)} processes  |  "
              f"{Fore.RED}Suspicious: {sus_count}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MODULE 3: PROCESS TREE (pstree)
# ─────────────────────────────────────────────

class ProcessTree:
    """Build and display a parent-child process hierarchy."""

    @staticmethod
    def build() -> dict:
        """Returns dict: {ppid: [child_proc, ...]}"""
        all_procs = {}
        children = {}

        for proc in psutil.process_iter(["pid", "ppid", "name", "status", "memory_percent"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info.get("ppid") or 0
                all_procs[pid] = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": info.get("name") or "?",
                    "status": info.get("status") or "?",
                    "mem_pct": round(info.get("memory_percent") or 0, 1),
                }
                children.setdefault(ppid, []).append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return all_procs, children

    @classmethod
    def display(cls):
        all_procs, children = cls.build()
        print_header("PROCESS TREE (pstree)")

        def _print_tree(pid, prefix="", is_last=True):
            if pid not in all_procs:
                return
            p = all_procs[pid]
            connector = "└── " if is_last else "├── "
            sus = any(s in p["name"].lower() for s in SUSPICIOUS_NAMES)
            color = Fore.RED if sus else Fore.GREEN
            flag = f" {Fore.RED}⚠" if sus else ""
            print(f"  {Fore.WHITE}{prefix}{connector}"
                  f"{color}{p['name']}{Style.RESET_ALL} "
                  f"{Fore.CYAN}[{p['pid']}]{Style.RESET_ALL} "
                  f"{Fore.WHITE}{p['status']} {p['mem_pct']}%{flag}{Style.RESET_ALL}")

            child_pids = children.get(pid, [])
            for i, child_pid in enumerate(child_pids):
                is_last_child = (i == len(child_pids) - 1)
                extension = "    " if is_last else "│   "
                _print_tree(child_pid, prefix + extension, is_last_child)

        # Find root processes (ppid not in all_procs, or ppid=0)
        roots = [pid for pid, p in all_procs.items()
                 if p["ppid"] not in all_procs or p["ppid"] == 0]
        roots = sorted(set(roots))

        for i, root_pid in enumerate(roots):
            is_last = (i == len(roots) - 1)
            _print_tree(root_pid, "", is_last)


# ─────────────────────────────────────────────
#  MODULE 4: DLL / MODULE LIST (dlllist)
# ─────────────────────────────────────────────

class DllList:
    """List loaded shared libraries / DLLs for processes."""

    @staticmethod
    def collect(pid: int = None) -> list:
        results = []
        targets = []

        if pid:
            try:
                targets = [psutil.Process(pid)]
            except psutil.NoSuchProcess:
                print(f"{Fore.RED}  [!] PID {pid} not found.{Style.RESET_ALL}")
                return []
        else:
            targets = list(psutil.process_iter(["pid", "name"]))

        for proc in targets:
            try:
                if isinstance(proc, psutil.Process):
                    p_info = {"pid": proc.pid, "name": proc.name()}
                else:
                    p_info = {"pid": proc.info["pid"], "name": proc.info.get("name", "N/A")}
                    proc = psutil.Process(p_info["pid"])

                maps = proc.memory_maps(grouped=True) if hasattr(proc, "memory_maps") else []
                dlls = []
                for m in maps:
                    path = m.path
                    if path and os.path.isfile(path):
                        ext = os.path.splitext(path)[1].lower()
                        if ext in (".dll", ".so", ".dylib", ".exe", ".sys"):
                            dlls.append({
                                "path": path,
                                "size": format_bytes(os.path.getsize(path)),
                                "md5": get_file_hash(path) if os.path.getsize(path) < 50_000_000 else "skipped",
                            })

                results.append({
                    "pid": p_info["pid"],
                    "name": p_info["name"],
                    "modules": dlls,
                    "module_count": len(dlls),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return results

    @classmethod
    def display(cls, pid: int = None):
        data = cls.collect(pid)
        print_header(f"DLL / MODULE LIST (dlllist){f' — PID {pid}' if pid else ''}")

        for proc_info in data:
            if not proc_info["modules"]:
                continue
            print(f"\n  {Fore.CYAN}PID {proc_info['pid']} — {Fore.GREEN}{proc_info['name']}"
                  f"{Fore.WHITE} ({proc_info['module_count']} modules){Style.RESET_ALL}")
            for dll in proc_info["modules"][:20]:  # limit display
                sus = any(s in dll["path"].lower() for s in ["temp", "tmp", "appdata"])
                color = Fore.YELLOW if sus else Fore.WHITE
                print(f"    {color}• {dll['path']}{Style.RESET_ALL} "
                      f"{Fore.CYAN}[{dll['size']}]{Style.RESET_ALL}")
            if len(proc_info["modules"]) > 20:
                print(f"    {Fore.YELLOW}... and {len(proc_info['modules']) - 20} more{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MODULE 5: NETWORK SCAN (netscan)
# ─────────────────────────────────────────────

class NetworkScan:
    """Enumerate active network connections."""

    PROTO_MAP = {
        psutil.CONN_ESTABLISHED: "ESTABLISHED",
        psutil.CONN_SYN_SENT: "SYN_SENT",
        psutil.CONN_SYN_RECV: "SYN_RECV",
        psutil.CONN_FIN_WAIT1: "FIN_WAIT1",
        psutil.CONN_FIN_WAIT2: "FIN_WAIT2",
        psutil.CONN_TIME_WAIT: "TIME_WAIT",
        psutil.CONN_CLOSE: "CLOSE",
        psutil.CONN_CLOSE_WAIT: "CLOSE_WAIT",
        psutil.CONN_LAST_ACK: "LAST_ACK",
        psutil.CONN_LISTEN: "LISTEN",
        psutil.CONN_CLOSING: "CLOSING",
        psutil.CONN_NONE: "NONE",
    }

    @staticmethod
    def collect() -> list:
        connections = []
        pid_names = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[proc.info["pid"]] = proc.info.get("name", "N/A")
            except Exception:
                pass

        try:
            all_conns = psutil.net_connections(kind="all")
        except psutil.AccessDenied:
            all_conns = psutil.net_connections(kind="inet")

        for conn in all_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid = conn.pid or 0
            proc_name = pid_names.get(pid, "N/A")
            status = conn.status or "N/A"

            # Suspicious checks
            suspicious = False
            flags = []
            if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                suspicious = True
                flags.append(f"suspicious_port:{conn.raddr.port}")
            if conn.laddr and conn.laddr.port in SUSPICIOUS_PORTS:
                suspicious = True
                flags.append(f"suspicious_listen_port:{conn.laddr.port}")

            # Check if remote IP is unusual (very basic)
            if conn.raddr:
                ip = conn.raddr.ip
                # Flag connections to raw IPs on common C2 ports
                if status == "ESTABLISHED" and conn.raddr.port in SUSPICIOUS_PORTS:
                    flags.append("possible_c2")
                    suspicious = True

            connections.append({
                "pid": pid,
                "process": proc_name,
                "local": laddr,
                "remote": raddr,
                "status": status,
                "family": "IPv6" if conn.family == socket.AF_INET6 else "IPv4",
                "type": "UDP" if conn.type == socket.SOCK_DGRAM else "TCP",
                "suspicious": suspicious,
                "flags": flags,
            })

        return sorted(connections, key=lambda x: (x["suspicious"], x["status"]), reverse=True)

    @classmethod
    def display(cls):
        connections = cls.collect()
        print_header(f"NETWORK CONNECTIONS (netscan) — {len(connections)} connections")

        fmt = "  {:<7} {:<22} {:<22} {:<16} {:<8} {:<6} {}"
        header = fmt.format("PID", "Local Address", "Remote Address", "Status", "Proto", "Family", "Process")
        print(f"{Fore.CYAN}{header}")
        print(f"  {'─' * 95}{Style.RESET_ALL}")

        for conn in connections:
            color = Fore.RED if conn["suspicious"] else Fore.WHITE
            flag_str = " ⚠ " + ",".join(conn["flags"]) if conn["flags"] else ""
            line = fmt.format(
                conn["pid"],
                conn["local"][:21],
                conn["remote"][:21],
                conn["status"][:15],
                conn["type"],
                conn["family"],
                conn["process"][:20],
            )
            print(f"{color}{line}{Fore.RED}{flag_str}{Style.RESET_ALL}")

        sus = sum(1 for c in connections if c["suspicious"])
        print(f"\n  {Fore.YELLOW}Total: {len(connections)} connections  |  "
              f"{Fore.RED}Suspicious: {sus}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MODULE 6: MALWARE DETECTION (malfind)
# ─────────────────────────────────────────────

class MalwareDetector:
    """Heuristic-based malware / anomaly detection."""

    @staticmethod
    def analyze() -> dict:
        report = {
            "suspicious_processes": [],
            "suspicious_connections": [],
            "orphan_processes": [],
            "high_privilege_unusual": [],
            "temp_executables": [],
            "multiple_instance_anomalies": [],
            "analysis_time": timestamp(),
        }

        processes = ProcessList.collect()
        connections = NetworkScan.collect()
        pid_map = {p["pid"]: p for p in processes}

        # Count process names for multiple-instance detection
        name_count = {}
        for p in processes:
            name_count[p["name"]] = name_count.get(p["name"], 0) + 1

        # Single-instance system processes (should only appear once)
        SINGLE_INSTANCE = {
            "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
            "services.exe", "winlogon.exe",
        }

        for p in processes:
            # Already flagged as suspicious
            if p["suspicious"]:
                report["suspicious_processes"].append({
                    "pid": p["pid"],
                    "name": p["name"],
                    "reason": p["flags"],
                    "exe": p["exe"],
                    "user": p["username"],
                })

            # Orphan processes (ppid doesn't exist)
            if p["ppid"] and p["ppid"] not in pid_map and p["pid"] > 4:
                report["orphan_processes"].append({
                    "pid": p["pid"],
                    "name": p["name"],
                    "claimed_ppid": p["ppid"],
                })

            # Executable in temp directory
            if p["exe"] and any(t in p["exe"].lower() for t in ["temp", "tmp", "\\appdata\\"]):
                report["temp_executables"].append({
                    "pid": p["pid"],
                    "name": p["name"],
                    "exe": p["exe"],
                })

            # Multiple instances of single-instance processes
            if p["name"].lower() in SINGLE_INSTANCE and name_count[p["name"]] > 1:
                report["multiple_instance_anomalies"].append({
                    "name": p["name"],
                    "count": name_count[p["name"]],
                    "pid": p["pid"],
                    "note": "Should only have 1 instance on Windows",
                })

        # Suspicious network connections
        for conn in connections:
            if conn["suspicious"]:
                report["suspicious_connections"].append(conn)

        return report

    @classmethod
    def display(cls):
        print_header("MALWARE DETECTION (malfind)")
        report = cls.analyze()

        sections = [
            ("suspicious_processes", "⚠  Suspicious Processes", "pid", ["pid", "name", "reason", "exe"]),
            ("orphan_processes", "👻 Orphan Processes", "pid", ["pid", "name", "claimed_ppid"]),
            ("temp_executables", "📁 Executables in Temp/AppData", "pid", ["pid", "name", "exe"]),
            ("multiple_instance_anomalies", "🔁 Multiple Instance Anomalies", "name", ["name", "count", "pid", "note"]),
            ("suspicious_connections", "🌐 Suspicious Network Connections", "pid", ["pid", "process", "local", "remote", "flags"]),
        ]

        total_findings = 0
        for key, title, sort_key, fields in sections:
            items = report.get(key, [])
            color = Fore.RED if items else Fore.GREEN
            status = f"{len(items)} found" if items else "None detected ✓"
            print(f"\n  {Fore.YELLOW}{title}{Style.RESET_ALL}")
            print(f"  {color}{status}{Style.RESET_ALL}")
            if items:
                total_findings += len(items)
                for item in items[:10]:
                    parts = []
                    for f in fields:
                        val = item.get(f, "")
                        if isinstance(val, list):
                            val = ", ".join(str(v) for v in val)
                        parts.append(f"{f}={val}")
                    print(f"    {Fore.RED}→ {Fore.WHITE}{' | '.join(parts)}{Style.RESET_ALL}")

        risk = "HIGH" if total_findings > 5 else ("MEDIUM" if total_findings > 2 else ("LOW" if total_findings > 0 else "CLEAN"))
        risk_color = Fore.RED if risk == "HIGH" else (Fore.YELLOW if risk in ("MEDIUM", "LOW") else Fore.GREEN)

        print(f"\n  {'─' * 50}")
        print(f"  {Fore.YELLOW}Risk Level: {risk_color}{risk}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Total Findings: {Fore.WHITE}{total_findings}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MODULE 7: REPORT GENERATION
# ─────────────────────────────────────────────

class ReportGenerator:
    """Generate structured forensic reports in JSON or TXT format."""

    @staticmethod
    def build_report() -> dict:
        print(f"{Fore.CYAN}  [*] Collecting system information...{Style.RESET_ALL}")
        sys_info = SystemInfo.collect()

        print(f"{Fore.CYAN}  [*] Enumerating processes...{Style.RESET_ALL}")
        processes = ProcessList.collect()

        print(f"{Fore.CYAN}  [*] Scanning network connections...{Style.RESET_ALL}")
        connections = NetworkScan.collect()

        print(f"{Fore.CYAN}  [*] Running malware detection...{Style.RESET_ALL}")
        malware = MalwareDetector.analyze()

        suspicious_procs = [p for p in processes if p["suspicious"]]
        suspicious_conns = [c for c in connections if c["suspicious"]]

        risk_score = (
            len(suspicious_procs) * 3 +
            len(suspicious_conns) * 5 +
            len(malware.get("orphan_processes", [])) * 2 +
            len(malware.get("temp_executables", [])) * 4 +
            len(malware.get("multiple_instance_anomalies", [])) * 6
        )

        risk = "HIGH" if risk_score > 20 else ("MEDIUM" if risk_score > 8 else ("LOW" if risk_score > 0 else "CLEAN"))

        return {
            "report_metadata": {
                "tool": "MiniVol",
                "version": VERSION,
                "generated_at": timestamp(),
                "analyst": os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown",
            },
            "system_info": sys_info,
            "risk_assessment": {
                "level": risk,
                "score": risk_score,
                "suspicious_process_count": len(suspicious_procs),
                "suspicious_connection_count": len(suspicious_conns),
            },
            "processes": {
                "total": len(processes),
                "suspicious_count": len(suspicious_procs),
                "all": processes,
                "suspicious": suspicious_procs,
            },
            "network": {
                "total": len(connections),
                "suspicious_count": len(suspicious_conns),
                "all": connections,
                "suspicious": suspicious_conns,
            },
            "malware_findings": malware,
        }

    @classmethod
    def save(cls, fmt: str = "json", output_dir: str = ".") -> str:
        print_header("REPORT GENERATION")
        report = cls.build_report()

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

        if fmt == "json":
            filename = os.path.join(output_dir, f"minivol_report_{ts}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)

        elif fmt == "txt":
            filename = os.path.join(output_dir, f"minivol_report_{ts}.txt")
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"{'=' * 60}\n")
                f.write(f"  MINIVOL FORENSIC REPORT v{VERSION}\n")
                f.write(f"  Generated: {report['report_metadata']['generated_at']}\n")
                f.write(f"{'=' * 60}\n\n")

                si = report["system_info"]
                f.write("[SYSTEM INFO]\n")
                f.write(f"  Hostname   : {si['hostname']}\n")
                f.write(f"  OS         : {si['os']} {si['os_version']}\n")
                f.write(f"  Arch       : {si['architecture']}\n")
                f.write(f"  Boot Time  : {si['boot_time']}\n")
                f.write(f"  RAM Total  : {si['memory']['total_fmt']}\n")
                f.write(f"  RAM Used   : {si['memory']['used_fmt']} ({si['memory']['percent']}%)\n\n")

                ra = report["risk_assessment"]
                f.write("[RISK ASSESSMENT]\n")
                f.write(f"  Risk Level : {ra['level']}\n")
                f.write(f"  Risk Score : {ra['score']}\n")
                f.write(f"  Suspicious Processes  : {ra['suspicious_process_count']}\n")
                f.write(f"  Suspicious Connections: {ra['suspicious_connection_count']}\n\n")

                f.write("[PROCESSES]\n")
                f.write(f"  {'PID':<7} {'PPID':<7} {'Name':<25} {'Status':<12} {'Mem%':<8} Flags\n")
                f.write(f"  {'-' * 80}\n")
                for p in report["processes"]["all"]:
                    flags = ",".join(p["flags"]) if p["flags"] else ""
                    f.write(f"  {p['pid']:<7} {p['ppid']:<7} {p['name']:<25} {p['status']:<12} "
                            f"{p['memory_percent']:<8} {flags}\n")

                f.write("\n[NETWORK CONNECTIONS]\n")
                f.write(f"  {'PID':<7} {'Local':<22} {'Remote':<22} {'Status':<16} {'Type':<6} Process\n")
                f.write(f"  {'-' * 90}\n")
                for c in report["network"]["all"]:
                    flags = ",".join(c["flags"]) if c["flags"] else ""
                    f.write(f"  {c['pid']:<7} {c['local']:<22} {c['remote']:<22} "
                            f"{c['status']:<16} {c['type']:<6} {c['process']} {flags}\n")

                f.write("\n[MALWARE FINDINGS]\n")
                mf = report["malware_findings"]
                for key in ["suspicious_processes", "orphan_processes", "temp_executables",
                            "multiple_instance_anomalies", "suspicious_connections"]:
                    items = mf.get(key, [])
                    f.write(f"\n  [{key.upper()}] — {len(items)} found\n")
                    for item in items:
                        f.write(f"    {item}\n")

        elif fmt == "csv":
            filename = os.path.join(output_dir, f"minivol_report_{ts}.csv")
            df = pd.DataFrame(report["processes"]["all"])
            df.to_csv(filename, index=False)

        else:
            print(f"{Fore.RED}  [!] Unknown format: {fmt}. Use json, txt, or csv.{Style.RESET_ALL}")
            return ""

        print(f"\n  {Fore.GREEN}✓ Report saved: {Fore.WHITE}{filename}{Style.RESET_ALL}")
        risk = report["risk_assessment"]
        risk_color = Fore.RED if risk["level"] == "HIGH" else (Fore.YELLOW if risk["level"] in ("MEDIUM", "LOW") else Fore.GREEN)
        print(f"  {Fore.YELLOW}Risk Level: {risk_color}{risk['level']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Risk Score: {Fore.WHITE}{risk['score']}{Style.RESET_ALL}")
        return filename


# ─────────────────────────────────────────────
#  CLI INTERFACE
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minivol",
        description=f"{TOOL_NAME} v{VERSION} — Simplified Memory Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  info          Show system and memory information
  pslist        List all running processes
  pstree        Display process hierarchy tree
  netscan       Enumerate network connections
  dlllist       List loaded DLLs / modules
  malfind       Run malware/anomaly detection
  report        Generate full forensic report

Examples:
  python minivol.py info
  python minivol.py pslist --suspicious
  python minivol.py dlllist --pid 1234
  python minivol.py report --format json --output ./reports
  python minivol.py report --format txt
        """,
    )

    parser.add_argument("command", choices=["info", "pslist", "pstree", "netscan", "dlllist", "malfind", "report"],
                        help="Command to run")
    parser.add_argument("--pid", type=int, help="Filter by process ID (for dlllist)")
    parser.add_argument("--suspicious", action="store_true", help="Show only suspicious entries")
    parser.add_argument("--format", choices=["json", "txt", "csv"], default="json",
                        help="Report output format (default: json)")
    parser.add_argument("--output", default=".", help="Output directory for reports (default: current dir)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    return parser


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        return

    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    cmd = args.command

    if cmd == "info":
        SystemInfo.display()
    elif cmd == "pslist":
        ProcessList.display(filter_suspicious=args.suspicious)
    elif cmd == "pstree":
        ProcessTree.display()
    elif cmd == "netscan":
        NetworkScan.display()
    elif cmd == "dlllist":
        DllList.display(pid=args.pid)
    elif cmd == "malfind":
        MalwareDetector.display()
    elif cmd == "report":
        ReportGenerator.save(fmt=args.format, output_dir=args.output)

    print(f"\n{Fore.CYAN}{'─' * 45}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  [MiniVol] Analysis complete — {timestamp()}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
