"""Process monitoring utilities for CyberToolkit.

Relies on ``psutil`` to gather information about running processes and
basic system statistics.  Each process record includes pid, name, CPU
and memory usage, status, username and executable path.  A separate
check identifies suspicious processes based on several heuristics.

Functions
---------

* ``get_all_processes()``
* ``get_suspicious_processes()``
* ``get_system_stats()``

"""

from __future__ import annotations

import os
from datetime import datetime
from typing import List, Dict, Any

import psutil

_TEMP_DIRS = {os.environ.get("TEMP", ""), os.environ.get("TMP", "")}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _safe_proc_iter():
    """Generator wrapping psutil.process_iter to handle disappearing procs."""
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                     'memory_percent', 'status',
                                     'username', 'exe']):
        try:
            yield proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def _is_suspicious(proc_info: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    # high CPU usage
    if proc_info.get('cpu_percent', 0) > 80:
        reasons.append('high cpu usage')
    exe = proc_info.get('exe_path') or ''
    if exe:
        exe_lower = exe.lower()
        # executable in temp folder
        for td in _TEMP_DIRS:
            if td and exe_lower.startswith(td.lower()):
                reasons.append('running from temp directory')
                break
        # no publisher info is not available via psutil; treat missing
        # executable or non-existent as suspicious
        if not os.path.exists(exe):
            reasons.append('executable missing')
    else:
        reasons.append('no executable path')
    return reasons


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def get_all_processes() -> List[Dict[str, Any]]:
    """Return a list of all running processes sorted by CPU usage.

    Each entry contains pid, name, cpu_percent, memory_percent, status,
    username and exe_path.
    """

    procs: List[Dict[str, Any]] = []
    for proc in _safe_proc_iter():
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        procs.append({
            'pid': info.get('pid'),
            'name': info.get('name'),
            'cpu_percent': info.get('cpu_percent'),
            'memory_percent': info.get('memory_percent'),
            'status': info.get('status'),
            'username': info.get('username'),
            'exe_path': info.get('exe'),
        })
    # sort descending by cpu
    procs.sort(key=lambda p: p.get('cpu_percent', 0) or 0, reverse=True)
    return procs


def get_suspicious_processes() -> List[Dict[str, Any]]:
    """Return only processes flagged as suspicious.

    Each entry includes the same fields as :func:`get_all_processes` plus a
    ``reasons`` list explaining why it was flagged.
    """

    suspicious = []
    for proc in get_all_processes():
        reasons = _is_suspicious(proc)
        if reasons:
            proc_copy = proc.copy()
            proc_copy['reasons'] = reasons
            suspicious.append(proc_copy)
    return suspicious


def get_system_stats() -> Dict[str, Any]:
    """Return basic system statistics.

    ``total_cpu``: overall CPU percent
    ``total_memory``: percent of RAM used
    ``disk_usage``: dict with ``total``/``used``/``free``/``percent`` for root
    ``boot_time``: isoformatted boot time
    """

    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    boot = datetime.fromtimestamp(psutil.boot_time()).isoformat()

    return {
        'total_cpu': cpu,
        'total_memory': mem,
        'disk_usage': {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent,
        },
        'boot_time': boot,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process monitor tool")
    parser.add_argument('--suspicious', action='store_true',
                        help='show only suspicious processes')
    args = parser.parse_args()
    if args.suspicious:
        for p in get_suspicious_processes():
            print(p)
    else:
        for p in get_all_processes():
            print(p)

