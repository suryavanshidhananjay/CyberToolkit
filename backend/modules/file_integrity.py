"""File integrity monitoring for the CyberToolkit backend.

Tracks files and directories, computes SHA-256 hashes, and persists the
results in a JSON database named ``file_hashes.json`` located in the
current working directory.  A background thread can monitor paths at a
30‑second interval; integrity can also be checked on demand.

API
----

* ``start_monitoring(paths: List[str])`` – begin watching given paths.
* ``stop_monitoring()`` – halt the watcher thread.
* ``check_integrity()`` – compare the current hashes to the stored ones
  and return a list of status records.

Returned records are dictionaries with keys ``filepath``, ``status``
(``"modified"``, ``"deleted"``, ``"new"`` or ``"ok"``),
``original_hash``, ``current_hash`` and ``timestamp`` (UTC ISO string).

"""

import hashlib
import json
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

_db_file = "file_hashes.json"
_hash_db: Dict[str, str] = {}

_monitor_paths: List[str] = []
_monitor_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------


def _load_db() -> None:
    global _hash_db
    if os.path.exists(_db_file):
        try:
            with open(_db_file, "r", encoding="utf-8") as f:
                _hash_db = json.load(f)
        except (OSError, ValueError):
            _hash_db = {}
    else:
        _hash_db = {}


def _save_db() -> None:
    try:
        with open(_db_file, "w", encoding="utf-8") as f:
            json.dump(_hash_db, f, indent=2)
    except OSError:
        pass


def _compute_hash(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _scan_paths(paths: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                for fname in files:
                    full = os.path.join(root, fname)
                    try:
                        result[full] = _compute_hash(full)
                    except (OSError, PermissionError):
                        continue
        elif os.path.isfile(p):
            try:
                result[p] = _compute_hash(p)
            except (OSError, PermissionError):
                continue
    return result


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def check_integrity() -> List[Dict[str, Optional[str]]]:
    _load_db()
    current = _scan_paths(_monitor_paths)
    results: List[Dict[str, Optional[str]]] = []

    for path, orig_hash in list(_hash_db.items()):
        if path in current:
            curr_hash = current[path]
            status = "ok" if curr_hash == orig_hash else "modified"
            results.append({
                "filepath": path,
                "status": status,
                "original_hash": orig_hash,
                "current_hash": curr_hash,
                "timestamp": datetime.utcnow().isoformat(),
            })
            del current[path]
        else:
            results.append({
                "filepath": path,
                "status": "deleted",
                "original_hash": orig_hash,
                "current_hash": None,
                "timestamp": datetime.utcnow().isoformat(),
            })

    for path, curr_hash in current.items():
        results.append({
            "filepath": path,
            "status": "new",
            "original_hash": None,
            "current_hash": curr_hash,
            "timestamp": datetime.utcnow().isoformat(),
        })

    return results


def _monitor_loop() -> None:
    while not _stop_event.wait(30.0):
        _load_db()
        current = _scan_paths(_monitor_paths)
        _hash_db.clear()
        _hash_db.update(current)
        _save_db()


def start_monitoring(paths: List[str]) -> None:
    global _monitor_thread, _monitor_paths
    _monitor_paths = [os.path.abspath(p) for p in paths]
    _load_db()
    snapshot = _scan_paths(_monitor_paths)
    _hash_db.update(snapshot)
    _save_db()

    _stop_event.clear()
    thread = threading.Thread(target=_monitor_loop, daemon=True)
    thread.start()
    _monitor_thread = thread


def stop_monitoring() -> None:
    _stop_event.set()
    if _monitor_thread is not None:
        _monitor_thread.join(timeout=5.0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Check file integrity.")
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    args = parser.parse_args()
    start_monitoring(args.paths)
    print(f"Initial scan complete; database stored to '{_db_file}'.")
    print("Use check_integrity() to inspect changes or import this module.")
