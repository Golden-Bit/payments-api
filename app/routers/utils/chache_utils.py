import json
import os
import tempfile
import contextlib
import logging
import errno
from pathlib import Path
from typing import Dict, Any
import time as _time

# === FILE-CACHE CONFIG ===
FILE_CACHE_PATH = os.getenv("PLANS_FILE_CACHE_PATH", "/tmp/plans_cache.json")
FILE_CACHE_LOCK_PATH = FILE_CACHE_PATH + ".lock"
FILE_CACHE_DIR = os.path.dirname(FILE_CACHE_PATH)
os.makedirs(FILE_CACHE_DIR, exist_ok=True)

_logger = logging.getLogger(__name__)

# --- cross-platform file lock (best-effort) ---
class _FileLock:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def __enter__(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+")
        try:
            try:
                import fcntl  # POSIX
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
                self._unlock = lambda: fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            except ImportError:
                import msvcrt  # Windows
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
                self._unlock = lambda: msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            # fallback: nessun lock (sconsigliato, ma non blocco l'app)
            self._unlock = lambda: None
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._unlock()
        finally:
            try:
                self._fh.close()
            except Exception:
                pass

# --- struttura di default ---
def _default_cache_payload() -> Dict[str, Any]:
    return {"version": 1, "customers": {}, "portal": {}}

def _load_cache_file() -> Dict[str, Any]:
    p = Path(FILE_CACHE_PATH)
    if not p.exists():
        return _default_cache_payload()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("not a dict")
        data.setdefault("version", 1)
        data.setdefault("customers", {})
        data.setdefault("portal", {})
        return data
    except Exception as e:
        # file corrotto → rinomina e reset
        try:
            corrupted = FILE_CACHE_PATH + f".corrupt.{int(_time.time())}"
            os.replace(FILE_CACHE_PATH, corrupted)
            _logger.warning("Cache file corrupted; moved to %s: %s", corrupted, e)
        except Exception:
            pass
        return _default_cache_payload()

def _atomic_write(path: str, payload: Dict[str, Any]) -> None:
    tmpfd, tmppath = tempfile.mkstemp(dir=FILE_CACHE_DIR, prefix=".cache.", suffix=".json")
    try:
        with os.fdopen(tmpfd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmppath, path)
    finally:
        try:
            if os.path.exists(tmppath):
                os.remove(tmppath)
        except Exception:
            pass

def _save_cache_file(data: Dict[str, Any]) -> None:
    _atomic_write(FILE_CACHE_PATH, data)
