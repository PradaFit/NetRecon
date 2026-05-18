"""
Minimal application logger for NetRecon.

Writes rotating logs to ~/.netrecon/logs/netrecon.log so that users can
attach them to bug reports. Logs are intentionally low-detail and avoid
recording targets, payloads, IP addresses, or anything else that could
leak the user's activity.

Use ``get_logger()`` for module-level loggers and ``export_diagnostic_log()``
to copy a sanitized snapshot to a user-chosen destination.
"""

import logging
import os
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOG_DIR = Path.home() / ".netrecon" / "logs"
LOG_FILE = LOG_DIR / "netrecon.log"

_MAX_BYTES = 512 * 1024     # 512 KB per file
_BACKUPS = 2                # netrecon.log, .1, .2
_INITIALIZED = False

# Redact obvious user-identifying tokens from any line we emit to disk.
# Targets, payloads, and arguments should never be passed to the logger
# in the first place, but this is a second line of defence.
#
# The IPv6 pattern intentionally requires at least four colon-separated
# hex groups so it cannot match ordinary log timestamps like ``21:34:56``.
_REDACT_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (
        re.compile(
            r"\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b|\b::[A-Fa-f0-9:]{2,}\b"
        ),
        "<ipv6>",
    ),
    (re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b"), "<email>"),
]


class _RedactingFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # Strip the user's home directory from any embedded paths.
        home = str(Path.home())
        if home and home in msg:
            msg = msg.replace(home, "~")
        for pat, repl in _REDACT_PATTERNS:
            msg = pat.sub(repl, msg)
        return msg


def _init():
    global _INITIALIZED
    if _INITIALIZED:
        return
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        _INITIALIZED = True
        return

    root = logging.getLogger("netrecon")
    root.setLevel(logging.INFO)
    root.propagate = False

    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        try:
            handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=_MAX_BYTES,
                backupCount=_BACKUPS,
                encoding="utf-8",
                delay=True,
            )
            handler.setFormatter(
                _RedactingFormatter(
                    "%(asctime)s %(levelname)s %(name)s: %(message)s"
                )
            )
            root.addHandler(handler)
        except OSError:
            pass

    _INITIALIZED = True


def get_logger(name: str = "netrecon") -> logging.Logger:
    _init()
    if name == "netrecon" or name.startswith("netrecon."):
        return logging.getLogger(name)
    return logging.getLogger("netrecon." + name)


def _system_summary() -> str:
    import platform
    return (
        f"NetRecon diagnostic log\n"
        f"OS       : {platform.system()} {platform.release()} ({platform.machine()})\n"
        f"Python   : {sys.version.split()[0]}\n"
        f"Executable: {os.path.basename(sys.executable)}\n"
        f"---- log start ----\n"
    )


def export_diagnostic_log(dest_path: str) -> bool:
    """
    Copy the current log file (plus rotated backups) to ``dest_path``.

    Returns True on success. The destination receives a single combined
    text file with a sanitized system summary header. No environment
    variables, no full paths, no credentials.
    """
    _init()
    dest = Path(dest_path)
    try:
        with open(dest, "w", encoding="utf-8") as out:
            out.write(_system_summary())
            for path in _log_files_in_order():
                if path.exists():
                    out.write(f"\n---- {path.name} ----\n")
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            out.write(fh.read())
                    except OSError as exc:
                        out.write(f"<could not read: {exc.__class__.__name__}>\n")
        return True
    except OSError:
        return False


def _log_files_in_order():
    # Oldest first so the newest entries land at the bottom of the export.
    files = []
    for i in range(_BACKUPS, 0, -1):
        files.append(LOG_DIR / f"netrecon.log.{i}")
    files.append(LOG_FILE)
    return files
