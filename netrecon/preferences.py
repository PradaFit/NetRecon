"""
Local user preferences for NetRecon.

Stored as JSON under the user's home directory at:
    ~/.netrecon/preferences.json

Used to persist things like the first-run responsible-use acceptance so
the notice does not appear on every launch. Safe defaults are returned
when the file is missing or malformed.
"""

import json
from datetime import datetime
from pathlib import Path


PREFS_DIR = Path.home() / ".netrecon"
PREFS_PATH = PREFS_DIR / "preferences.json"


def _ensure_dir():
    try:
        PREFS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def load() -> dict:
    """Return the preferences dict, or {} if unreadable."""
    try:
        with open(PREFS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {}


def save(data: dict) -> bool:
    """Write preferences atomically. Returns True on success."""
    _ensure_dir()
    try:
        tmp = PREFS_PATH.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(PREFS_PATH)
        return True
    except OSError:
        return False


def is_responsible_use_accepted() -> bool:
    return bool(load().get("responsible_use_accepted"))


def accept_responsible_use(app_version: str) -> bool:
    data = load()
    data["responsible_use_accepted"] = True
    data["responsible_use_accepted_at"] = datetime.utcnow().isoformat() + "Z"
    data["responsible_use_version"] = app_version
    return save(data)
