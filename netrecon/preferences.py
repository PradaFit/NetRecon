"""
Local user preferences for NetRecon.

Stored as JSON under the user's home directory at:
    ~/.netrecon/preferences.json

Used to persist the first-run responsible-use acceptance and the last
main-window monitor anchor. Safe defaults are returned when the file is
missing or malformed.
"""

import json
from datetime import datetime, timezone
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


def is_responsible_use_accepted(app_version=None) -> bool:
    data = load()
    if not data.get("responsible_use_accepted"):
        return False
    if not app_version:
        return True
    accepted_version = str(data.get("responsible_use_version", ""))
    try:
        return accepted_version.split(".", 1)[0] == str(app_version).split(".", 1)[0]
    except (AttributeError, IndexError):
        return False


def accept_responsible_use(app_version: str) -> bool:
    data = load()
    data["responsible_use_accepted"] = True
    data["responsible_use_accepted_at"] = datetime.now(timezone.utc).isoformat()
    data["responsible_use_version"] = app_version
    return save(data)


def get_window_anchor() -> tuple[int, int] | None:
    """Return the last valid main-window center point, if one was saved."""
    anchor = load().get("window_center")
    if not isinstance(anchor, dict):
        return None
    x = anchor.get("x")
    y = anchor.get("y")
    if (
        isinstance(x, bool)
        or isinstance(y, bool)
        or not isinstance(x, int)
        or not isinstance(y, int)
    ):
        return None
    if not (-1_000_000 <= x <= 1_000_000 and -1_000_000 <= y <= 1_000_000):
        return None
    return x, y


def save_window_anchor(x: int, y: int) -> bool:
    """Persist the window center used to choose a monitor on next launch."""
    data = load()
    data["window_center"] = {"x": int(x), "y": int(y)}
    return save(data)
