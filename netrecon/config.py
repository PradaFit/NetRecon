"""Small, read-only loader for the bundled NetRecon configuration."""

import json
import sys
from functools import lru_cache
from pathlib import Path


DEFAULTS = {
    "dns": {"timeout": 5.0, "lifetime": 10.0},
    "scan": {
        "default_profile": "native_quick",
        "default_timing": "Profile default",
        "native_concurrency": 4000,
        "native_timeout": 1.5,
    },
    "geo": {"timeout": 10.0},
    "database": {"path": None},
}


def _config_path():
    if getattr(sys, "frozen", False):
        bundle_root = getattr(sys, "_MEIPASS", None)
        if bundle_root:
            return Path(bundle_root) / "config.json"
        return Path(sys.executable).resolve().parent / "config.json"
    return Path(__file__).resolve().parents[1] / "config.json"


@lru_cache(maxsize=1)
def load_config():
    config = {section: dict(values) for section, values in DEFAULTS.items()}
    try:
        with _config_path().open("r", encoding="utf-8") as handle:
            supplied = json.load(handle)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return config
    if not isinstance(supplied, dict):
        return config
    for section, defaults in config.items():
        incoming = supplied.get(section)
        if isinstance(incoming, dict):
            defaults.update(incoming)
    return config


def get_section(name):
    return dict(load_config().get(name, {}))
