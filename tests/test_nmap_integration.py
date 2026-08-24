import os
import threading
import time

import pytest

from netrecon.scan_engine import SCAN_PROFILES, ScanEngine


pytestmark = pytest.mark.skipif(
    os.environ.get("NETRECON_RUN_NMAP_INTEGRATION") != "1",
    reason="set NETRECON_RUN_NMAP_INTEGRATION=1 for controlled local Nmap scans",
)


@pytest.mark.parametrize(
    "profile",
    [
        key
        for key, data in SCAN_PROFILES.items()
        if not data.get("native") and not data.get("extended")
    ],
)
def test_each_nmap_profile_starts_and_completes_on_localhost(profile):
    engine = ScanEngine()
    if not engine.is_available:
        pytest.skip("Nmap is not installed")
    ports = None if profile == "ping_sweep" else "65534"
    result = engine.scan(
        "127.0.0.1",
        profile=profile,
        ports=ports,
        timing="T4",
    )
    assert result.cancelled is False
    assert result.error is None
    assert result.profile == SCAN_PROFILES[profile]["name"]
    assert result.command_line
    assert "--stats-every 1s" in result.arguments
    assert "--host-timeout 30m" in result.arguments
    assert "--script-timeout 5m" in result.arguments


@pytest.mark.parametrize(
    ("profile", "ports"),
    [
        ("native_quick", None),
        ("native_full", None),
        ("native_custom", "65534"),
    ],
)
def test_each_native_profile_starts_and_completes_on_localhost(profile, ports):
    result = ScanEngine().scan(
        "127.0.0.1",
        profile=profile,
        ports=ports,
        concurrency=4000,
    )
    assert result.cancelled is False
    assert result.error is None
    assert result.profile == SCAN_PROFILES[profile]["name"]
    assert result.command_line.startswith("NetRecon native TCP scanner")


def test_live_nmap_process_cancels_promptly():
    engine = ScanEngine()
    if not engine.is_available:
        pytest.skip("Nmap is not installed")
    holder = {}
    worker = threading.Thread(
        target=lambda: holder.setdefault(
            "result",
            engine.scan("127.0.0.1", profile="intense", timing="T0"),
        )
    )
    worker.start()
    deadline = time.perf_counter() + 10
    while engine._nmap_process is None and worker.is_alive() and time.perf_counter() < deadline:
        time.sleep(0.02)
    started = time.perf_counter()
    assert engine.cancel() is True
    worker.join(timeout=2)
    elapsed = time.perf_counter() - started
    assert not worker.is_alive()
    assert elapsed < 1.0
    assert holder["result"].cancelled is True
