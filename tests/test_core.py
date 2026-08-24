import csv
import json
import shlex
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from netrecon.async_scanner import AsyncPortScanner, PortResult, TOP_1000
from netrecon import config as app_config
from netrecon.db_manager import DatabaseManager
from netrecon.dns_engine import DNSEngine, DNSResult
from netrecon.export_engine import ExportEngine
from netrecon.geo_engine import GeoEngine, GeoResult
from netrecon.platform_utils import PlatformInfo
from netrecon.scan_engine import SCAN_PROFILES, ScanEngine
from netrecon.validator import InputError, sanitize_nmap_args
from netrecon import __version__
from netrecon import preferences
from gui import windowing
from gui.windowing import apply_window_icon, calculate_centered_geometry, resource_path
import main as app_main


ROOT = Path(__file__).resolve().parents[1]


def test_top_port_list_is_exactly_1000_unique_ports():
    assert len(TOP_1000) == 1000
    assert len(set(TOP_1000)) == 1000
    assert all(1 <= port <= 65535 for port in TOP_1000)


def test_frozen_config_uses_pyinstaller_bundle_root(monkeypatch, tmp_path):
    monkeypatch.setattr(app_config.sys, "frozen", True, raising=False)
    monkeypatch.setattr(app_config.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert app_config._config_path() == tmp_path / "config.json"


def test_nmap_version_check_hides_windows_console(monkeypatch):
    info = PlatformInfo()
    info.is_windows = True
    info._nmap_path = r"C:\Program Files\Nmap\nmap.exe"
    no_window = 0x08000000
    monkeypatch.setattr(
        "netrecon.platform_utils.subprocess.CREATE_NO_WINDOW",
        no_window,
        raising=False,
    )
    captured = {}

    def fake_check_output(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return b"Nmap version 7.98 ( https://nmap.org )\n"

    monkeypatch.setattr(
        "netrecon.platform_utils.subprocess.check_output", fake_check_output
    )

    assert info.get_nmap_version().startswith("Nmap version 7.98")
    assert captured["command"] == [info._nmap_path, "--version"]
    assert captured["kwargs"]["creationflags"] == no_window
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL


def test_window_geometry_centers_on_positive_and_negative_monitors():
    assert calculate_centered_geometry(1300, 860, (0, 0, 1920, 1040)) == (
        1300,
        860,
        310,
        90,
    )
    assert calculate_centered_geometry(1300, 860, (-1920, 0, 0, 1040)) == (
        1300,
        860,
        -1610,
        90,
    )
    assert calculate_centered_geometry(1300, 860, (0, 0, 1024, 768)) == (
        1024,
        768,
        0,
        0,
    )


def test_window_anchor_preferences_are_validated_and_persisted(monkeypatch, tmp_path):
    monkeypatch.setattr(preferences, "PREFS_DIR", tmp_path)
    monkeypatch.setattr(preferences, "PREFS_PATH", tmp_path / "preferences.json")
    assert preferences.get_window_anchor() is None
    assert preferences.save_window_anchor(-1200, 450) is True
    assert preferences.get_window_anchor() == (-1200, 450)

    preferences.PREFS_PATH.write_text(
        json.dumps({"window_center": {"x": True, "y": 450}}), encoding="utf-8"
    )
    assert preferences.get_window_anchor() is None


def test_window_icon_is_available_in_source_and_frozen_layout(monkeypatch, tmp_path):
    source_icon = resource_path("packaging", "NetRecon.ico")
    assert source_icon.is_file()
    bundled_icon = tmp_path / "packaging" / "NetRecon.ico"
    bundled_icon.parent.mkdir()
    bundled_icon.write_bytes(b"ico")
    monkeypatch.setattr("gui.windowing.sys._MEIPASS", str(tmp_path), raising=False)
    assert resource_path("packaging", "NetRecon.ico") == bundled_icon

    class FakeWindow:
        def __init__(self):
            self.calls = []

        def iconbitmap(self, *args, **kwargs):
            self.calls.append((args, kwargs))

    window = FakeWindow()
    assert apply_window_icon(window) == bundled_icon
    expected_calls = [((str(bundled_icon),), {})]
    if windowing.sys.platform.startswith("win"):
        expected_calls.append(((), {"default": str(bundled_icon)}))
    assert window.calls == expected_calls


def test_center_window_accounts_for_customtkinter_dpi_scaling(monkeypatch):
    monkeypatch.setattr(
        windowing, "_windows_work_area", lambda anchor: (0, 0, 1920, 1040)
    )

    class FakeWindow:
        applied_geometry = None

        @staticmethod
        def _get_window_scaling():
            return 1.25

        def geometry(self, value):
            self.applied_geometry = value

    window = FakeWindow()
    placement = windowing.center_window(window, 1300, 860, anchor=(200, 200))
    assert placement == (1300, 832, 147, 0)
    assert window.applied_geometry == "1300x832+147+0"


def test_release_version_metadata_is_consistent():
    assert __version__ == "2.0.5"
    assert json.loads((ROOT / "config.json").read_text(encoding="utf-8"))["version"] == __version__
    four_part = f"{__version__}.0"
    assert four_part in (ROOT / "packaging" / "version_info.txt").read_text(
        encoding="utf-8"
    )
    assert four_part in (ROOT / "packaging" / "version_info_cli.txt").read_text(
        encoding="utf-8"
    )
    assert four_part in (ROOT / "packaging" / "NetRecon.iss").read_text(
        encoding="utf-8"
    )
    assert four_part in (ROOT / "packaging" / "AppxManifest.xml").read_text(
        encoding="utf-8"
    )
    assert four_part in (ROOT / "packaging" / "AppxManifest.dev.xml").read_text(
        encoding="utf-8"
    )


def test_packaged_cli_executable_is_detected_by_name(monkeypatch, tmp_path):
    monkeypatch.setattr(app_main.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        app_main.sys, "executable", str(tmp_path / "NetRecon-CLI.exe")
    )
    assert app_main._is_cli_executable() is True

    monkeypatch.setattr(app_main.sys, "executable", str(tmp_path / "NetRecon.exe"))
    assert app_main._is_cli_executable() is False


def test_packaging_source_defines_gui_cli_and_store_alias():
    spec = (ROOT / "packaging" / "NetRecon.spec").read_text(encoding="utf-8")
    assert 'name="NetRecon"' in spec
    assert 'name="NetRecon-CLI"' in spec
    assert "console=False" in spec
    assert "console=True" in spec
    assert '(str(ROOT / "packaging" / "NetRecon.ico"), "packaging")' in spec
    assert 'collect_submodules("netrecon")' in spec

    inno = (ROOT / "packaging" / "NetRecon.iss").read_text(encoding="utf-8")
    assert '#define MyCliExeName     "NetRecon-CLI.exe"' in inno
    assert "{#MyCliExeName}" in inno

    uap5 = "http://schemas.microsoft.com/appx/manifest/uap/windows10/5"
    for manifest_name in ("AppxManifest.xml", "AppxManifest.dev.xml"):
        root = ET.parse(ROOT / "packaging" / manifest_name).getroot()
        alias = root.find(f".//{{{uap5}}}ExecutionAlias")
        assert alias is not None
        assert alias.attrib["Alias"] == "netrecon-cli.exe"


def test_packaging_credentials_and_generated_output_remain_ignored():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "packaging/" not in ignore
    for pattern in (
        "packaging/Output/",
        "packaging/msix-stage/",
        "packaging/dev-msix.pfx",
        "packaging/dev-msix.cer",
        "packaging/trusted-signing.json",
        "*.pfx",
        "*.key",
    ):
        assert pattern in ignore


def test_msix_build_requires_legal_and_privacy_documents():
    build_script = (ROOT / "packaging" / "build-msix.ps1").read_text(
        encoding="utf-8"
    )
    assert '$RequiredDocs = @("LICENSE", "PRIVACY.md", "DISCLAIMER.md")' in build_script
    assert "Required MSIX document not found" in build_script
    assert "best effort" not in build_script


def test_all_nmap_profiles_build_valid_arguments_with_overrides():
    engine = ScanEngine()
    for key, profile in SCAN_PROFILES.items():
        if profile.get("native"):
            continue
        args, name, requires_admin = engine.build_nmap_arguments(
            profile=key, ports="65000", timing="T4"
        )
        assert name == profile["name"]
        assert requires_admin == bool(profile.get("requires_admin"))
        assert "-T4" in args
        tokens = shlex.split(args, posix=True)
        assert "T4" not in tokens
        if key == "ping_sweep":
            assert "-p" not in tokens
        else:
            assert tokens[-2:] == ["-p", "65000"]
            assert "-p-" not in tokens
            assert "--top-ports" not in tokens
            assert "-F" not in tokens


def test_builtin_nmap_profiles_keep_their_documented_commands():
    expected = {
        "quick": "-n -T4 -F",
        "default": "-n -T3 -sV",
        "intense": "-n -T4 -A -p-",
        "stealth": "-n -sS -T2",
        "udp": "-n -sU -T4 --top-ports 100",
        "vuln": (
            '-n -sV "--script=vuln and safe and not external and not broadcast"'
        ),
        "vuln_extended": (
            "-n -sV --script=vuln --script-timeout 15m --host-timeout 60m"
        ),
        "ping_sweep": "-n -sn",
        "os_detect": "-n -O --osscan-guess",
        "service_version": "-n -sV --version-intensity 5",
        "comprehensive": (
            '-n -T4 -A -p- "--script=(default or vuln) and safe and not '
            'external and not broadcast"'
        ),
        "comprehensive_extended": (
            "-n -T4 -A -p- --script=default,vuln --script-timeout 15m "
            "--host-timeout 60m"
        ),
    }
    engine = ScanEngine()
    for profile, expected_args in expected.items():
        args, name, _ = engine.build_nmap_arguments(profile=profile)
        assert args == expected_args
        assert name == SCAN_PROFILES[profile]["name"]


@pytest.mark.parametrize(
    "unsafe",
    [
        "-oX report.xml",
        "-iL targets.txt",
        "--script=../../local-script",
        "--script-args user=value",
        "--proxies http://127.0.0.1",
        "-sV; whoami",
    ],
)
def test_custom_nmap_arguments_reject_unsafe_or_unapproved_options(unsafe):
    with pytest.raises(InputError):
        sanitize_nmap_args(unsafe)


def test_custom_nmap_arguments_accept_documented_safe_options():
    assert sanitize_nmap_args(
        "-sV -T4 -p 1-1000 --max-retries 2 --script-timeout 5m"
    ) == (
        "-sV -T4 -p 1-1000 --max-retries 2 --script-timeout 5m"
    )


def test_nmap_runtime_controls_are_bounded_and_preserve_explicit_overrides():
    engine = ScanEngine()
    controlled = engine._add_runtime_controls(["-n", "-sV"])
    assert controlled[-6:] == [
        "--stats-every",
        "1s",
        "--host-timeout",
        "30m",
        "--script-timeout",
        "5m",
    ]

    explicit = engine._add_runtime_controls(
        ["-n", "--host-timeout", "0", "--script-timeout=0"]
    )
    assert explicit.count("--host-timeout") == 1
    assert "--script-timeout=0" in explicit
    assert "5m" not in explicit


def test_nmap_taskprogress_is_converted_to_a_live_status_message():
    line = (
        '<taskprogress task="SYN Stealth Scan" time="1" percent="42.50" '
        'remaining="75" etc="2" />\n'
    )
    assert ScanEngine._nmap_progress_message(line) == (
        "  [ 42.5%] Nmap SYN Stealth Scan; about 1m 15s remaining"
    )
    assert ScanEngine._nmap_progress_message("<host></host>") is None


def test_native_custom_finds_a_controlled_local_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                client.sendall(b"NetRecon test\r\n")
            except OSError:
                pass
            finally:
                client.close()

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = ScanEngine().scan(
            "127.0.0.1",
            profile="native_custom",
            ports=str(port),
            concurrency=10,
        )
    finally:
        stop.set()
        listener.close()
        server.join(timeout=1)

    assert result.error is None
    assert result.profile == "Native Custom"
    assert result.total_open_ports == 1
    assert result.hosts[0]["state"] == "up"
    assert result.hosts[0]["ports"][0]["port"] == port


def test_native_cancel_wakes_inflight_tasks_immediately(monkeypatch):
    async def slow_probe(self, ip, port, family):
        import asyncio

        await asyncio.sleep(10)
        return PortResult(port=port, state="filtered")

    monkeypatch.setattr(AsyncPortScanner, "_probe_port", slow_probe)
    scanner = AsyncPortScanner(concurrency=100, connect_timeout=10, grab_banners=False)
    holder = {}
    worker = threading.Thread(
        target=lambda: holder.setdefault(
            "result", scanner.scan("127.0.0.1", ports=range(1, 5001))
        )
    )
    worker.start()
    deadline = time.perf_counter() + 2
    while scanner._loop is None and time.perf_counter() < deadline:
        time.sleep(0.01)
    started = time.perf_counter()
    scanner.cancel()
    worker.join(timeout=2)
    elapsed = time.perf_counter() - started

    assert not worker.is_alive()
    assert elapsed < 1.0
    assert holder["result"].cancelled is True
    assert holder["result"].total_scanned < 5000


def test_native_profiles_reject_cidr_with_actionable_message():
    result = ScanEngine().scan("192.0.2.0/24", profile="native_quick")
    assert result.error
    assert "Nmap profile" in result.error


def test_reverse_dns_uses_a_real_resolver(monkeypatch):
    class Resolver:
        def resolve(self, name, record_type):
            assert record_type == "PTR"
            return ["localhost."]

    engine = DNSEngine()
    monkeypatch.setattr(engine, "_resolver", lambda nameserver=None: Resolver())
    result = engine.reverse_lookup("127.0.0.1")
    assert result.error is None
    assert result.records == [{"value": "localhost."}]


def test_all_dns_records_preserve_errors_for_ui_feedback(monkeypatch):
    engine = DNSEngine()
    monkeypatch.setattr(
        engine,
        "resolve",
        lambda domain, record_type: DNSResult(
            query=domain, record_type=record_type, error="no answer"
        ),
    )
    results = engine.get_all_records("example.com")
    assert len(results) > 1
    assert all(result.error == "no answer" for result in results)


def test_geolocation_rejects_private_addresses_without_contacting_provider(monkeypatch):
    engine = GeoEngine()
    monkeypatch.setattr(
        engine, "_query_ipwhois", lambda ip: pytest.fail("provider should not run")
    )
    result = engine.locate("127.0.0.1")
    assert result.error
    assert "public IP" in result.error


def test_geolocation_provider_urls_are_https():
    source = __import__("inspect").getsource(GeoEngine)
    assert 'url = f"http://' not in source
    assert "ip-api.com" not in source


def test_zero_coordinate_is_valid():
    assert GeoResult(ip="203.0.113.1", latitude=0.0, longitude=10.0).coordinates == (
        0.0,
        10.0,
    )


def test_csv_export_handles_mixed_fields_and_neutralizes_formulas(tmp_path):
    output = tmp_path / "mixed.csv"
    data = [
        {"records": [{"value": "=cmd|test", "extra": "one"}], "query": "a"},
        {"records": [{"value": "+SUM(1,1)", "different": "two"}], "query": "b"},
    ]
    ExportEngine.to_csv(data, output, trusted=True)
    with output.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["value"].startswith("'=")
    assert rows[1]["value"].startswith("'+")
    assert "extra" in rows[0]
    assert "different" in rows[1]


def test_map_export_accepts_zero_latitude(tmp_path):
    output = tmp_path / "map.html"
    result = ExportEngine.generate_map(
        [GeoResult(ip="203.0.113.1", latitude=0.0, longitude=10.0)],
        output,
        trusted=True,
    )
    assert result == str(output.resolve())
    assert output.exists()


def test_history_export_includes_full_result_payload(tmp_path):
    database = DatabaseManager(tmp_path / "history.db")
    database.save("Port Scan", "127.0.0.1", {"hosts": [{"ip": "127.0.0.1"}]})
    rows = database.get_export_records()
    assert rows[0]["result_data"]["hosts"][0]["ip"] == "127.0.0.1"
