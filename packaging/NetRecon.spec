# -*- mode: python ; coding: utf-8 -*-
r"""
PyInstaller spec for NetRecon.

Build:
    pyinstaller --noconfirm packaging\NetRecon.spec

Output:
    dist\NetRecon\NetRecon.exe          (entry point, GUI mode)
    dist\NetRecon\_internal\...         (Python runtime + deps)

Notes:
    - onedir layout: fast cold start, no per-launch self-extraction
    - UPX disabled on purpose: avoids AV false positives and adds startup overhead
    - Console disabled: GUI app, no flashing terminal window
"""

import os
import sys
from pathlib import Path

# This spec file lives in <repo>\packaging\, so the repo root is one up.
ROOT = Path(SPECPATH).resolve().parent

block_cipher = None

data_files = [
    (str(ROOT / "config.json"), "."),
    (str(ROOT / "PradaFit_Ascii_Art.txt"), "."),
    (str(ROOT / "DISCLAIMER.md"), "."),
    (str(ROOT / "LICENSE"), "."),
]

# customtkinter ships its own assets (themes, fonts) that PyInstaller
# can't see via static analysis. Pull them in explicitly.
hidden_imports = [
    "customtkinter",
    "PIL",
    "PIL._tkinter_finder",
    "dns",
    "dns.resolver",
    "dns.reversename",
    "dns.zone",
    "dns.query",
    "folium",
    "branca",
    "nmap",
    "requests",
]

from PyInstaller.utils.hooks import collect_data_files
data_files += collect_data_files("customtkinter")
data_files += collect_data_files("folium")
data_files += collect_data_files("branca")

excludes = [
    "tkinter.test",
    "test",
    "unittest",
    "pydoc_data",
    "pytest",
]

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=data_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

icon_path = ROOT / "packaging" / "NetRecon.ico"
icon_arg = str(icon_path) if icon_path.exists() else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetRecon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_arg,
    version=str(ROOT / "packaging" / "version_info.txt") if (ROOT / "packaging" / "version_info.txt").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="NetRecon",
)
