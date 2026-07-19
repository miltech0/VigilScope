# -*- mode: python ; coding: utf-8 -*-
"""Reproducible PyInstaller configuration for VigilScope."""

from pathlib import Path

project_root = Path(SPECPATH)

data_files = [
    (str(project_root / "locales"), "locales"),
    (str(project_root / "rules" / "builtin_rules.json"), "rules"),
    (str(project_root / "assets" / "flags"), "assets/flags"),
    (str(project_root / "assets" / "vigilscope.png"), "assets"),
    (str(project_root / "assets" / "vigilscope.ico"), "assets"),
]

analysis = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=data_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="VigilScope",
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
    icon=str(project_root / "assets" / "vigilscope.ico"),
    version=str(project_root / "packaging" / "windows_version_info.txt"),
)
