# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['src\\tinysocs\\api\\node.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        # Bundle detections rules so the onefile extraction has:
        # <_MEI...>\tinysocs\agent\detections\rules.yaml
        ('src\\tinysocs\\agent\\detections\\rules.yaml', 'tinysocs\\agent\\detections'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='TinySocsNode',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)