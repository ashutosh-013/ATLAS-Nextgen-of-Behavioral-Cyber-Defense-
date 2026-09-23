# -*- mode: python ; coding: utf-8 -*-
"""
ATLAS Desktop PyInstaller Specification File
--------------------------------------------
Compiles ATLAS into an enterprise-ready, fast-booting directory distribution (onedir)
with UAC Administrator elevation and bundled frontend & knowledge base assets.
"""

import sys
from pathlib import Path

block_cipher = None

# Base directory
base_dir = Path.cwd()

# Static assets and data folders to bundle
datas = [
    ('frontend', 'frontend'),
    ('knowledge_base', 'knowledge_base'),
    ('config.json', '.'),
]

# Hidden imports required by dynamic scientific & web packages
hiddenimports = [
    'unittest',
    'scipy.special.cython_special',
    'scipy.spatial.transform._rotation_groups',
    'sklearn.utils._typedefs',
    'sklearn.neighbors._typedefs',
    'sklearn.tree._utils',
    'engineio.async_drivers.threading',
    'webview',
    'webview.platforms.winforms',
]

excludes = [
    'tkinter', 'matplotlib', 'IPython', 'jupyter', 'jupyter_core', 'jupyter_client',
    'notebook', 'nbformat', 'nbconvert', 'tornado', 'zmq', 'pyzmq',
    'torch', 'torchvision', 'torchaudio', 'tensorflow', 'tensorboard',
    'keras', 'cv2', 'PIL.ImageQt'
]

a = Analysis(
    ['atlas_desktop.py'],
    pathex=[str(base_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Strip out any jupyter runtime files or locked AppData temporary files
a.datas = [d for d in a.datas if 'jupyter' not in d[0].lower() and 'jpserver' not in d[0].lower()]

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ATLAS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Keep False to prevent antivirus heuristic false-positives
    console=False,  # Silent desktop launch without intrusive command prompt window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(base_dir / 'frontend' / 'atlas_logo.ico'),
    uac_admin=True,  # Windows UAC: Requests Administrator execution level for netsh & vssadmin
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ATLAS',
)
