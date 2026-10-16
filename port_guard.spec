# -*- mode: python ; coding: utf-8 -*-
"""
PortGuard PyInstaller 打包配置

打包命令：
    pyinstaller port_guard.spec

说明：
- xdb 定位库与默认 rules.json 作为只读资源打进包内（首次运行会拷到 %APPDATA%/PortGuard）
- 推荐 onedir 模式（启动更快）；如需单文件，把 EXE(...) 的 exclude_binaries / COLLECT 段改为 onefile 写法
- uac_admin=True 会要求管理员权限；若只想默认普通权限，把 uac_admin 改为 False，
  并用 start_as_admin.bat / 界面上的「以管理员身份重启」按钮在需要时提权
"""
import os

block_cipher = None

hidden = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "anyio._backends._asyncio",
]

# 只打包真实存在的资源：离线 IP 库与会话数据已列入 .gitignore（体积大，
# 可在设置页从上游同步），新克隆的仓库里可能没有，硬写路径会让 PyInstaller 直接报错。
_res_candidates = [
    ("data/ip2region_v4.xdb", "data"),
    ("data/ip2region_v6.xdb", "data"),
    ("data/rules.json", "data"),
    ("assets", "assets"),
]
datas = [(src, dst) for src, dst in _res_candidates if os.path.exists(src)]
_missing = [src for src, _ in _res_candidates if not os.path.exists(src)]
if _missing:
    print(f"[port_guard.spec] 跳过不存在的资源（首次运行会自动同步离线库）：{_missing}")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PySide6.QtWebEngineCore"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PortGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon="assets/icon.ico" if os.path.exists("assets/icon.ico") else None,
    manifest="app.manifest",
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PortGuard",
)
