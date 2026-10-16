# -*- mode: python ; coding: utf-8 -*-
r"""
PortGuard PyInstaller 打包配置

打包命令：
    pyinstaller port_guard.spec

说明：
- xdb 定位库与默认 rules.json 作为只读资源打进包内（首次运行会拷到 %APPDATA%/PortGuard）
- 推荐 onedir 模式（启动更快）；如需单文件，把 EXE(...) 的 exclude_binaries / COLLECT 段改为 onefile 写法
- uac_admin=True 会要求管理员权限；若只想默认普通权限，把 uac_admin 改为 False，
  并用 start_as_admin.bat / 界面上的「以管理员身份重启」按钮在需要时提权

打包产物的运行验证（2026-10-16 实做过）：
- **首选：`PortGuard.exe --selfcheck`** —— 在「模拟无控制台」的条件下真正启停一次接收服务，
  退出码 0 即通过（窗口程序没有 stdout，`print` 看不到，细节看日志文件）。
  这一步专门覆盖「窗口化 + sys.stdout 为 None」这条路径：uvicorn 的彩色 formatter 会执行
  `sys.stdout.isatty()`，std 流为 None 时会抛 AttributeError，被 dictConfig 包成
  「Unable to configure formatter 'default'」，表现成「接收服务启动失败」。
- 但 `uac_admin=True` 的 exe 从非提权进程启动会直接被系统拒绝（ERROR_ELEVATION_REQUIRED），
  所以要自动化跑 `--selfcheck` 时，另建一份 `uac_admin=False` 的临时 spec：
      copy port_guard.spec _smoke.spec      # 把 uac_admin 改 False、name 改成 PortGuardSmoke
      pyinstaller --noconfirm --workpath build_smoke --distpath dist_smoke _smoke.spec
      dist_smoke\PortGuardSmoke\PortGuardSmoke.exe --selfcheck
- 判定「跑起来了」不能只看进程存活：窗口化程序崩溃时会弹错误框并一直卡住，进程同样“活着”。
  可靠做法是看 %APPDATA%/PortGuard/logs/portguard.log 里出现
  「PortGuard 后端就绪（配置项 N 条）」且没有「界面启动失败」。
- 离屏跑设 QT_QPA_PLATFORM=offscreen，避免在自动化环境里弹窗。
- **拷到别的电脑跑不起来时，先跑 `PortGuard.exe --diag`**：它打印系统内部版本、
  逐个探测运行库、扫描产物依赖闭包，直接点名是缺哪个 DLL。见 core/diag.py。
  `tools/verify_exe.py` 的第 07–10 项就是校验这个入口在产物里可用。

运行环境要求（2026-10-16 用 PE 导入表实测）：
- `Qt6Core.dll` 把 `icuuc.dll` 列为**硬导入**，而 `icuuc.dll` 是 Windows 10 1703
  （内部版本 15063）才加入的系统组件 → 目标是 **Windows 10 1703+（推荐 1809+）**。
  在 Win7 / Win8.1 / Server 2012R2 / Server 2016 / Win10 早期版本上，
  `import PySide6.QtCore` 必然报「找不到指定的模块」，且无法通过补 DLL 解决。
- 静态核对依赖：`python tools/check_dll_deps.py dist/PortGuard`
  （判定时只认**硬导入**，并按「DLL 自身目录 / _internal / System32」的
  真实搜索上下文解析，而不是「整个目录树里有没有」）
"""
import os

block_cipher = None

# --- VC++ 运行库平铺到 _internal 根目录 -------------------------------------
# PySide6 轮子里带有 MSVCP140 / VCRUNTIME140 系列，但它们是散落在
# `_internal/PySide6/`、`_internal/shiboken6/` 子目录里的。Windows 解析依赖时
# 会先搜「DLL 自身所在目录」，所以本机能跑；可一旦有模块从别的目录起链（或
# 目标机没装 VC++ 运行库），就得靠 PATH / add_dll_directory 兜，非常脆弱。
# 平铺一份到 _internal 根目录后，任何模块都能按标准搜索顺序解析到，
# 与目标机是否安装过 VC++ 运行库、是否被 PATH 干扰都无关。
# 注意：vcruntime140.dll / vcruntime140_1.dll 是 python313.dll 的依赖，
# PyInstaller 已经自动平铺在 _internal 根，重复添加会撞名，这里排除。
_VC_ALREADY_FLAT = {"vcruntime140.dll", "vcruntime140_1.dll"}
_VC_RUNTIME = [
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_codecvt_ids.dll",
    "concrt140.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
]


def _pyside6_dir() -> str:
    """定位 PySide6 包目录；只查 spec 不求 import，避免拖慢打包。"""
    try:
        import importlib.util

        spec = importlib.util.find_spec("PySide6")
        if spec and spec.origin:
            return os.path.dirname(os.path.abspath(spec.origin))
    except Exception:
        pass
    return ""


_pyside_dir = _pyside6_dir()
_vc_binaries = []
for _name in _VC_RUNTIME:
    if _name in _VC_ALREADY_FLAT:
        continue
    _src = os.path.join(_pyside_dir, _name)
    if _pyside_dir and os.path.exists(_src):
        _vc_binaries.append((_src, "."))
    else:
        print(f"[port_guard.spec] 未找到 VC 运行库 {_name}（跳过，通常不影响）")

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
    binaries=_vc_binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    # 说明：依赖只装 PySide6-Essentials，正常情况不会有 WebEngine；
    # 这里仍显式排除，防止开发机装了完整版 PySide6 时把 100+ MB 的 WebEngine 打进去。
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
