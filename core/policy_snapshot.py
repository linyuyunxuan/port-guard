"""策略快照：把「可复制的配置」打包与还原，供逐台交付时快速复制。

只带策略：规则配置、黑白名单、策略类设置键。
**不带**运行数据（事件 / 封禁账本 / 审计 / 离线库 / 备份），也不带本机相关
或含凭据的键（开机自启、Webhook 地址、镜像代理、同步时间戳、机器日志路径）。
导入前把现有三份 JSON 与设置快照备份到 `%APPDATA%/PortGuard/backup/policy-*`，
失败自动回滚 —— 逐台交付时要能核对、能回溯。
"""

import json
import os
import shutil
import time
from typing import Any, Dict, List, Tuple

from core import config as cfgmod
from core import settings as cfg
from core.logger import get_logger
from core.rule_engine import RuleEngine

log = get_logger(__name__)

SCHEMA = 1

#: 允许随快照复制的设置键。显式白名单，避免把本机状态 / 凭据带到别的机器。
POLICY_SETTING_KEYS: Tuple[str, ...] = (
    "auto_mode",
    "auto_ban_threshold",
    "default_ban_duration_sec",
    "ban_duration_critical_sec",
    "ban_duration_high_sec",
    "ban_duration_medium_sec",
    "ban_duration_low_sec",
    "ban_escalation_enabled",
    "ban_escalation_factor",
    "ban_escalation_max_sec",
    "repeat_blacklist_enabled",
    "repeat_blacklist_hits",
    "max_ban_duration_sec",
    "alert_sound",
    "alert_merge_sec",
    "alert_block_silent",
    "alert_webhook_enabled",
    "alert_webhook_level",
    "watch_enabled",
    "watch_ports",
    "watch_methods",
    "watch_interval_sec",
    "watch_dedupe_sec",
    "watch_resolve_pid",
    "watch_skip_history",
    "watch_auto_ban",
    "risk_retention_days",
    "ban_retention_days",
    "audit_retention_days",
    "log_retention_days",
    "maintenance_enabled",
    "maintenance_hour",
)


def _paths() -> List[str]:
    return [
        cfgmod.rules_path(),
        cfgmod.blacklist_path(),
        cfgmod.whitelist_path(),
    ]


def _write_json(path: str, data: Any) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    # newline="\n"：仓库 .gitattributes 是 eol=lf，别写成 CRLF
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_snapshot() -> Dict[str, Any]:
    """采集当前策略；不写盘，便于先核对再导出。"""
    eng = RuleEngine()
    return {
        "schema": SCHEMA,
        "app_version": cfgmod.APP_VERSION,
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rules": eng.get_config(),
        "blacklist": eng.blacklist.entries(),
        "whitelist": eng.whitelist.entries(),
        "settings": {k: cfg.get(k) for k in POLICY_SETTING_KEYS},
    }


def validate(data: Any) -> Tuple[bool, str]:
    """拒绝结构不对 / 类型不对的快照，绝不半途写入。"""
    if not isinstance(data, dict):
        return False, "快照不是 JSON 对象"
    if data.get("schema") != SCHEMA:
        return False, f"快照版本不兼容（需要 schema={SCHEMA}）"
    if not isinstance(data.get("rules"), dict):
        return False, "rules 必须是对象"
    for key in ("blacklist", "whitelist"):
        val = data.get(key)
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            return False, f"{key} 必须是字符串数组"
    st = data.get("settings")
    if not isinstance(st, dict) or not all(isinstance(v, str) for v in st.values()):
        return False, "settings 必须是字符串字典"
    unknown = sorted(set(st) - set(POLICY_SETTING_KEYS))
    if unknown:
        return False, "settings 含不允许复制的键：" + ", ".join(unknown)
    return True, ""


def _backup() -> str:
    folder = os.path.join(
        cfgmod.user_data_dir(), "backup", "policy-" + time.strftime("%Y%m%d-%H%M%S")
    )
    os.makedirs(folder, exist_ok=True)
    for path in _paths():
        if os.path.isfile(path):
            shutil.copy2(path, os.path.join(folder, os.path.basename(path)))
    _write_json(os.path.join(folder, "settings.json"), cfg.snapshot())
    return folder


def _restore(folder: str) -> None:
    for path in _paths():
        src = os.path.join(folder, os.path.basename(path))
        if os.path.isfile(src):
            shutil.copy2(src, path)
    st_path = os.path.join(folder, "settings.json")
    if os.path.isfile(st_path):
        st = _read_json(st_path)
        if isinstance(st, dict):
            cfg.set_many({str(k): str(v) for k, v in st.items()})


def export_to(path: str) -> Dict[str, Any]:
    """把当前策略写成一份 JSON 快照，返回写出的内容（便于审计摘要）。"""
    data = build_snapshot()
    _write_json(path, data)
    return data


def import_from(path: str) -> Dict[str, Any]:
    """校验 → 备份 → 应用 → 热重载；任一步失败都回滚到导入前。

    返回 `{ok, error, backup_dir, applied}`；`applied` 是各部分的条数，
    供界面与审计摘要使用。这里不写审计，审计由调用方（GUI/app 层）记录。
    """
    try:
        data = _read_json(path)
    except Exception as e:
        return {"ok": False, "error": f"读取快照失败：{e}", "backup_dir": "", "applied": {}}

    ok, err = validate(data)
    if not ok:
        return {"ok": False, "error": err, "backup_dir": "", "applied": {}}

    folder = ""
    try:
        folder = _backup()
        eng = RuleEngine()
        eng.save_config(data["rules"])
        black_path, white_path = cfgmod.blacklist_path(), cfgmod.whitelist_path()
        _write_json(black_path, {"items": list(data["blacklist"])})
        _write_json(white_path, {"items": list(data["whitelist"])})
        cfg.set_many({k: v for k, v in data["settings"].items() if k in POLICY_SETTING_KEYS})
        eng.reload()
        eng.load_lists()
        applied = {
            "settings": len(data["settings"]),
            "blacklist": len(data["blacklist"]),
            "whitelist": len(data["whitelist"]),
        }
        return {"ok": True, "error": "", "backup_dir": folder, "applied": applied}
    except Exception as e:
        log.exception("导入策略快照失败，回滚到导入前")
        if folder:
            try:
                _restore(folder)
            except Exception:
                log.exception("策略快照回滚失败，请从 %s 手工恢复", folder)
        return {
            "ok": False,
            "error": f"导入失败，已回滚：{e}",
            "backup_dir": folder,
            "applied": {},
        }
