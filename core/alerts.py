"""
PortGuard — 告警通知

- 托盘气泡（QSystemTrayIcon.showMessage）
- 声音（Windows 内置 winsound，异步播放，不阻塞）
- 严重级别弹窗（QMessageBox）
- 同 IP 告警合并节流

本模块的方法必须由 Qt 主线程调用（由主窗口的事件泵驱动）。
"""

import time
from typing import Dict

from core import settings as cfg
from core.logger import get_logger

log = get_logger(__name__)


class Alerter:
    def __init__(self, tray=None, parent_widget=None, on_settings_changed=None):
        self.tray = tray
        self.parent = parent_widget
        self._last_alert: Dict[str, float] = {}
        self._on_settings_changed = on_settings_changed

    # ── 设置读取（走内存缓存，UI 改动即时生效且零查库开销）──
    @staticmethod
    def _settings() -> Dict:
        try:
            return {
                "sound": cfg.get_bool("alert_sound", True),
                "popup_level": cfg.get("alert_popup_level", "critical") or "none",
                "merge_sec": cfg.get_int("alert_merge_sec", 60),
            }
        except Exception:
            log.exception("读取告警设置失败，使用默认值")
            return {"sound": True, "popup_level": "critical", "merge_sec": 60}

    def set_tray(self, tray) -> None:
        self.tray = tray

    def set_parent(self, parent) -> None:
        self.parent = parent

    # ── 主入口 ──
    def notify(self, alert: Dict) -> bool:
        """
        alert: {ip, level, score, reason, geo, local_port}
        返回是否真正弹出了提醒（被节流则返回 False）
        """
        s = self._settings()
        ip = alert.get("ip", "")
        now = time.time()

        # 同 IP 合并节流
        last = self._last_alert.get(ip, 0)
        if now - last < s["merge_sec"]:
            return False
        self._last_alert[ip] = now
        self._gc(now, s["merge_sec"])

        level = alert.get("level", "medium")
        title = self._title(level)
        body = self._body(alert)

        if self.tray is not None:
            try:
                from qtcompat import QSystemTrayIcon

                icon = (
                    QSystemTrayIcon.MessageIcon.Critical
                    if level in ("critical", "high")
                    else QSystemTrayIcon.MessageIcon.Warning
                )
                self.tray.showMessage(title, body, icon, 8000)
            except Exception:
                log.exception("托盘气泡告警失败")

        if s["sound"]:
            self._beep(level)

        popup_level = s.get("popup_level") or ""
        # 注意 "none" 必须显式排除：它会被 _rank 当成 0，导致「不弹窗」反而每次都弹
        if popup_level and popup_level != "none" and self._rank(level) >= self._rank(popup_level):
            self._popup(title, body)

        return True

    def _popup(self, title: str, body: str) -> None:
        if self.parent is None:
            return
        try:
            from qtcompat import QMessageBox

            QMessageBox.warning(self.parent, title, body)
        except Exception:
            log.exception("弹窗告警失败")

    def _beep(self, level: str) -> None:
        try:
            import winsound

            if level == "critical":
                winsound.MessageBeep(winsound.MB_ICONHAND)
            elif level == "high":
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception:
            log.debug("声音提示不可用", exc_info=True)

    @staticmethod
    def _title(level: str) -> str:
        return {
            "critical": "⛔ PortGuard 严重风险告警",
            "high": "⚠ PortGuard 高风险告警",
            "medium": "PortGuard 中风险提醒",
            "low": "PortGuard 低风险提醒",
        }.get(level, "PortGuard 告警")

    @staticmethod
    def _body(alert: Dict) -> str:
        lines = [
            f"来源 IP：{alert.get('ip', '-')}",
            f"归属地：{alert.get('geo', '未知')}",
            f"目标端口：{alert.get('local_port', '-')}",
            f"风险评分：{alert.get('score', 0)}",
        ]
        reason = alert.get("reason")
        if reason:
            lines.append(f"命中：{reason}")
        return "\n".join(lines)

    @staticmethod
    def _rank(level: str) -> int:
        return {"normal": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)

    def _gc(self, now: float, window: int) -> None:
        if len(self._last_alert) < 2000:
            return
        cutoff = now - max(window, 60) * 10
        for k in [k for k, v in self._last_alert.items() if v < cutoff]:
            self._last_alert.pop(k, None)
