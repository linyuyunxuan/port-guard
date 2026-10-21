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
from core.models import (
    DISPOSITION_ALLOW,
    DISPOSITION_BLOCK,
    DISPOSITION_CONFIRM,
    DISPOSITION_HINT,
    DISPOSITION_LABEL,
)

log = get_logger(__name__)

#: 等级的中文单字，标题里用（「高风险」而不是「high 风险」）
_LEVEL_WORD = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


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
        alert: {ip, level, score, reason, geo, local_port, disposition}
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
        disposition = str(alert.get("disposition") or "")
        title = self._title(level, disposition)
        body = self._body(alert)

        if self.tray is not None:
            try:
                from qtcompat import QSystemTrayIcon

                # 「已拦截」用 Information 而不是警告图标：它已经不是待办事项，
                # 用感叹号催用户去处理，反而让人以为还有事没做。
                if disposition == DISPOSITION_BLOCK:
                    icon = QSystemTrayIcon.MessageIcon.Information
                elif level in ("critical", "high"):
                    icon = QSystemTrayIcon.MessageIcon.Critical
                else:
                    icon = QSystemTrayIcon.MessageIcon.Warning
                self.tray.showMessage(title, body, icon, 8000)
            except Exception:
                log.exception("托盘气泡告警失败")

        if s["sound"]:
            self._beep(level, disposition)

        popup_level = s.get("popup_level") or ""
        # 注意 "none" 必须显式排除：它会被 _rank 当成 0，导致「不弹窗」反而每次都弹
        if popup_level and popup_level != "none" and self._rank(level) >= self._rank(popup_level):
            self._popup(title, body, disposition)

        return True

    def _popup(self, title: str, body: str, disposition: str = "") -> None:
        if self.parent is None:
            return
        try:
            from qtcompat import QMessageBox

            # 「已拦截」用信息图标：窗口里写的是结论，不是待办。
            # 用黄色感叹号会让人以为还要去操作一次。
            if disposition == DISPOSITION_BLOCK:
                QMessageBox.information(self.parent, title, body)
            else:
                QMessageBox.warning(self.parent, title, body)
        except Exception:
            log.exception("弹窗告警失败")

    def _beep(self, level: str, disposition: str = "") -> None:
        try:
            import winsound

            # 已拦截不必再用刺耳提示音：事情已经处理完了，剩下的只是「知会一声」
            if disposition == DISPOSITION_BLOCK:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            elif level == "critical":
                winsound.MessageBeep(winsound.MB_ICONHAND)
            elif level == "high":
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception:
            log.debug("声音提示不可用", exc_info=True)

    @staticmethod
    def _title(level: str, disposition: str = "") -> str:
        """标题先说「处理结果」，再说「多严重」。

        这是用户提出的原话：「弹窗里应该显示处理结果，比如已放行、已拦截、
        仅提醒」。级别只说明事情多大，处置才说明**要不要起身处理** ——
        「已拦截」可以直接关掉，「待确认」才需要人。
        """
        word = _LEVEL_WORD.get(level, "")
        if disposition == DISPOSITION_BLOCK:
            return f"⛔ PortGuard 已拦截 · {word}风险"
        if disposition == DISPOSITION_CONFIRM:
            return f"⚠ PortGuard 待确认 · {word}风险"
        if disposition == DISPOSITION_ALLOW:
            return f"PortGuard 已放行 · {word}访问"
        if disposition:
            return f"PortGuard {DISPOSITION_LABEL.get(disposition, '提醒')} · {word}风险"
        # 没有 disposition（老调用方 / 单测只喂 ip+level）时退回按级别措辞
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
        disposition = str(alert.get("disposition") or "")
        if disposition:
            lines.append(f"处置结果：{DISPOSITION_LABEL.get(disposition, disposition)}")
            hint = DISPOSITION_HINT.get(disposition)
            if hint:
                lines.append(f"　　说明：{hint}")
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
