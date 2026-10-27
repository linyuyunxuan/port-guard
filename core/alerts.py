"""
PortGuard — 告警通知

- 托盘气泡（QSystemTrayIcon.showMessage）—— 唯一的人机提醒通道
- 声音（Windows 内置 winsound，异步播放，不阻塞）
- 同 IP 告警合并节流

**不再有模态弹窗**（2026-10-27 用户要求：「取消这个弹窗，保留右下角弹窗功能」）。
模态 QMessageBox 会抢走键盘焦点，而它的内容在托盘气泡与风险事件页里完全一样 ——
攻击期几十条告警就是几十次打断，用户正在打字的那一行会被吃掉。
告警文案仍由 `_title` / `_body` 生成，供气泡与外部推送共用。

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
                "merge_sec": cfg.get_int("alert_merge_sec", 60),
                "block_silent": cfg.get_bool("alert_block_silent", True),
            }
        except Exception:
            log.exception("读取告警设置失败，使用默认值")
            return {"sound": True, "merge_sec": 60, "block_silent": True}

    def set_tray(self, tray) -> None:
        self.tray = tray

    def set_parent(self, parent) -> None:
        self.parent = parent

    # ── 主入口 ──
    def notify(self, alert: Dict) -> bool:
        """
        alert: {ip, level, score, reason, geo, local_port, disposition}
               blocked_again —— 该 IP 本来就在封禁中，这是重复命中
               block_hits   —— 封禁期间累计被拦下的次数
               escalated    —— 本次触发了「惯犯升级黑名单」
        返回是否真正弹出了提醒（被静默或节流则返回 False）
        """
        s = self._settings()
        ip = alert.get("ip", "")
        now = time.time()

        # ── 静默：封禁期间的重复命中 ──
        # 用户原话（2026-10-22）：「已拦截了还弹窗提示或者右下角窗口提示，
        # 影响电脑操作」。防火墙规则已经生效，重复命中说的还是同一句「已拦截」，
        # 除了抢走焦点没有任何新信息 —— 改为只累加次数（pipeline 已写库），
        # 什么都不弹。真正的「状态变了」（升级黑名单）走下面的 escalated 分支。
        if s["block_silent"] and alert.get("blocked_again") and not alert.get("escalated"):
            return False

        # 同 IP 合并节流
        last = self._last_alert.get(ip, 0)
        if now - last < s["merge_sec"]:
            return False
        self._last_alert[ip] = now
        self._gc(now, s["merge_sec"])

        level = alert.get("level", "medium")
        disposition = str(alert.get("disposition") or "")
        escalated = bool(alert.get("escalated"))
        if escalated:
            title = self._escalation_title(ip, alert)
            body = self._escalation_body(alert)
        else:
            title = self._title(level, disposition)
            body = self._body(alert)

        if self.tray is not None:
            try:
                from qtcompat import QSystemTrayIcon

                # 「已拦截」用 Information 而不是警告图标：它已经不是待办事项，
                # 用感叹号催用户去处理，反而让人以为还有事没做。
                if escalated:
                    # 升级黑名单是「程序自己收紧了安全策略」：图标用 Critical，
                    # 让人一眼看出这不是一次普通的拦截
                    icon = QSystemTrayIcon.MessageIcon.Critical
                elif disposition == DISPOSITION_BLOCK:
                    icon = QSystemTrayIcon.MessageIcon.Information
                elif level in ("critical", "high"):
                    icon = QSystemTrayIcon.MessageIcon.Critical
                else:
                    icon = QSystemTrayIcon.MessageIcon.Warning
                self.tray.showMessage(title, body, icon, 8000)
            except Exception:
                log.exception("托盘气泡告警失败")

        # 升级提示刻意不响铃：它一天也未必有一次，但打扰的代价是一样的
        # （2026-10-22 用户反馈）。
        if s["sound"] and not escalated:
            self._beep(level, disposition)

        # 外部推送（可选）：气泡 + 声音都要求「有人正看着这台机器」，
        # 而最需要告警的无人值守场景恰恰没人看。默认关闭，见 core/alert_webhook.py
        self._notify_webhook(alert)

        return True

    @staticmethod
    def _notify_webhook(alert: Dict) -> None:
        try:
            from core import alert_webhook

            alert_webhook.send_async(alert)
        except Exception:
            # 推送失败绝不能影响本地告警：它只是「额外一条路」
            log.exception("Webhook 推送调度失败")

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
    def _escalation_title(ip: str, alert: Dict) -> str:
        """「已列入黑名单」的标题：说的是**策略变了**，不是又一次拦截"""
        return f"⛔ PortGuard 已列入黑名单 · {ip}"

    @staticmethod
    def _escalation_body(alert: Dict) -> str:
        hits = int(alert.get("block_hits") or 0)
        lines = [
            f"来源 IP：{alert.get('ip', '-')}",
            f"归属地：{alert.get('geo') or '未知'}",
            f"封禁期间又访问：{hits} 次",
            "处置结果：已列入黑名单（永久封禁）",
            "　　说明：封了还在撞，已按惯犯处理，到期不再自动解封",
        ]
        reason = alert.get("reason")
        if reason:
            lines.append(f"命中：{reason}")
        return "\n".join(lines)

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
        hits = int(alert.get("block_hits") or 0)
        if hits:
            # 关掉「已拦截静默」时才会走到这里。次数必须说出来 ——
            # 否则这条弹窗和上一次长得一模一样，等于白打扰一次。
            lines.append(f"　　已拦截次数：{hits} 次")
        reason = alert.get("reason")
        if reason:
            lines.append(f"命中：{reason}")
        return "\n".join(lines)

    def _gc(self, now: float, window: int) -> None:
        if len(self._last_alert) < 2000:
            return
        cutoff = now - max(window, 60) * 10
        for k in [k for k, v in self._last_alert.items() if v < cutoff]:
            self._last_alert.pop(k, None)
