"""封禁业务编排：从 MainWindow 下沉到独立 QObject 协调器。

历史背景：MainWindow 体量过大，虽然事件泵 / 统计 / 状态栏已下沉到
EventPumpMixin，但「封禁编排」区块（单条 / 批量封禁的入口、校验、后台线程
执行、批量完成回刷）仍留在主窗类体内。这里把它拆到独立协调器 BanCoordinator，
主窗通过组合持有一个实例，只保留信号与装配。

方法论：封禁编排逻辑在协调器内，但需要主窗 / mixin 的界面能力（_set_status /
_restart_as_admin / _refresh_current_page / batch_ban_done 信号）时，统一经
self._owner 访问。这是「编排层组合持主窗回调」的保真下沉，不改变业务逻辑一行。
"""

import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from app import ban_service
from core import firewall
from core.database import find_active_ban_by_ip
from core.event_bus import bus
from core.logger import get_logger
from gui.page_bans import ManualBanDialog
from gui.theme import C
from qtcompat import QDialog, QMessageBox, QObject

if TYPE_CHECKING:  # 仅类型解析用，避免 import 环
    from gui.main_window import MainWindow

# 注意：BanDurationDialog / BatchBanDialog 定义在 gui.main_window（模块顶部、
# MainWindow 类之前）。若在模块级 `from gui.main_window import ...` 会与
# main_window 的 `from gui.ban_coordinator import BanCoordinator` 构成循环
# import（main_window 先加载 ban_coordinator，此时其类还没定义）。故这里
# 在两个用到它们的入口方法内做局部 import，保持模块加载顺序干净。


log = get_logger(__name__)


class BanCoordinator(QObject):
    """封禁编排协调器：单条 / 批量封禁的入口与后台线程调度。

    owner 是 MainWindow 实例。凡需主窗 / mixin 的界面能力（_set_status /
    _restart_as_admin / _refresh_current_page / batch_ban_done 信号），
    统一经 self._owner 访问 —— 便于把封禁业务流程与 Qt 控件解耦、可独立单测。
    """

    def __init__(self, owner: "MainWindow") -> None:
        super().__init__(owner)
        self._owner = owner

    # 状态栏转发：mixin 的 _set_status 实际挂在 owner 上，这里收一个薄转发，
    # 协调器内部统一用它，避免四处写 self._owner._set_status。
    def _status(self, text: str, color: Optional[str] = None, auto_clear_ms: int = 0) -> None:
        self._owner._set_status(text, color, auto_clear_ms)

    def request_ban(self, ip: str, score: int = 0, reason: str = "") -> None:
        """封禁入口：右键菜单 / 风险事件页 / 封禁页 / 手动输入"""
        if not ip:
            dlg = ManualBanDialog("", self._owner)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            ip2, reason2, dur = dlg.values()
            self._do_ban(ip2, 0, reason2, dur)
            return

        # 唯一校验入口（同时挡掉命令注入与受保护地址）
        try:
            rec = ban_service.prepare(ip, score, reason, 0)
        except ban_service.BanError as e:
            QMessageBox.warning(self._owner, "无法封禁", str(e))
            return

        if not firewall.is_admin():
            if (
                QMessageBox.question(
                    self._owner,
                    "权限不足",
                    "封禁需要管理员权限。\n\n是否以管理员身份重启程序？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self._owner._restart_as_admin()
            return

        try:
            exists = find_active_ban_by_ip(rec.ip)
        except Exception:
            log.exception("查询已有封禁失败 ip=%s", rec.ip)
            exists = None
        if exists:
            QMessageBox.information(
                self._owner, "已封禁", f"{rec.ip} 已处于封禁状态（记录 #{exists.id}）。"
            )
            return

        from gui.main_window import BanDurationDialog  # 局部导入避免循环 import

        dur_dlg = BanDurationDialog(rec.ip, score, reason, self._owner)
        if dur_dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._do_ban(rec.ip, score, reason, dur_dlg.duration_sec())

    def _do_ban(self, ip: str, score: int, reason: str, duration_sec: int) -> None:
        """后台线程执行真实封禁（防火墙命令可能耗时数秒）"""
        self._status(f"正在封禁 {ip} …", C.warning)

        def work():
            ban_id, err = ban_service.execute(ip, score, reason, duration_sec)
            if ban_id is None:
                # 校验失败等前置错误不会走 ban_service 的事件投递，这里补一条
                bus.emit_ban(
                    {
                        "ip": ip,
                        "ok": False,
                        "rule_name": "",
                        "error": err,
                        "ban_id": None,
                        "source": "manual",
                    }
                )

        threading.Thread(target=work, daemon=True, name=f"ban-{ip}").start()

    def request_ban_many(self, items: List[Dict[str, Any]]) -> None:
        """批量封禁入口（风险事件页「一键封禁」）。

        流程与单条封禁一致，区别只在「确认」与「执行」被批量化：
        校验逐条做（唯一校验入口不能绕），确认只做一次，执行放在同一个
        后台线程里串行跑 —— 每个 IP 起一个线程会让 30 个 PowerShell 进程
        同时抢 CPU，反而更慢、也更容易触发杀软拦截。
        """
        if not items:
            return

        if not firewall.is_admin():
            if (
                QMessageBox.question(
                    self._owner,
                    "权限不足",
                    f"批量封禁 {len(items)} 个 IP 需要管理员权限。\n\n是否以管理员身份重启程序？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self._owner._restart_as_admin()
            return

        prepared = []
        skipped: List[tuple] = []
        for it in items:
            ip = str(it.get("ip") or "")
            try:
                rec = ban_service.prepare(
                    ip, int(it.get("score") or 0), str(it.get("reason") or ""), 0
                )
            except ban_service.BanError as e:
                skipped.append((ip or "?", str(e)))
                continue
            try:
                if find_active_ban_by_ip(rec.ip) is not None:
                    skipped.append((rec.ip, "已在封禁中"))
                    continue
            except Exception:
                log.exception("批量封禁：查询已有封禁失败 ip=%s", rec.ip)
            prepared.append(rec)

        if not prepared:
            detail = "\n".join(f"· {ip}：{why}" for ip, why in skipped[:10])
            QMessageBox.information(
                self._owner,
                "无需封禁",
                "选中的 IP 全部被跳过：\n\n" + detail if detail else "没有可封禁的 IP。",
            )
            return

        from gui.main_window import BatchBanDialog  # 局部导入避免循环 import

        dlg = BatchBanDialog([rec.ip for rec in prepared], skipped, self._owner)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        duration = dlg.duration_sec()
        self._status(f"正在批量封禁 {len(prepared)} 个 IP …", C.warning)

        def work():
            ok = 0
            fail = 0
            # 事件状态不在这里回填：`ban_service.execute` 成功时已按 IP 把该 IP
            # 下所有「未处理」事件标成「已确认」，且是在投递封禁事件**之前**做的，
            # 所以界面收到结果时刷新到的就是最终状态。
            for rec in prepared:
                ban_id, err = ban_service.execute(
                    rec.ip, int(rec.risk_score or 0), rec.reason or "", duration
                )
                if ban_id is None:
                    fail += 1
                    # 前置校验失败不会走 ban_service 的事件投递，这里补一条，
                    # 否则界面上只会看到「正在批量封禁」，永远等不到结果
                    bus.emit_ban(
                        {
                            "ip": rec.ip,
                            "ok": False,
                            "rule_name": "",
                            "error": err,
                            "ban_id": None,
                            "source": "manual",
                        }
                    )
                else:
                    ok += 1
            self._owner.batch_ban_done.emit(ok, fail)

        threading.Thread(target=work, daemon=True, name="ban-batch").start()

    def _on_batch_ban_done(self, ok: int, fail: int) -> None:
        if fail:
            self._status(f"批量封禁完成：成功 {ok} 个，失败 {fail} 个（详见运行日志）", C.warning)
        else:
            self._status(f"批量封禁完成：{ok} 个 IP 已封禁", C.success)
        # 状态栏改完必须把**当前页**重刷一遍：封禁顺带改了事件的处理状态与
        # 行内按钮的「已封禁」态，不刷新的话用户看到的还是封禁前的快照，
        # 会以为一键封禁没生效（这正是「状态不跟操作联动」的主诉）。
        self._owner._refresh_current_page()
