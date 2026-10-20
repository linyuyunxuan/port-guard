"""
PortGuard — 操作审计埋点（不依赖 Qt，可脱离界面单测）

分工：
- `core/database.py` 只提供 audit_log 的原始读写（insert_audit / query_audit /
  count_audit），**不带任何业务语义**；
- 本模块负责「谁在什么时候干了什么」的口径与埋点封装。

为什么埋点不放进 `core/database.py` 的写函数里：那些函数（insert_ban /
update_ban / delete_bans …）被 GUI、业务层、测试多处直接调用，一旦为了记审计
给它们加一个 actor 参数，所有调用点都得跟着改，而其中很多地方压根不知道
actor 是谁。埋点跟着**业务动作**走，不跟着**SQL**走。

⚠️ 审计写失败绝不能反过来中断业务动作：防火墙规则已经加了、数据库状态已经
改了，却因为审计表写不进去而回滚，那是把记账系统变成了业务系统的单点故障。
所以 `record()` 内部吞掉所有异常，只留一条 warning 日志。

actor 口径（三种值，不要再加第四种）：
- 本机交互（点按钮、改设置）→ `os.environ["USERNAME"]`，即当前登录的 Windows 用户；
- 程序自己（定时器、到期巡检、定期清理、自动封禁）→ `system`；
- HTTP 上报触发的动作 → `http:<来源 IP>`，用来区分「哪个业务系统让我们封的」。
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from core.database import insert_audit
from core.logger import get_logger
from core.models import now_ms

log = get_logger(__name__)


# ═══════════════════════════════════════════════════════════
#  actor
# ═══════════════════════════════════════════════════════════

#: 程序自身触发（定时器 / 巡检 / 自动封禁），不是某个具体的人
ACTOR_SYSTEM = "system"
#: HTTP 上报来源的前缀，完整值形如 `http:203.0.113.7`
ACTOR_HTTP_PREFIX = "http:"


def actor_local() -> str:
    """
    本机交互者：Windows 上 `USERNAME` 必然存在（服务会话可能没有），
    退回 `USER`（Linux / CI），都没有才给 `unknown`。
    """
    name = (os.environ.get("USERNAME") or os.environ.get("USER") or "").strip()
    return name or "unknown"


def actor_http(ip: str) -> str:
    """HTTP 上报来源。IP 为空时给 `http:unknown`，不要退化成裸前缀"""
    return ACTOR_HTTP_PREFIX + (str(ip).strip() or "unknown")


def actor_label(actor: str) -> str:
    """把 actor 翻成给人看的一句话（界面展示用）"""
    if not actor:
        return "未知"
    if actor == ACTOR_SYSTEM:
        return "程序自动"
    if actor.startswith(ACTOR_HTTP_PREFIX):
        return "上报 " + actor[len(ACTOR_HTTP_PREFIX) :]
    return actor


# ═══════════════════════════════════════════════════════════
#  action / result
# ═══════════════════════════════════════════════════════════

RESULT_OK = "ok"  # 动作成功
RESULT_FAIL = "fail"  # 动作失败（防火墙报错、写库异常等）
RESULT_SKIP = "skipped"  # 动作没执行（如该 IP 已在封禁中）

ACTION_BAN_MANUAL = "ban.manual"  # 手动封禁
ACTION_BAN_AUTO = "ban.auto"  # 自动模式封禁
ACTION_BAN_UNBAN = "ban.unban"  # 解封单条
ACTION_BAN_UNBAN_ALL = "ban.unban_all"  # 一键解封
ACTION_BAN_EXPIRE = "ban.expire"  # 到期自动解封
ACTION_BAN_RECONCILE = "ban.reconcile"  # 与防火墙对账修正
ACTION_BAN_DELETE = "ban.delete"  # 删除封禁记录
ACTION_EVENT_CONFIRM = "event.confirm"  # 确认风险事件
ACTION_EVENT_IGNORE = "event.ignore"  # 忽略风险事件
ACTION_EVENT_DELETE = "event.delete"  # 删除风险事件
ACTION_DATA_CLEAR = "data.clear"  # 清空全部日志
ACTION_DATA_CLEANUP = "data.cleanup"  # 定期清理
ACTION_SETTINGS_SAVE = "settings.save"  # 保存设置
ACTION_RULES_SAVE = "rules.save"  # 保存规则
ACTION_LIST_SAVE = "list.save"  # 黑白名单变更
ACTION_XDB_SYNC = "xdb.sync"  # 离线库同步
ACTION_XDB_ROLLBACK = "xdb.rollback"  # 离线库回滚

#: 界面下拉框用：action → 中文名。顺序即下拉顺序（按业务分组）。
ACTION_LABELS: Dict[str, str] = {
    ACTION_BAN_MANUAL: "封禁·手动",
    ACTION_BAN_AUTO: "封禁·自动",
    ACTION_BAN_UNBAN: "解封",
    ACTION_BAN_UNBAN_ALL: "一键解封",
    ACTION_BAN_EXPIRE: "到期解封",
    ACTION_BAN_RECONCILE: "防火墙对账",
    ACTION_BAN_DELETE: "删除封禁记录",
    ACTION_EVENT_CONFIRM: "确认事件",
    ACTION_EVENT_IGNORE: "忽略事件",
    ACTION_EVENT_DELETE: "删除事件",
    ACTION_DATA_CLEAR: "清空日志",
    ACTION_DATA_CLEANUP: "定期清理",
    ACTION_SETTINGS_SAVE: "保存设置",
    ACTION_RULES_SAVE: "保存规则",
    ACTION_LIST_SAVE: "黑白名单变更",
    ACTION_XDB_SYNC: "离线库同步",
    ACTION_XDB_ROLLBACK: "离线库回滚",
}

#: 稳定的 action 枚举顺序（下拉框 / 测试都按这个来，别用 dict 顺序）
ACTIONS: List[str] = list(ACTION_LABELS.keys())


def action_label(action: str) -> str:
    """action 的中文名；未知 action 原样返回（新增动作漏登记时不至于显示空白）"""
    return ACTION_LABELS.get(action, action)


# ═══════════════════════════════════════════════════════════
#  写入
# ═══════════════════════════════════════════════════════════


def dumps(value: Any) -> Optional[str]:
    """
    把 before/after 快照序列化成 JSON 文本；`None` 表示「没有这一栏」。

    `default=str` 是刻意的：快照里经常混着 datetime、Decimal、`_IPSet` 这类
    非 JSON 原生类型，不兜住的话整条审计会因为一个 datetime 全丢。
    `ensure_ascii=False` 也是刻意的 —— 归属地、规则名都是中文，转义成
    \\uXXXX 之后界面和排查时都没法看。
    """
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except Exception:
        # 循环引用等极端情况：退成 repr，宁可难看也不要丢记录
        try:
            return json.dumps(repr(value)[:2000], ensure_ascii=False)
        except Exception:
            return None


def record(
    action: str,
    *,
    actor: Optional[str] = None,
    target_type: str = "",
    target_id: Optional[Any] = None,
    summary: str = "",
    before: Any = None,
    after: Any = None,
    result: str = RESULT_OK,
    detail: str = "",
) -> int:
    """
    写一条审计记录，返回 rowid（失败返回 0）。

    **绝不抛异常** —— 见模块顶部说明。调用方不需要 try/except。
    `actor` 留空表示「本机交互」，自动取当前登录用户名。
    """
    try:
        return insert_audit(
            ts=now_ms(),
            actor=actor or actor_local(),
            action=action,
            target_type=target_type,
            target_id=None if target_id is None else str(target_id),
            summary=summary,
            before_json=dumps(before),
            after_json=dumps(after),
            result=result,
            detail=detail,
        )
    except Exception:
        log.warning("写入审计记录失败（不影响业务动作）action=%s", action, exc_info=True)
        return 0


# ═══════════════════════════════════════════════════════════
#  展示辅助
# ═══════════════════════════════════════════════════════════


def fmt_ts(ms: Optional[int]) -> str:
    """epoch 毫秒 → `YYYY-MM-DD HH:MM:SS`（本地时区）。0 / None → 空串"""
    if not ms:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ms) / 1000.0))
    except (ValueError, OSError, OverflowError):
        return ""


#: 快照文本在界面上的截断长度。完整 JSON 放 tooltip / 详情里，别撑爆表格
SNAPSHOT_MAX = 400


def fmt_snapshot(text: Optional[str], limit: int = SNAPSHOT_MAX) -> str:
    """审计快照的展示文本：空→`-`，过长则截断加省略号"""
    if not text:
        return "-"
    if len(text) <= limit:
        return text
    return text[:limit] + "…"
