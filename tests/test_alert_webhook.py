"""PortGuard — 外部告警推送（Webhook）的护栏

这组用例盯的是**安全边界**，不是「消息发得好看」：

1. 默认必须是关的 —— v1.2.0 好不容易把攻击面从全网收回到本机输入，
   不能因为加了个可选功能又还回去；
2. 只允许 http / https，且**不许指向本机、内网、保留地址**
   —— 否则这个设置项就成了一根现成的 SSRF 探针；
3. 地址里几乎必然带机器人 key，**日志与界面只许出现 scheme://host**；
4. 推送在后台线程跑、失败只记日志不重试不抛 —— 告警是高频事件，
   一次网络抖动不能把判定链带崩。
"""

import contextlib
import json
import logging
import threading
import time
import urllib.error
from typing import Any, Dict, Iterator, List, Tuple

import pytest

from core import alert_webhook
from core import settings as cfg

#: 形如企业微信机器人地址（key 是要藏起来的那部分）
HOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=SECRET-KEY-1234"


class _LogCatcher(logging.Handler):
    """`core.logger` 把 propagate 关掉了，caplog 抓不到 —— 直接挂到模块自己的 logger 上"""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


@contextlib.contextmanager
def _capture_logs() -> Iterator[_LogCatcher]:
    catcher = _LogCatcher()
    alert_webhook.log.addHandler(catcher)
    try:
        yield catcher
    finally:
        alert_webhook.log.removeHandler(catcher)


@pytest.fixture(autouse=True)
def _clean_throttle():
    """模块级节流表是进程内状态，用例之间必须清干净"""
    alert_webhook.reset_throttle()
    yield
    alert_webhook.reset_throttle()


def _configure(url: str = HOOK, enabled: bool = True, level: str = "critical") -> None:
    """写设置缓存。

    `persist=False`：单元测试不落库（`fresh_db` 删库后并不保证已建表），
    但缓存照样生效，`_settings()` 读到就是这份值；收尾 `invalidate()` 会清掉。
    """
    cfg.set("alert_webhook_enabled", "1" if enabled else "0", persist=False)
    cfg.set("alert_webhook_url", url, persist=False)
    cfg.set("alert_webhook_level", level, persist=False)


def _alert(**kw: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "ip": "113.118.1.1",
        "level": "critical",
        "score": 100,
        "reason": "暴力破解",
        "local_port": 3389,
        "disposition": "block",
    }
    base.update(kw)
    return base


def _settings(enabled: bool = True, url: str = HOOK, level: str = "critical") -> Dict[str, Any]:
    """绕开数据库，直接构造一份设置快照（`should_send` 支持显式传入）"""
    return {"enabled": enabled, "url": url, "level": level}


# ═══════════════════════════════════════════════════════════
#  默认关闭
# ═══════════════════════════════════════════════════════════


def test_default_settings_keep_webhook_off() -> None:
    from core.config import DEFAULT_SETTINGS

    assert DEFAULT_SETTINGS["alert_webhook_enabled"] == "0"
    assert DEFAULT_SETTINGS["alert_webhook_url"] == ""


def test_send_async_is_noop_when_settings_are_default() -> None:
    """默认设置下连线程都不该起"""
    before = threading.active_count()
    assert alert_webhook.send_async(_alert()) is False
    # 后台线程名固定，直接查名字比数活跃线程稳
    assert not [t for t in threading.enumerate() if t.name == "alert-webhook"]
    assert threading.active_count() <= before


# ═══════════════════════════════════════════════════════════
#  地址校验（SSRF 防线）
# ═══════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/hook",
        "file:///C:/Windows/win.ini",
        "javascript:alert(1)",
        "example.com/hook",  # 没有 scheme
        "",
        "   ",
    ],
)
def test_validate_url_rejects_non_http_scheme(url: str) -> None:
    ok, why = alert_webhook.validate_url(url)
    assert ok is False
    assert why


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://localhost:8080/hook",
        "https://localhost.localdomain/hook",
        "http://10.0.0.1/hook",
        "http://172.16.5.4:9000/hook",
        "http://192.168.1.100/hook",
        "http://169.254.169.254/latest/meta-data/",  # 云元数据地址
        "http://[::1]/hook",
        "http://intranet/hook",  # 单标签：只能靠 DNS 后缀补全，必然是内网
        "http://api.corp.local/hook",  # 内网后缀
    ],
)
def test_validate_url_rejects_private_targets(url: str) -> None:
    ok, why = alert_webhook.validate_url(url)
    assert ok is False, f"{url} 不该通过校验"
    assert "内网" in why or "保留" in why


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x",
        "http://admin@example.com/hook",
    ],
)
def test_validate_url_rejects_credentials(url: str) -> None:
    ok, why = alert_webhook.validate_url(url)
    assert ok is False
    assert "用户名密码" in why


@pytest.mark.parametrize(
    "url",
    [
        HOOK,
        "https://oapi.dingtalk.com/robot/send?access_token=abc",
        "http://alert-gw.example.com:8080/hook",
    ],
)
def test_validate_url_accepts_public_endpoints(url: str) -> None:
    ok, why = alert_webhook.validate_url(url)
    assert ok is True
    assert why == ""


def test_mask_url_hides_the_key() -> None:
    masked = alert_webhook.mask_url(HOOK)
    assert "SECRET-KEY-1234" not in masked
    assert masked == "https://qyapi.weixin.qq.com/…"


def test_mask_url_keeps_port_and_handles_empty() -> None:
    assert alert_webhook.mask_url("http://alert-gw.example.com:8080/x?k=1") == (
        "http://alert-gw.example.com:8080/…"
    )
    assert alert_webhook.mask_url("") == "(未配置)"


# ═══════════════════════════════════════════════════════════
#  该不该推（四关）
# ═══════════════════════════════════════════════════════════


def test_should_send_false_when_disabled() -> None:
    assert alert_webhook.should_send(_alert(), _settings(enabled=False)) is False


def test_should_send_false_when_url_empty() -> None:
    assert alert_webhook.should_send(_alert(), _settings(url="")) is False


def test_should_send_false_when_level_below_threshold() -> None:
    s = _settings(level="critical")
    assert alert_webhook.should_send(_alert(level="high"), s) is False
    assert alert_webhook.should_send(_alert(level="medium"), s) is False
    assert alert_webhook.should_send(_alert(level="critical"), s) is True


def test_should_send_honours_lower_threshold() -> None:
    """阈值调到 high 时，high 也要推（不是只认 critical）"""
    assert alert_webhook.should_send(_alert(level="high"), _settings(level="high")) is True
    assert alert_webhook.should_send(_alert(level="medium"), _settings(level="high")) is False


def test_should_send_throttles_same_ip_within_window() -> None:
    s = _settings()
    assert alert_webhook.should_send(_alert(), s) is True
    assert alert_webhook.should_send(_alert(), s) is False, "同一 IP 60 秒内不该重复推送"
    assert alert_webhook.should_send(_alert(ip="113.118.1.2"), s) is True


def test_throttle_expires() -> None:
    s = _settings()
    assert alert_webhook.should_send(_alert(), s) is True
    # 把「上次推送时间」往前推超过窗口，等价于等过了一分钟
    stale = time.time() - alert_webhook.THROTTLE_SEC - 1
    with alert_webhook._lock:  # 直接验证节流表的过期语义
        alert_webhook._last_sent["113.118.1.1"] = stale
    assert alert_webhook.should_send(_alert(), s) is True


def test_reset_throttle_clears_window() -> None:
    s = _settings()
    assert alert_webhook.should_send(_alert(), s) is True
    alert_webhook.reset_throttle()
    assert alert_webhook.should_send(_alert(), s) is True


def test_should_send_reads_settings_when_not_given(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure()
    assert alert_webhook.should_send(_alert()) is True


# ═══════════════════════════════════════════════════════════
#  消息体
# ═══════════════════════════════════════════════════════════


def test_build_content_carries_the_essentials() -> None:
    text = alert_webhook.build_content(_alert())
    assert "113.118.1.1" in text
    assert "严重" in text
    assert "3389" in text
    assert "暴力破解" in text
    assert "已自动拦截" in text


def test_build_content_tolerates_sparse_alert() -> None:
    """字段缺失不能抛异常（fwlog 通道的记录可能没有端口/归属地）"""
    text = alert_webhook.build_content({"ip": "1.2.3.4", "level": "high"})
    assert "1.2.3.4" in text
    assert "高风险" in text


def test_build_payload_is_wechat_compatible_json() -> None:
    raw = alert_webhook.build_payload(_alert())
    body = json.loads(raw.decode("utf-8"))
    assert body["msgtype"] == "text"
    assert "113.118.1.1" in body["text"]["content"]


# ═══════════════════════════════════════════════════════════
#  发送
# ═══════════════════════════════════════════════════════════


class _Resp:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_post_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alert_webhook.urllib.request, "urlopen", lambda *a, **k: _Resp(204))
    ok, why = alert_webhook.post(HOOK, b"{}")
    assert ok is True
    assert why == ""


def test_post_reports_http_error_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> Any:
        raise urllib.error.HTTPError(HOOK, 403, "Forbidden", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(alert_webhook.urllib.request, "urlopen", boom)
    ok, why = alert_webhook.post(HOOK, b"{}")
    assert ok is False
    assert "403" in why


def test_post_reports_network_failure_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr(alert_webhook.urllib.request, "urlopen", boom)
    ok, why = alert_webhook.post(HOOK, b"{}")
    assert ok is False
    assert "TimeoutError" in why


def _wait_for(pred, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def test_send_async_runs_in_background_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure()

    sent: List[Tuple[str, bytes]] = []
    seen: List[str] = []

    def fake_post(url: str, payload: bytes, timeout: float = 0.0) -> Tuple[bool, str]:
        sent.append((url, payload))
        seen.append(threading.current_thread().name)
        return True, ""

    monkeypatch.setattr(alert_webhook, "post", fake_post)
    with _capture_logs() as logs:
        assert alert_webhook.send_async(_alert()) is True
        assert _wait_for(lambda: bool(sent)), "推送没有在后台发出"
        assert _wait_for(lambda: bool(logs.lines)), "推送结果没有写日志"

    assert seen and all(n.startswith("alert-webhook") and n != "MainThread" for n in seen), (
        f"推送必须跑在后台线程池，不能占界面线程：{seen}"
    )
    assert "113.118.1.1" in sent[0][1].decode("utf-8")

    # 日志里只许出现 host，key 绝不能落盘
    logged = "\n".join(logs.lines)
    assert "qyapi.weixin.qq.com" in logged
    assert "SECRET-KEY-1234" not in logged


def test_send_async_refuses_invalid_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(url="http://127.0.0.1:8080/hook")

    called: List[str] = []

    def fake_post(url: str, payload: bytes, timeout: float = 0.0) -> Tuple[bool, str]:
        called.append(url)
        return True, ""

    monkeypatch.setattr(alert_webhook, "post", fake_post)

    assert alert_webhook.send_async(_alert()) is False
    assert called == [], "地址没过校验就绝不能发出请求"


def test_send_async_swallows_post_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """发送失败只记日志：不能把异常抛回告警调用方"""
    _configure()

    done: List[bool] = []

    def fake_post(url: str, payload: bytes, timeout: float = 0.0) -> Tuple[bool, str]:
        done.append(False)
        return False, "HTTP 500"

    monkeypatch.setattr(alert_webhook, "post", fake_post)
    assert alert_webhook.send_async(_alert()) is True
    assert _wait_for(lambda: bool(done))


# ═══════════════════════════════════════════════════════════
#  与本地告警的挂接
# ═══════════════════════════════════════════════════════════


def test_alerter_forwards_to_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    """托盘告警之后要顺带调一次推送（哪怕是关着的，也只多一次内存判断）"""
    from core.alerts import Alerter

    seen: List[Dict[str, Any]] = []

    def fake_send(alert: Dict[str, Any]) -> bool:
        seen.append(alert)
        return False

    monkeypatch.setattr(alert_webhook, "send_async", fake_send)
    cfg.set("alert_sound", "0", persist=False)  # 别在测试机上真的响一声

    alerter = Alerter()
    assert alerter.notify(_alert(level="critical")) is True
    assert seen and seen[0]["ip"] == "113.118.1.1"


def test_webhook_failure_never_blocks_local_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    from core import alerts as alerts_mod

    def boom(alert: Any) -> bool:
        raise RuntimeError("webhook 炸了")

    monkeypatch.setattr(alert_webhook, "send_async", boom)
    cfg.set("alert_sound", "0", persist=False)
    alerter = alerts_mod.Alerter()
    # notify 依然要返回 True，异常被 _notify_webhook 吞掉
    assert alerter.notify(_alert(level="critical")) is True


def test_send_async_stats_count_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """P2-10 可观测性：stats() 必须如实记下 成功/失败/已安排 三个计数。

    变异：删掉 work() 里的计数分支 → 本例变红（差值全 0）。
    """
    _configure()
    before = dict(alert_webhook.stats())

    monkeypatch.setattr(alert_webhook, "post", lambda *a, **kw: (True, ""))
    assert alert_webhook.send_async(_alert()) is True
    assert _wait_for(lambda: alert_webhook.stats()["sent_ok"] > before["sent_ok"])

    monkeypatch.setattr(alert_webhook, "post", lambda *a, **kw: (False, "HTTP 500"))
    # 换个 IP 绕开 60s 合并窗口
    assert alert_webhook.send_async(_alert(ip="198.51.100.42")) is True
    assert _wait_for(lambda: alert_webhook.stats()["sent_fail"] > before["sent_fail"]), (
        "失败必须计入 sent_fail，接收端挂了要能从计数上看出来"
    )

    after = alert_webhook.stats()
    assert after["sent_ok"] == before["sent_ok"] + 1
    assert after["sent_fail"] == before["sent_fail"] + 1
    assert after["scheduled"] >= before["scheduled"] + 2
