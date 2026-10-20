"""
Webhook 外部告警通道测试（core/webhook.py + app/notify_service.py）

全部用例都打桩 `urllib.request.OpenerDirector.open`，**绝不真发网络请求**。
打桩点选在 opener 层而非 urlopen：这样连「有没有按 S310 的要求先构造
Request」「timeout 有没有真的传下去」都能一起验到。
"""

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, List, cast

import pytest

from app import notify_service
from core import settings as cfg
from core import webhook
from core.database import init_db
from core.validators import InvalidURL

URL = "https://hooks.example.com/portguard"
SECRET = "s3cr3t-中文密钥"

ALERT = {
    "ip": "203.0.113.10",
    "level": "critical",
    "score": 95,
    "reason": "疑似扫描",
    "geo": "中国·广东·深圳",
    "local_port": 3389,
}


class _Resp:
    """假响应：够 urllib 用就行（status / read / getcode / close）"""

    def __init__(self, status: int = 200, body: bytes = b"ok"):
        self.status = status
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        pass


class _Recorder:
    """拦截 opener.open，记录每次请求并按脚本返回 / 抛异常"""

    def __init__(self, monkeypatch):
        self.calls = []  # [(Request, timeout)]
        self.script = [_Resp()]
        self.delay = 0.0
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", self._open)

    def _open(self, req, data=None, timeout=None):
        self.calls.append((req, timeout))
        if self.delay:
            time.sleep(self.delay)
        item = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def count(self) -> int:
        return len(self.calls)

    @property
    def last(self):
        return self.calls[-1][0]

    @property
    def last_timeout(self):
        return self.calls[-1][1]

    def header(self, name: str, idx: int = -1):
        """请求头大小写不敏感地取（Request 会把首字母大写）"""
        for k, v in self.calls[idx][0].headers.items():
            if k.lower() == name.lower():
                return v
        return None


def _hook_cfg(**over) -> None:
    """写一套「已启用」的 Webhook 配置"""
    base = {
        "webhook_enabled": "1",
        "webhook_url": URL,
        "webhook_secret": "",
        "webhook_timeout_sec": "5",
        "webhook_min_level": "high",
        "webhook_max_per_min": "60",
        "webhook_verify_ssl": "1",
        "webhook_allow_http": "0",
    }
    base.update({k: str(v) for k, v in over.items()})
    # persist=False：只用内存缓存。业务代码读设置走的正是这条路径，
    # 而每次都落库在慢盘上会明显拖长整套用例。
    for k, v in base.items():
        cfg.set(k, v, persist=False)


@pytest.fixture
def rec(monkeypatch):
    return _Recorder(monkeypatch)


@pytest.fixture
def svc():
    s = notify_service.NotifyService()
    yield s
    s.stop(timeout=5.0)


@pytest.fixture
def send_now(monkeypatch):
    """把重试等待压成 0，但**保留**退避次数与顺序可观测"""
    monkeypatch.setattr(notify_service, "RETRY_DELAYS", (0.0, 0.0))


#: 排空队列的等待上限。给得宽是刻意的：机器忙（别人并行跑全量）时线程调度会变慢，
#: 而 wait_idle 是**条件等待**不是固定 sleep —— 超时给大只是把上界放宽，
#: 正常情况仍是处理完立刻返回，不会影响用例时长。
DRAIN_TIMEOUT = 15.0


def _drain(svc) -> None:
    """等到后台线程真的处理完，超时则给出可读的失败信息（而不是让后面的计数断言红）"""
    assert svc.wait_idle(DRAIN_TIMEOUT), (
        f"{DRAIN_TIMEOUT}s 内队列没排空：{svc.stats()}，last_error={svc.last_error!r}"
    )


# ═══════════════════════════════════════════
#  静默 / 门槛 / 限流
# ═══════════════════════════════════════════


def test_disabled_or_url_empty_sends_nothing(isolated_env, rec, svc):
    init_db()
    _hook_cfg(webhook_enabled="0")
    assert svc.send(dict(ALERT)) is False

    _hook_cfg(webhook_url="")
    assert svc.send(dict(ALERT)) is False

    _drain(svc)
    assert rec.count == 0, "未启用 / 未配地址时必须一条都不发（且不能刷日志报错）"
    assert svc.pending == 0


def test_level_gate_filters_lower_alerts(isolated_env, rec, svc):
    init_db()
    _hook_cfg(webhook_min_level="high")

    low = dict(ALERT, level="medium")
    assert svc.send(low) is False
    assert svc.send(dict(ALERT)) is True  # critical ≥ high

    _drain(svc)
    assert rec.count == 1
    assert svc.skipped == 1


def test_wait_idle_waits_for_inflight_item(isolated_env, rec, svc, monkeypatch):
    """回归：元素已出队、但还没处理完时，wait_idle 必须继续等。

    原实现按「队列空 + 正在干活」判定空闲，而「正在干活」是在取出元素之后才置的 ——
    中间那个窗口会让 wait_idle 立刻返回，count 还是 0，负载高时便间歇红。
    这里人为拉长该窗口（等价于机器忙时的线程调度），锁住修复。
    """
    init_db()
    _hook_cfg()
    real_get = svc._q.get

    def slow_get(*args, **kwargs):
        item = real_get(*args, **kwargs)
        time.sleep(0.3)  # 模拟「已出队、尚未处理」这段被拉长
        return item

    monkeypatch.setattr(svc._q, "get", slow_get)
    assert svc.send(dict(ALERT)) is True

    _drain(svc)
    assert rec.count == 1, "wait_idle 提前返回了：出队后、处理前的窗口没有覆盖住"


def test_rate_limit_caps_burst(isolated_env, rec, svc):
    """一分钟 60 条 = 每秒 1 条、桶容量 1：连发 5 条只应该出去 1 条"""
    init_db()
    _hook_cfg(webhook_max_per_min="60")
    for _ in range(5):
        svc.send(dict(ALERT))

    _drain(svc)
    assert rec.count == 1, "去掉限流这里会变成 5 —— 这条就是为此而写"
    assert svc.sent == 1
    assert svc.throttled == 4


# ═══════════════════════════════════════════
#  请求内容：payload / 签名 / 超时
# ═══════════════════════════════════════════


def test_payload_and_headers(isolated_env, rec, svc):
    init_db()
    _hook_cfg()
    svc.send(dict(ALERT))
    _drain(svc)

    req = rec.last
    assert isinstance(req.data, bytes), "py3.8 的 Request(data=) 只接受 bytes"
    body = req.data
    payload = json.loads(body.decode("utf-8"))
    for k in ("type", "ts", "ip", "level", "score", "reason", "geo", "local_port"):
        assert k in payload
    assert payload["ip"] == ALERT["ip"]
    assert payload["local_port"] == 3389
    assert "深圳" in body.decode("utf-8"), "ensure_ascii=False：中文不该被转义"
    assert rec.last_timeout == 5.0, "超时必须真的传给 opener"


def test_signature_matches_hmac_of_body(isolated_env, rec, svc):
    init_db()
    _hook_cfg(webhook_secret=SECRET)
    svc.send(dict(ALERT))
    _drain(svc)

    body = rec.last.data
    got = rec.header(webhook.SIG_HEADER)
    assert got == webhook.signature(body, SECRET)
    assert got.startswith("sha256=")
    # 变异验证：把签名改成常量或算错密钥，这里必须红
    assert got != webhook.signature(body, SECRET + "x")


def test_no_signature_without_secret(isolated_env, rec, svc):
    init_db()
    _hook_cfg(webhook_secret="")
    svc.send(dict(ALERT))
    _drain(svc)
    assert rec.header(webhook.SIG_HEADER) is None
    assert rec.header(webhook.TS_HEADER)


# ═══════════════════════════════════════════
#  失败重试 / 退避 / 错误归类
# ═══════════════════════════════════════════


def test_retry_then_success(isolated_env, rec, svc, monkeypatch):
    init_db()
    _hook_cfg()
    sleeps: List[float] = []
    monkeypatch.setattr(notify_service.time, "sleep", sleeps.append)
    rec.script = [
        urllib.error.URLError("connection reset"),
        urllib.error.URLError("connection reset"),
        _Resp(200),
    ]

    svc.send(dict(ALERT))
    _drain(svc)
    assert rec.count == 3, "失败必须重试（共 3 次尝试）"
    # time.sleep 被打桩后 wait_idle 内部的轮询也会进来，只挑重试的等待
    assert [s for s in sleeps if s > 0.1] == [1.0, 3.0], "退避必须是递增的 1s / 3s"
    assert svc.sent == 1 and svc.failed == 0


def test_all_failed_counts_once(isolated_env, rec, svc, send_now):
    init_db()
    _hook_cfg()
    rec.script = [urllib.error.URLError("down")]
    svc.send(dict(ALERT))
    _drain(svc)
    assert rec.count == 3
    assert svc.sent == 0 and svc.failed == 1


def test_http_4xx_is_not_retried(isolated_env, rec, svc, send_now):
    init_db()
    _hook_cfg()
    rec.script = [_Resp(404)]
    svc.send(dict(ALERT))
    _drain(svc)
    assert rec.count == 1, "4xx 重试没有意义"
    assert svc.failed == 1


def test_invalid_url_never_touches_network(isolated_env, rec, svc, send_now):
    init_db()
    _hook_cfg(webhook_url="http://public.example.com/hook")  # 明文 http 且是域名
    svc.send(dict(ALERT))
    _drain(svc)
    assert rec.count == 0
    assert svc.failed == 1
    assert "https" in svc.last_error


def test_timeout_is_classified(isolated_env, rec):
    init_db()
    rec.script = [socket.timeout("timed out")]
    res = webhook.send(URL, webhook.build_payload(ALERT), timeout=3)
    assert res.ok is False
    assert res.kind == "timeout"
    assert "超时" in res.message


def test_ssl_error_is_classified_separately(isolated_env, rec):
    init_db()
    rec.script = [ssl.SSLError("certificate verify failed")]
    res = webhook.send(URL, webhook.build_payload(ALERT))
    assert res.kind == "ssl", "TLS 必须单独归类，否则老旧服务器上只会看到「发送失败」"
    assert "TLS" in res.message
    assert "2008" in res.message, "提示要指向真正的根因（旧 OpenSSL）"


def test_verify_ssl_off_uses_unverified_context(isolated_env, monkeypatch):
    init_db()
    _hook_cfg()
    op_strict = webhook._opener(True)
    op_loose = webhook._opener(False)
    # handlers / _context 是 urllib 的内部结构，typeshed 没声明，测试里取一下即可
    loose = [
        h for h in getattr(op_loose, "handlers", []) if isinstance(h, urllib.request.HTTPSHandler)
    ]
    strict = [
        h for h in getattr(op_strict, "handlers", []) if isinstance(h, urllib.request.HTTPSHandler)
    ]
    assert loose and strict
    # _context 是 urllib 的内部结构，typeshed 没声明；标成 Any 就别跟类型检查较劲了
    loose_ctx: Any = cast(Any, loose[0])._context
    strict_ctx: Any = cast(Any, strict[0])._context
    assert loose_ctx.verify_mode == ssl.CERT_NONE
    assert strict_ctx.verify_mode == ssl.CERT_REQUIRED


# ═══════════════════════════════════════════
#  地址校验：强制 https vs 内网 http 豁免
# ═══════════════════════════════════════════


def test_https_is_required_by_default():
    assert webhook.validate_target("https://a.example.com/hook")
    with pytest.raises(InvalidURL):
        webhook.validate_target("http://a.example.com/hook")
    with pytest.raises(InvalidURL):
        webhook.validate_target("ftp://a.example.com/hook")


def test_allow_http_only_for_intranet_literal_ip():
    assert webhook.validate_target("http://10.0.0.5:8080/hook", allow_http=True)
    assert webhook.validate_target("http://192.168.1.9/hook", allow_http=True)
    # 域名即使是内网的，也无法证明 —— 一律拒绝
    with pytest.raises(InvalidURL):
        webhook.validate_target("http://intranet.example.com/hook", allow_http=True)
    # 公网 IP 走明文同样拒绝
    with pytest.raises(InvalidURL):
        webhook.validate_target("http://8.8.8.8/hook", allow_http=True)


# ═══════════════════════════════════════════
#  异步性 / 测试按钮
# ═══════════════════════════════════════════


def test_send_returns_immediately(isolated_env, rec, svc):
    """调用方是 Qt 主线程的事件泵 —— 卡在这里就等于冻界面"""
    init_db()
    _hook_cfg()
    rec.delay = 1.0  # 卡住 1 秒的「网络」；返回必须远快于它
    t0 = time.time()
    assert svc.send(dict(ALERT)) is True
    assert time.time() - t0 < 0.3
    _drain(svc)
    assert rec.count == 1


def test_test_button_reports_without_url(isolated_env, rec):
    init_db()
    cfg.set_many({"webhook_url": ""})
    got: List[webhook.SendResult] = []
    svc = notify_service.NotifyService()
    try:
        assert svc.test(on_done=got.append) is False
    finally:
        svc.stop(timeout=3.0)
    assert got and got[0].kind == "invalid"
    assert rec.count == 0


def test_test_button_sends_with_form_overrides(isolated_env, rec, svc):
    init_db()
    cfg.set_many({"webhook_url": ""})  # 设置里没配，但表单里填了
    got: List[webhook.SendResult] = []
    assert svc.test(overrides={"url": URL, "secret": SECRET}, on_done=got.append) is True
    deadline = time.time() + 3.0
    while not got and time.time() < deadline:
        time.sleep(0.01)
    assert got and got[0].ok is True
    assert rec.count == 1
    assert rec.header(webhook.SIG_HEADER) == webhook.signature(rec.last.data, SECRET)
