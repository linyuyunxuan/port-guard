"""PortGuard 上报客户端封装 —— 供业务系统（XCL-POS / pharma_pos 等）接入

设计原则：**上报失败绝不能影响业务主流程**。
- 固定 1 秒超时
- 所有异常一律吞掉
- 可选的异步 / 采样模式见下方说明

用法：
    from report_client import PortGuardClient

    pg = PortGuardClient("http://127.0.0.1:18080", api_key="")

    # 在请求结束前调用（Fastify/Express 中间件、Django 中间件、FastAPI 依赖等）
    pg.report(client_ip="113.118.113.77", local_port=3000,
              path="/admin/login", status_code=401, method="POST",
              user_agent=request.headers.get("user-agent"),
              server_name="xcl-pos")
"""
import datetime
import json
import threading
import urllib.request
from typing import Any, Dict, List, Optional


class PortGuardClient:
    def __init__(self, base_url: str = "http://127.0.0.1:18080",
                 api_key: str = "", timeout: float = 1.0,
                 enabled: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.timeout = timeout
        self.enabled = enabled

    # ── 构造上报体 ──
    def _payload(self, client_ip: str, local_port: int, path: str = "",
                 status_code: Optional[int] = None, method: str = "GET",
                 user_agent: str = "", size: int = 0,
                 server_name: str = "", remote_port: Optional[int] = None,
                 protocol: str = "http", host: str = "",
                 tags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "ip": client_ip,
            "local_port": int(local_port or 0),
            "remote_port": remote_port,
            "protocol": protocol,
            "method": (method or "").upper(),
            "path": path or "",
            "status_code": status_code,
            "user_agent": user_agent or "",
            "bytes": int(size or 0),
            "host": host or "",
            "server_name": server_name or "",
            "tags": tags or {},
            "timestamp": datetime.datetime.now().astimezone().isoformat(),
        }

    # ── 发送 ──
    def _post(self, url: str, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        try:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            # 熔断：任何异常都不向外抛，不影响业务
            return None

    def report(self, client_ip: str, local_port: int, path: str = "",
               status_code: Optional[int] = None, method: str = "GET",
               user_agent: str = "", size: int = 0, server_name: str = "",
               remote_port: Optional[int] = None, protocol: str = "http",
               host: str = "", tags: Optional[Dict[str, Any]] = None
               ) -> Optional[Dict[str, Any]]:
        """同步上报一条访问记录，返回 PortGuard 的风险判定（失败返回 None）"""
        body = self._payload(client_ip, local_port, path, status_code, method,
                             user_agent, size, server_name, remote_port,
                             protocol, host, tags)
        return self._post(f"{self.base_url}/api/v1/access/report", body)

    def report_batch(self, items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """批量上报，items 为与单条上报同结构的字典列表（≤1000 条）"""
        return self._post(f"{self.base_url}/api/v1/access/batch", {"items": items[:1000]})

    def report_async(self, **kwargs) -> None:
        """异步上报：不阻塞业务线程"""
        threading.Thread(target=self.report, kwargs=kwargs, daemon=True).start()

    def is_banned(self, ip: str) -> bool:
        """查询某 IP 当前是否被封禁"""
        try:
            url = f"{self.base_url}/api/v1/banned/{ip}"
            req = urllib.request.Request(url)
            if self.api_key:
                req.add_header("X-API-Key", self.api_key)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return bool(data.get("data", {}).get("banned"))
        except Exception:
            return False


# ── 直接运行本文件时的演示 ──
if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080"
    cli = PortGuardClient(url)

    demo: List[Dict[str, Any]] = [
        # 正常业务访问
        {"client_ip": "113.118.113.77", "local_port": 3000, "path": "/api/products",
             "status_code": 200, "method": "GET",
             "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "size": 2048},
        # 疑似扫描器
        {"client_ip": "45.33.32.156", "local_port": 8080, "path": "/admin/login",
             "status_code": 401, "method": "POST", "user_agent": "sqlmap/1.7#stable", "size": 512},
        # 境外访问数据库端口
        {"client_ip": "8.8.8.8", "local_port": 1433, "path": "/", "status_code": 200,
             "method": "GET", "user_agent": "Mozilla/5.0", "size": 128},
    ]
    for item in demo:
        r = cli.report(**item)
        print(f"{item['client_ip']}:{item['local_port']} -> {r}")
