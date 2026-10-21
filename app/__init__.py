"""
PortGuard — 应用服务层

这里放**不依赖 Qt** 的业务编排，好处是：
- 可以脱离界面单测（不需要构造 QApplication）
- `gui/main_window.py` 只负责界面组装与信号连线，不再是 600 行 God Object

- `ban_service`   封禁/解封/到期巡检编排
- `blacklist_service` 黑名单联动防火墙
- `maintenance`   日志与文件清理
- `xdb_service`   离线库在线同步调度
- `export_csv`    CSV 导出
- `audit`         审计留痕
"""
