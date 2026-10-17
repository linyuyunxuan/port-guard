"""
PortGuard — 日志文件增量读取（供「运行日志」页在**程序内**显示日志）

用户明确要求：日志要在程序里显示，**不是**「打开日志保存位置」。
所以需要一个能持续跟读当前日志文件的轻量 tailer。

关键点：
- 按字节偏移**增量**读取，只读新增部分（日志文件可能已经几十 MB，
  每次全量读会直接把 UI 线程卡住）
- 日志按天 + 按大小滚动（见 core/logger.py 的 DailySizeRotatingFileHandler）。
  滚动后当前文件名不变、内容重置，所以必须检测「文件变小」并重新打开，
  否则会一直读一个已经不存在的偏移
- 末尾可能是**没写完的半行**，只消费到最后一个换行符
- 只保留最近 N 行，避免界面被几十万行拖死
- 顺手把行解析成结构化字段（时间/级别/线程/logger/消息），供按级别过滤 ——
  解析不出来就整行当作 RAW，绝不因为格式不认识就丢日志

不依赖 Qt，可单测。
"""

import os
import re
from collections import deque
from dataclasses import dataclass
from typing import Deque, List, Optional

# 与 core/logger.py 的 _FORMAT 严格对齐：
#   "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s"
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>[A-Z]{3,8})\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<logger>[^:]+):\s?(?P<msg>.*)$"
)

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LEVEL_ORDER = {name: i for i, name in enumerate(LEVELS)}


@dataclass
class LogLine:
    raw: str = ""
    ts: str = ""
    level: str = ""
    thread: str = ""
    logger: str = ""
    msg: str = ""

    @property
    def level_rank(self) -> int:
        """越大越严重；未知级别按 INFO 处理"""
        return LEVEL_ORDER.get(self.level, 1)

    def __str__(self) -> str:
        return self.raw


def parse_line(raw: str) -> LogLine:
    """把一行日志解析成结构化字段；不匹配就原样放进 raw"""
    text = (raw or "").rstrip("\r\n")
    m = _LINE_RE.match(text)
    if not m:
        return LogLine(raw=text)
    return LogLine(
        raw=text,
        ts=m.group("ts"),
        level=m.group("level"),
        thread=m.group("thread").strip(),
        logger=m.group("logger").strip(),
        msg=m.group("msg"),
    )


def read_last_lines(path: str, n: int = 500) -> List[str]:
    """
    取文件末尾 n 行。

    实现上用 deque(maxlen=n) 滑一遍 —— 日志文件几十 MB 时逐行读也只要几百毫秒，
    比「seek 到尾部再猜字节数」可靠得多（多字节字符会把猜测的字节数切碎）。
    """
    if not path or not os.path.isfile(path):
        return []
    n = max(1, int(n))
    dq: Deque[str] = deque(maxlen=n)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                dq.append(line.rstrip("\r\n"))
    except OSError:
        return []
    return list(dq)


class LogTailer:
    """跟读单个日志文件（当前生效的那一个）"""

    def __init__(self, path: str, max_lines: int = 2000):
        self._path = path
        self._offset = 0
        self._partial = ""
        self._max_lines = max(100, int(max_lines))
        self._buffer: Deque[LogLine] = deque(maxlen=self._max_lines)
        self.read_bytes = 0
        self.rotations = 0

    @property
    def path(self) -> str:
        return self._path

    def set_path(self, path: str) -> None:
        if path == self._path:
            return
        self._path = path
        self.reset()

    def set_max_lines(self, n: int) -> None:
        n = max(100, int(n))
        if n == self._max_lines:
            return
        self._max_lines = n
        kept = list(self._buffer)[-n:]
        self._buffer = deque(kept, maxlen=n)

    def reset(self) -> None:
        self._offset = 0
        self._partial = ""

    def exists(self) -> bool:
        try:
            return os.path.isfile(self._path)
        except Exception:
            return False

    @property
    def buffer(self) -> List[LogLine]:
        return list(self._buffer)

    def clear_buffer(self) -> None:
        self._buffer.clear()

    def seed_from_tail(self, n: Optional[int] = None) -> List[LogLine]:
        """
        首次打开页面时先把「已有内容的最后 N 行」铺进缓冲区，
        并把偏移推到文件末尾 —— 这样用户一进来就能看到最近日志，
        而不会把整份历史当成"新增"再刷一遍。
        """
        n = n or self._max_lines
        lines = [parse_line(x) for x in read_last_lines(self._path, n)]
        self._buffer = deque(lines[-self._max_lines :], maxlen=self._max_lines)
        try:
            self._offset = os.path.getsize(self._path) if self.exists() else 0
        except OSError:
            self._offset = 0
        self._partial = ""
        return list(self._buffer)

    def read_new(self) -> List[LogLine]:
        """读取自上次以来新增的完整行"""
        if not self.exists():
            return []
        try:
            size = os.path.getsize(self._path)
        except OSError:
            return []
        if size < self._offset:
            # 日志滚动 / 被清空：从头读新文件
            self.rotations += 1
            self._offset = 0
            self._partial = ""
        if size == self._offset:
            return []
        try:
            with open(self._path, "rb") as f:
                f.seek(self._offset)
                chunk = f.read(size - self._offset)
        except OSError:
            return []
        if not chunk:
            return []
        data = self._partial.encode("utf-8", "replace") + chunk if self._partial else chunk
        consumed = len(chunk)
        self._offset += consumed
        self.read_bytes += consumed

        text = data.decode("utf-8", "replace")
        if text.endswith("\n"):
            self._partial = ""
            complete = text
        else:
            idx = text.rfind("\n")
            if idx < 0:
                # 整块都是半行：留着等下一次，但偏移已经推进（避免重复读）
                self._partial = text
                return []
            self._partial = text[idx + 1 :]
            complete = text[: idx + 1]

        out: List[LogLine] = []
        for raw in complete.splitlines():
            if not raw.strip():
                continue
            line = parse_line(raw)
            self._buffer.append(line)
            out.append(line)
        return out

    def stats(self) -> dict:
        return {
            "path": self._path,
            "exists": self.exists(),
            "offset": self._offset,
            "read_bytes": self.read_bytes,
            "buffered": len(self._buffer),
            "rotations": self.rotations,
        }
