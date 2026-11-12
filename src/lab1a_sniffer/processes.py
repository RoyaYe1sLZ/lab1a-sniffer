"""macOS 当前用户的 TCP 套接字快照；无提权，不猜测离线文件的进程归属。"""
from dataclasses import dataclass, replace
import os
import re
import subprocess
import sys
import time
from .flows import connection_key, endpoint


@dataclass(frozen=True, order=True, slots=True)
class ProcessIdentity:
    pid: int
    name: str
    started: str

    def __str__(self):
        return f"{self.name} · PID {self.pid}"


@dataclass(frozen=True, slots=True)
class SocketSnapshot:
    started_us: int
    ended_us: int
    connections: dict
    message: str = ""


def parse_endpoint(text):
    if text.startswith("["):
        address, port = text.rsplit("]:", 1)
        return endpoint(address[1:], port)
    address, port = text.rsplit(":", 1)
    return endpoint(address, port)


def parse_lsof(text):
    result = {}
    pid, name = None, ""
    records = 0
    for line in text.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else None
            name = ""
        elif line.startswith("c"):
            name = "".join(c for c in line[1:256] if c.isprintable())
        elif line.startswith("n") and "->" in line and pid and name:
            records += 1
            if records > 8192:
                raise ValueError("套接字快照超过 8192 条，未使用本次结果。")
            try:
                a, b = (parse_endpoint(s) for s in line[1:].split("->", 1))
            except (ValueError, IndexError):
                continue
            result.setdefault(connection_key(a, b), set()).add(ProcessIdentity(pid, name, ""))
    return result


def _run(command, cancelled, *, timeout=2):
    if cancelled():
        raise InterruptedError("已取消进程查询")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, "LC_ALL": "C"})
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancelled():
                raise InterruptedError("已取消进程查询")
            if time.monotonic() > deadline:
                raise TimeoutError("进程查询超时")
            try:
                out, err = process.communicate(timeout=.05)
                break
            except subprocess.TimeoutExpired:
                continue
        if len(out) > 2 * 1024 * 1024:
            raise ValueError("进程查询输出超过 2 MiB，未使用本次结果。")
        return process.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def collect_snapshot(cancelled=lambda: False):
    if sys.platform != "darwin":
        raise OSError("进程关联当前仅支持 macOS。")
    started = time.time_ns() // 1000
    # 查询前后核对启动时间，避免扫描期间 PID 已被新进程复用。
    _, before, _ = _run(["/bin/ps", "-axo", "pid=,lstart="], cancelled)
    def starts(text):
        result = {}
        for line in text.splitlines():
            match = re.fullmatch(r"\s*(\d+)\s+(.+?)\s*", line)
            if match:
                result[int(match[1])] = match[2]
        return result
    before = starts(before)
    code, out, err = _run(["/usr/sbin/lsof", "-w", "-nP", "+c", "0", "-a", "-u", str(os.getuid()),
                           "-iTCP", "-Fpcn"], cancelled)
    if code not in (0, 1) or err.strip():
        raise OSError("套接字查询失败；权限或系统限制可能导致不可见。")
    connections = parse_lsof(out)
    pids = sorted({p.pid for owners in connections.values() for p in owners})
    births = {}
    if len(pids) > 2048:
        raise ValueError("进程数超过 2048，未使用本次快照。")
    if pids:
        code, out, _ = _run(["/bin/ps", "-p", ",".join(map(str, pids)), "-o", "pid=,lstart="], cancelled)
        if code not in (0, 1):
            raise OSError("无法确认进程启动时间，未使用本次快照。")
        births = {pid: birth for pid, birth in starts(out).items() if before.get(pid) == birth}
    confirmed = {key: frozenset(replace(p, started=births[p.pid]) for p in owners if p.pid in births)
                 for key, owners in connections.items()}
    return SocketSnapshot(started, time.time_ns() // 1000, confirmed,
                          "仅当前用户可见的 TCP 套接字；短连接、权限限制、代理转发可能无法归属。")
