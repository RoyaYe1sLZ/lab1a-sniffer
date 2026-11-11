"""阶段 1 端到端验收：只用自行产生、带随机标记的流量验证抓包。"""

from contextlib import ExitStack, closing
from dataclasses import asdict
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

from .capture import CaptureConfig, CaptureSession
from .models import RawPacket
from .pcap import PcapError, write_pcap


def _collect_until(session: CaptureSession, markers: list[bytes], timeout: float = 3) -> list[RawPacket]:
    packets = []
    missing = set(markers)
    deadline = time.monotonic() + timeout
    while missing and time.monotonic() < deadline:
        batch = session.drain()
        packets.extend(batch)
        for packet in batch:
            missing = {marker for marker in missing if marker not in packet.data}
        if session.finished.wait(0.01):
            break
    return packets


def _finish(session: CaptureSession, packets: list[RawPacket]) -> None:
    session.request_stop()
    if not session.join():
        raise PcapError("验收会话未能在 3 秒内停止。")
    packets.extend(session.drain(session.config.queue_size))
    if session.status().error:
        raise PcapError(session.status().error)


def _result(session: CaptureSession, packets: list[RawPacket], checks: dict,
            output: Path | None) -> dict:
    assert session.info is not None
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        write_pcap(output / f"{session.info.interface}.pcap", packets, session.info)
    return {
        "interface": session.info.interface,
        "linktype": session.info.linktype,
        "linktype_name": session.info.linktype_name,
        "checks": checks,
        "passed": all(checks.values()),
        "status": asdict(session.status()),
        "pcap": str(output / f"{session.info.interface}.pcap") if output else None,
    }


def check_loopback(output: Path | None = None) -> dict:
    marker = f"lab1a-{uuid.uuid4().hex}".encode()
    http_marker, udp4_marker, udp6_marker = [marker + suffix for suffix in (b"-http", b"-udp4", b"-udp6")]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(http_marker)))
            self.end_headers()
            self.wfile.write(http_marker)

        def log_message(self, *_):
            pass

    with ExitStack() as resources:
        udp4 = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp6 = resources.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
        udp4.bind(("127.0.0.1", 0))
        udp6.bind(("::1", 0))
        udp4.settimeout(2)
        udp6.settimeout(2)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, name="selfcheck-http")
        server_thread.start()
        # LIFO：先 shutdown，再 join，最后 close。
        resources.callback(server.server_close)
        resources.callback(server_thread.join, 3)
        resources.callback(server.shutdown)
        http_port = server.server_port
        udp4_port, udp6_port = udp4.getsockname()[1], udp6.getsockname()[1]
        session = CaptureSession(CaptureConfig(
            "lo0", bpf=f"tcp port {http_port} or udp port {udp4_port} or udp port {udp6_port}",
            duration=6,
        ))
        packets = []
        session.start()
        try:
            session.wait_ready()
            udp4.sendto(udp4_marker, udp4.getsockname())
            udp6.sendto(udp6_marker, udp6.getsockname())
            if udp4.recv(1024) != udp4_marker or udp6.recv(1024) != udp6_marker:
                raise PcapError("本地 UDP 测试数据不一致。")
            with closing(http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)) as connection:
                connection.request("GET", "/" + http_marker.decode())
                response = connection.getresponse()
                if response.status != 200 or response.read() != http_marker:
                    raise PcapError("本地 HTTP 测试服务器响应不正确。")
            packets = _collect_until(session, [http_marker, udp4_marker, udp6_marker])
        finally:
            _finish(session, packets)
        checks = {
            "http_marker": any(http_marker in p.data for p in packets),
            "udp_ipv4_marker": any(udp4_marker in p.data for p in packets),
            "udp_ipv6_marker": any(udp6_marker in p.data for p in packets),
            "stopped_cleanly": session.finished.is_set(),
        }
        return _result(session, packets, checks, output)


def check_physical(interface: str = "en0", output: Path | None = None) -> dict:
    if sys.platform != "darwin":
        raise PcapError("物理接口验收目前仅支持 macOS。")
    marker = f"lab1a-{uuid.uuid4().hex}-physical".encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        # Apple XNU bsd/netinet/in.h: IP_BOUND_IF=25。避免被 VPN 默认路由带到 utun。
        sender.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        sender.bind(("0.0.0.0", 0))
        port = sender.getsockname()[1]
        session = CaptureSession(CaptureConfig(
            interface, bpf=f"udp and src port {port} and dst host 192.0.2.1 and dst port 59123",
            duration=6,
        ))
        packets = []
        session.start()
        try:
            session.wait_ready()
            # TEST-NET-1 文档地址，TTL=1；只检查发包，不要求远端服务存在。
            for _ in range(3):
                sender.sendto(marker, ("192.0.2.1", 59123))
            packets = _collect_until(session, [marker])
        finally:
            _finish(session, packets)
        return _result(session, packets, {
            "outbound_udp_marker": any(marker in p.data for p in packets),
            "stopped_cleanly": session.finished.is_set(),
        }, output)


def check_idle_stop() -> dict:
    # 一个当前未使用的临时端口，保证无流量时的停止不依赖新包唤醒。
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as guard:
        guard.bind(("127.0.0.1", 0))
        session = CaptureSession(CaptureConfig("lo0", bpf=f"udp port {guard.getsockname()[1]}"))
        session.start()
        try:
            session.wait_ready()
        finally:
            started = time.monotonic()
            session.request_stop()
            stopped = session.join()
        elapsed = time.monotonic() - started
        return {
            "passed": stopped and elapsed < 1 and session.status().error is None,
            "stop_seconds": round(elapsed, 6),
            "status": asdict(session.status()),
        }
