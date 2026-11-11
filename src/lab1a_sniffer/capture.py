"""后台抓包生命周期。后续 GUI 只消费队列，不接触原生句柄。"""

from dataclasses import dataclass, replace
import math
from queue import Empty, Full, Queue
import select
import threading
import time

from .models import CaptureInfo, KernelStats, RawPacket
from .pcap import LiveCapture, PcapError


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    interface: str
    bpf: str = ""
    snaplen: int = 65535
    promiscuous: bool = False
    queue_size: int = 2048
    duration: float | None = None
    max_packets: int = 20000
    max_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.interface or "\0" in self.interface:
            raise ValueError("网卡名称不能为空或包含 NUL。")
        if "\0" in self.bpf:
            raise ValueError("过滤表达式不能包含 NUL。")
        if not 64 <= self.snaplen <= 262144:
            raise ValueError("snaplen 必须在 64 到 262144 字节之间。")
        if self.queue_size < 1 or self.max_packets < 1 or self.max_bytes < 1:
            raise ValueError("队列、包数量和字节数上限必须大于零。")
        if self.duration is not None and (not math.isfinite(self.duration) or self.duration <= 0):
            raise ValueError("抓包时长必须为有限正数。")


@dataclass(frozen=True, slots=True)
class CaptureStatus:
    packets_read: int = 0
    bytes_read: int = 0
    packets_queued: int = 0
    queue_dropped: int = 0
    kernel: KernelStats | None = None
    stop_reason: str = "未启动"
    error: str | None = None


class CaptureSession:
    """一次性会话：start -> wait_ready -> drain/request_stop -> join。

    一个实例只能启动一次。重新抓包要创建新会话，防止前次事件和队列污染。
    非阻塞 pcap_next_ex + 最长 50ms 的等待保证无流量时也能响应停止。
    """

    def __init__(self, config: CaptureConfig) -> None:
        self.config = config
        self._queue: Queue[RawPacket] = Queue(maxsize=config.queue_size)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self.finished = threading.Event()
        self._status_lock = threading.Lock()
        self._status = CaptureStatus()
        self.info: CaptureInfo | None = None
        self._thread = threading.Thread(target=self._run, name=f"pcap-{config.interface}")

    def start(self) -> None:
        self._thread.start()

    def wait_ready(self, timeout: float = 5.0) -> CaptureInfo:
        if not self._ready.wait(timeout):
            self.request_stop()
            raise TimeoutError("等待抓包初始化超时，已请求停止。")
        status = self.status()
        if status.error:
            raise PcapError(status.error)
        if self.info is None:
            raise PcapError("抓包会话没有成功初始化。")
        return self.info

    def status(self) -> CaptureStatus:
        with self._status_lock:
            return self._status

    def _update_status(self, **values) -> None:
        with self._status_lock:
            self._status = replace(self._status, **values)

    def drain(self, limit: int = 256) -> list[RawPacket]:
        if limit < 1:
            raise ValueError("每次消费数量必须大于零。")
        packets = []
        for _ in range(limit):
            try:
                packets.append(self._queue.get_nowait())
            except Empty:
                break
        return packets

    def request_stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float = 3.0) -> bool:
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def _run(self) -> None:
        try:
            with LiveCapture(
                self.config.interface, bpf=self.config.bpf,
                snaplen=self.config.snaplen, promiscuous=self.config.promiscuous,
            ) as capture:
                self.info = capture.info
                self._update_status(stop_reason="抓包中")
                self._ready.set()
                started = time.monotonic()
                next_stats = started + 1
                try:
                    while not self._stop.is_set():
                        now = time.monotonic()
                        if self.config.duration is not None and now - started >= self.config.duration:
                            self._update_status(stop_reason="达到时长上限")
                            break
                        if now >= next_stats:
                            self._update_status(kernel=capture.statistics())
                            next_stats = now + 1
                        packet = capture.read_packet()
                        if packet is None:
                            # 先读再等：libpcap 的内部缓冲区可能仍有未取完的数据。
                            wait = 0.05
                            if self.config.duration is not None:
                                wait = min(wait, max(0, started + self.config.duration - now))
                            if capture.selectable_fd >= 0:
                                select.select([capture.selectable_fd], [], [], wait)
                            else:
                                self._stop.wait(min(wait, 0.01))
                            continue
                        previous = self.status()
                        count = previous.packets_read + 1
                        byte_count = previous.bytes_read + packet.captured_length
                        queued, dropped = previous.packets_queued, previous.queue_dropped
                        try:
                            self._queue.put_nowait(packet)
                            queued += 1
                        except Full:
                            dropped += 1
                        self._update_status(
                            packets_read=count, bytes_read=byte_count,
                            packets_queued=queued, queue_dropped=dropped,
                        )
                        if count >= self.config.max_packets:
                            self._update_status(stop_reason="达到包数量上限")
                            break
                        if byte_count >= self.config.max_bytes:
                            self._update_status(stop_reason="达到捕获字节数上限")
                            break
                    else:
                        self._update_status(stop_reason="用户停止")
                finally:
                    self._update_status(kernel=capture.statistics())
        except Exception as exc:
            self._update_status(error=str(exc), stop_reason="错误停止")
        finally:
            self._ready.set()
            self.finished.set()
