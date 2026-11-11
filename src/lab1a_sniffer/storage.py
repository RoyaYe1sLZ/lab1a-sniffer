"""离线导入与缓存预算，不依赖 Qt 控件。"""

from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
import sys

from .models import CaptureInfo, ParsedPacket
from .parser import parse_packet
from .pcap import FileCancelled, OfflineCapture, PcapError


def packet_memory_cost(packet: ParsedPacket) -> int:
    """跨包重复计费共享对象，作为保守的 Python 对象缓存预算，不是 RSS。"""
    seen = set()

    def size(value):
        if id(value) in seen:
            return 0
        seen.add(id(value))
        result = sys.getsizeof(value)
        if is_dataclass(value) and not isinstance(value, type):
            result += sum(size(getattr(value, field.name)) for field in fields(value))
        elif isinstance(value, (tuple, list, frozenset)):
            result += sum(size(item) for item in value)
        return result

    return size(packet)


@dataclass(frozen=True, slots=True)
class LoadedCapture:
    info: CaptureInfo
    packets: tuple[ParsedPacket, ...]
    memory_cost: int
    raw_bytes: int


def load_capture(path: str | Path, *, max_packets=20000, max_memory=128 * 1024 * 1024,
                 cancelled=lambda: False) -> LoadedCapture:
    if max_packets < 1 or max_memory < 1:
        raise ValueError("导入限额必须大于零。")
    packets = []
    cost = raw_bytes = 0
    with OfflineCapture(path) as source:
        while True:
            if cancelled():
                raise FileCancelled("已取消读取，当前列表已保留。")
            raw = source.read_packet()
            if raw is None:
                return LoadedCapture(source.info, tuple(packets), cost, raw_bytes)
            if len(packets) >= max_packets:
                raise PcapError(f"文件超过 {max_packets:,} 个包的导入上限，未替换当前列表。")
            parsed = parse_packet(raw)
            size = packet_memory_cost(parsed)
            if cost + size > max_memory:
                raise PcapError("文件超过解析缓存预算，未替换当前列表。")
            packets.append(parsed)
            cost += size
            raw_bytes += raw.captured_length
