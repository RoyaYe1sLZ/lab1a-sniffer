"""与 GUI、ctypes 无关的值对象，供后续实时/离线解析复用。"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str
    flags: int

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def is_up(self) -> bool:
        return bool(self.flags & 0x2)

    @property
    def is_running(self) -> bool:
        return bool(self.flags & 0x4)


@dataclass(frozen=True, slots=True)
class RawPacket:
    # 使用整数保存 libpcap 的微秒时间戳，避免浮点数损失精度。
    seconds: int
    microseconds: int
    wire_length: int
    linktype: int
    data: bytes

    @property
    def captured_length(self) -> int:
        return len(self.data)

    @property
    def timestamp_us(self) -> int:
        return self.seconds * 1_000_000 + self.microseconds


@dataclass(frozen=True, slots=True)
class KernelStats:
    received: int
    dropped: int
    interface_dropped: int


@dataclass(frozen=True, slots=True)
class CaptureInfo:
    interface: str
    linktype: int
    linktype_name: str
    snapshot_length: int
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PacketField:
    name: str
    value: str
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class ProtocolLayer:
    name: str
    offset: int
    length: int
    fields: tuple[PacketField, ...]


@dataclass(frozen=True, slots=True)
class ParseIssue:
    kind: str
    message: str
    offset: int


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    raw: RawPacket
    layers: tuple[ProtocolLayer, ...]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    summary: str
    issues: tuple[ParseIssue, ...]

    @property
    def protocol(self) -> str:
        return self.layers[-1].name if self.layers else "未知"

    @property
    def protocols(self) -> frozenset[str]:
        return frozenset(layer.name for layer in self.layers)

    def matches_protocol(self, name: str) -> bool:
        return name in ("全部", "ALL") or any(p.upper() == name.upper() for p in self.protocols)
