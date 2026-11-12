"""有界 TCP 连接索引。只引用缓存行号，不复制载荷，不执行 TCP 字节流重组。"""
from dataclasses import dataclass, field
import ipaddress
import struct
from .models import ParsedPacket


@dataclass(frozen=True, order=True, slots=True)
class Endpoint:
    address: str
    port: int

    def __str__(self):
        return f"[{self.address}]:{self.port}" if ":" in self.address else f"{self.address}:{self.port}"


def endpoint(address, port):
    return Endpoint(str(ipaddress.ip_address(address.split("%")[0])), int(port))


def connection_key(a, b):
    return tuple(sorted((a, b)))


@dataclass(frozen=True, slots=True)
class Segment:
    source: Endpoint
    destination: Endpoint
    sequence: int
    acknowledgement: int
    flags: int
    payload_length: int
    complete: bool


def tcp_segment(packet: ParsedPacket) -> Segment | None:
    tcp = next((layer for layer in packet.layers if layer.name == "TCP"), None)
    if tcp is None or packet.source_port is None or packet.destination_port is None:
        return None
    data, pos = packet.raw.data, tcp.offset
    if len(data) < pos + tcp.length or tcp.length < 20:
        return None
    ip = next((layer for layer in packet.layers if layer.name in ("IPv4", "IPv6")), None)
    if ip is None:
        return None
    if ip.name == "IPv4":
        declared = ip.offset + int.from_bytes(data[ip.offset + 2:ip.offset + 4], "big")
    else:
        declared = ip.offset + 40 + int.from_bytes(data[ip.offset + 4:ip.offset + 6], "big")
    seq, ack = struct.unpack_from("!II", data, pos + 4)
    return Segment(endpoint(packet.source, packet.source_port), endpoint(packet.destination, packet.destination_port),
                   seq, ack, data[pos + 13], max(0, min(len(data), declared) - pos - tcp.length),
                   declared <= len(data) and not any(i.kind == "malformed" for i in packet.issues))


@dataclass(slots=True)
class TCPFlow:
    id: int
    a: Endpoint
    b: Endpoint
    first_us: int
    last_us: int
    rows: list[int] = field(default_factory=list)
    counts: list[int] = field(default_factory=lambda: [0, 0])
    wire_bytes: list[int] = field(default_factory=lambda: [0, 0])
    payload_bytes: list[int] = field(default_factory=lambda: [0, 0])
    syn: dict = field(default_factory=dict)
    syn_ack: bool = False
    established: bool = False
    handshake_us: int | None = None
    fin: dict = field(default_factory=dict)
    fin_ack: set = field(default_factory=set)
    reset: bool = False
    owners: dict = field(default_factory=dict)

    @property
    def key(self):
        return connection_key(self.a, self.b)

    @property
    def terminal(self):
        return self.reset or len(self.fin_ack) == 2

    @property
    def state(self):
        if self.reset:
            return "RST 结束"
        if len(self.fin_ack) == 2:
            return "FIN 已确认"
        if self.fin:
            return "关闭中"
        if self.established:
            return "已见三次握手"
        return "握手中" if self.syn else "中途捕获"

    def add(self, row, packet, seg):
        direction = 0 if seg.source == self.a else 1
        other = 1 - direction
        self.rows.append(row)
        self.counts[direction] += 1
        self.wire_bytes[direction] += packet.raw.wire_length
        self.payload_bytes[direction] += seg.payload_length
        self.last_us = max(self.last_us, packet.raw.timestamp_us)
        self.first_us = min(self.first_us, packet.raw.timestamp_us)
        if seg.flags & 2:
            self.syn.setdefault(direction, (seg.sequence, packet.raw.timestamp_us, seg.payload_length))
            if seg.flags & 16 and other in self.syn:
                self.syn_ack |= seg.acknowledgement == (self.syn[other][0] + self.syn[other][2] + 1) & 0xFFFFFFFF
        if not seg.flags & 2 and seg.flags & 16 and self.syn_ack and direction == 0 and 1 in self.syn:
            if (seg.acknowledgement == (self.syn[1][0] + self.syn[1][2] + 1) & 0xFFFFFFFF
                    and seg.sequence == (self.syn[0][0] + self.syn[0][2] + 1) & 0xFFFFFFFF
                    and not self.established):
                self.established = True
                self.handshake_us = max(0, packet.raw.timestamp_us - self.syn[0][1])
        if seg.flags & 1 and seg.complete:
            self.fin[direction] = (seg.sequence + seg.payload_length + 1) & 0xFFFFFFFF
        if seg.flags & 16 and other in self.fin:
            delta = (seg.acknowledgement - self.fin[other]) & 0xFFFFFFFF
            if delta < 0x80000000:
                self.fin_ack.add(other)
        self.reset |= bool(seg.flags & 4)


class FlowTracker:
    def __init__(self, *, max_flows=2048, max_packets=20000):
        self.max_flows, self.max_packets = max_flows, max_packets
        self.flows: dict[int, TCPFlow] = {}
        self.active: dict[tuple, int] = {}
        self.row_flow: dict[int, int] = {}
        self.untracked = 0

    def add(self, row, packet):
        seg = tcp_segment(packet)
        if seg is None:
            return
        if len(self.row_flow) >= self.max_packets:
            self.untracked += 1
            return
        key = connection_key(seg.source, seg.destination)
        flow = self.flows.get(self.active.get(key))
        initial = seg.flags & 2 and not seg.flags & 16
        if flow is not None and initial:
            side = 0 if seg.source == flow.a else 1
            old = flow.syn.get(side)
            if flow.terminal or (old is not None and old[0] != seg.sequence) or (old is None and flow.rows):
                flow = None
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.untracked += 1
                return
            a, b = (seg.destination, seg.source) if seg.flags & 2 and seg.flags & 16 else (seg.source, seg.destination)
            flow = TCPFlow(len(self.flows) + 1, a, b, packet.raw.timestamp_us, packet.raw.timestamp_us)
            self.flows[flow.id] = flow
            self.active[key] = flow.id
        flow.add(row, packet, seg)
        self.row_flow[row] = flow.id

    def associate(self, snapshot):
        """只在实时会话调用：匹配完整端点与相近时间；保留已观测的历史线索。"""
        changed = False
        for flow in self.flows.values():
            if flow.terminal or flow.first_us > snapshot.ended_us or flow.last_us < snapshot.started_us - 2_000_000:
                continue
            for owner in snapshot.connections.get(flow.key, ()):
                if owner not in flow.owners and len(flow.owners) < 4:
                    flow.owners[owner] = snapshot.ended_us
                    changed = True
        return changed
