"""纯 Python 分层解析：只解释当前捕获的字节，不重组 IP 分片或 TCP 流。

所有偏移均相对 RawPacket.data；IP 声明的长度限定上层边界，避免把
Ethernet padding 或截断后的内容误当成传输层/HTTP。无需加载 libpcap 或 Qt。
"""

from ipaddress import IPv4Address, IPv6Address
import re
import struct
import sys

from .models import PacketField, ParsedPacket, ParseIssue, ProtocolLayer, RawPacket

HTTP_LIMIT = 16384
HTTP_FIELD_LIMIT = 128
EXTENSION_LIMIT = 8
TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
REQUEST = re.compile(TOKEN + rb" [^\x00-\x20\x7f]+ HTTP/1\.[0-9]")
RESPONSE = re.compile(rb"HTTP/1\.[0-9] [0-9]{3}(?: [\t\x20-\x7e\x80-\xff]*)?")
HEADER_NAME = re.compile(TOKEN)
PARTIAL_REQUEST = re.compile(rb"(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) ")


def safe_text(data: bytes) -> str:
    """保留可显示的 Latin-1 字节，转义终端控制字符。"""
    return "".join(chr(b) if 32 <= b <= 126 or b >= 160 else f"\\x{b:02x}" for b in data)


class _Stop(Exception):
    """已记录问题，停止当前包的进一步解析，不代表程序错误。"""


class _Parser:
    def __init__(self, raw: RawPacket):
        self.raw = raw
        self.data = raw.data
        self.layers: list[ProtocolLayer] = []
        self.issues: list[ParseIssue] = []
        self.source = self.destination = ""
        self.source_port = self.destination_port = None
        self.summary = "未识别协议"

    def issue(self, kind: str, message: str, offset: int) -> None:
        self.issues.append(ParseIssue(kind, message, min(max(offset, 0), len(self.data))))

    def stop(self, kind: str, message: str, offset: int) -> None:
        self.issue(kind, message, offset)
        raise _Stop

    def need(self, offset: int, length: int, end: int, context: str,
             declared_end: int | None = None) -> None:
        if declared_end is not None and offset + length > declared_end:
            self.stop("malformed", f"{context} 所需长度超出上层声明的边界", offset)
        if offset + length > end:
            self.stop("truncated", f"{context} 被截断，需要 {length} 字节", offset)

    def layer(self, name: str, offset: int, length: int, fields: list[tuple]) -> None:
        self.layers.append(ProtocolLayer(name, offset, length, tuple(
            PacketField(label, str(value), position, size) for label, value, position, size in fields
        )))

    def run(self) -> ParsedPacket:
        try:
            if self.raw.wire_length < len(self.data):
                self.stop("malformed", "捕获长度大于线上长度", 0)
            if self.raw.wire_length > len(self.data):
                self.issue("truncated", "捕获长度小于线上长度，部分数据不可见", len(self.data))
            offset, version = self.link()
            if version == 4:
                self.ipv4(offset)
            elif version == 6:
                self.ipv6(offset)
        except _Stop:
            pass
        return ParsedPacket(
            self.raw, tuple(self.layers), self.source, self.destination,
            self.source_port, self.destination_port, self.summary, tuple(self.issues),
        )

    def link(self) -> tuple[int, int]:
        end = len(self.data)
        kind = self.raw.linktype
        if kind == 1:  # DLT_EN10MB
            self.need(0, 14, end, "Ethernet 头部")
            dst, src, ethertype = struct.unpack_from("!6s6sH", self.data)
            mac = lambda value: ":".join(f"{b:02x}" for b in value)
            self.source, self.destination = mac(src), mac(dst)
            self.layer("Ethernet", 0, 14, [
                ("目的 MAC", self.destination, 0, 6), ("源 MAC", self.source, 6, 6),
                ("EtherType", f"0x{ethertype:04x}", 12, 2),
            ])
            offset = 14
            for _ in range(4):
                if ethertype not in (0x8100, 0x88A8, 0x9100):
                    break
                self.need(offset, 4, end, "VLAN 头部")
                tci, ethertype = struct.unpack_from("!HH", self.data, offset)
                self.layer("VLAN", offset, 4, [
                    ("VLAN ID", tci & 0xFFF, offset, 2),
                    ("优先级", tci >> 13, offset, 2),
                    ("EtherType", f"0x{ethertype:04x}", offset + 2, 2),
                ])
                offset += 4
            if ethertype in (0x8100, 0x88A8, 0x9100):
                self.stop("limit", "VLAN 嵌套超过 4 层，停止解析", offset)
            if ethertype not in (0x0800, 0x86DD):
                self.summary = f"EtherType 0x{ethertype:04x}"
                self.stop("unsupported", "当前不解析此 EtherType", offset)
            return offset, 4 if ethertype == 0x0800 else 6
        if kind in (0, 108):  # DLT_NULL 为本机字节序，DLT_LOOP 为网络字节序。
            self.need(0, 4, end, "回环头部")
            family = int.from_bytes(self.data[:4], sys.byteorder if kind == 0 else "big")
            self.layer("NULL" if kind == 0 else "LOOP", 0, 4, [("地址族", family, 0, 4)])
            # PF_INET6 在 Darwin/FreeBSD/OpenBSD 上可能为 30/28/24。
            if family not in (2, 24, 28, 30):
                self.summary = f"回环地址族 {family}"
                self.stop("unsupported", f"不支持的回环地址族 {family}", 0)
            return 4, 4 if family == 2 else 6
        if kind in (12, 101, 228, 229):  # DLT_RAW / LINKTYPE_RAW / DLT_IPV4 / DLT_IPV6
            self.need(0, 1, end, "原始 IP 数据")
            version = self.data[0] >> 4
            if version not in (4, 6) or kind == 228 and version != 4 or kind == 229 and version != 6:
                self.stop("malformed", "原始 IP 版本与链路类型不一致", 0)
            return 0, version
        self.stop("unsupported", f"不支持的链路类型 DLT={kind}", 0)

    def ipv4(self, offset: int) -> None:
        end = len(self.data)
        self.need(offset, 20, end, "IPv4 固定头部")
        first, tos, total, ident, fragment, ttl, protocol, checksum, src, dst = struct.unpack_from(
            "!BBHHHBBH4s4s", self.data, offset)
        header = (first & 15) * 4
        if first >> 4 != 4 or header < 20 or total < header:
            self.stop("malformed", "IPv4 版本、IHL 或总长度不合法", offset)
        self.source, self.destination = str(IPv4Address(src)), str(IPv4Address(dst))
        self.summary = f"IPv4 协议号 {protocol}"
        fields = [
            ("版本", 4, offset, 1), ("头部长度", header, offset, 1),
            ("DSCP/ECN", f"0x{tos:02x}", offset + 1, 1), ("总长度", total, offset + 2, 2),
            ("标识", ident, offset + 4, 2), ("标志", f"0x{fragment >> 13:x}", offset + 6, 2),
            ("分片偏移（字节）", (fragment & 0x1FFF) * 8, offset + 6, 2),
            ("TTL", ttl, offset + 8, 1), ("协议号", protocol, offset + 9, 1),
            ("头部校验和（未验证）", f"0x{checksum:04x}", offset + 10, 2),
            ("源地址", self.source, offset + 12, 4), ("目的地址", self.destination, offset + 16, 4),
        ]
        self.layer("IPv4", offset, min(header, end - offset), fields)
        self.need(offset, header, end, "IPv4 可变头部")
        if header > 20:
            self._options(offset + 20, header - 20)
        declared = offset + total
        if declared > end:
            self.issue("truncated", "IPv4 声明的数据未完整捕获", end)
        if fragment & 0x3FFF:
            self.summary = f"IPv4 分片 · 偏移 {(fragment & 0x1FFF) * 8} 字节 · MF={bool(fragment & 0x2000)}"
            self.stop("fragmented", "未重组 IPv4 分片，不继续解释上层协议", offset + 6)
        self.transport(protocol, offset + header, min(end, declared), declared, ipv6=False)

    def _options(self, offset: int, length: int) -> None:
        # 只呈现选项原始字节，不声称已解释所有选项语义。
        layer = self.layers[-1]
        self.layers[-1] = ProtocolLayer(layer.name, layer.offset, layer.length, layer.fields + (
            PacketField("选项（原始）", self.data[offset:offset + length].hex(" "), offset, length),
        ))

    def ipv6(self, offset: int) -> None:
        self.need(offset, 40, len(self.data), "IPv6 固定头部")
        first, payload_length, following, hops, src, dst = struct.unpack_from("!IHBB16s16s", self.data, offset)
        if first >> 28 != 6:
            self.stop("malformed", "IPv6 版本不合法", offset)
        self.source, self.destination = str(IPv6Address(src)), str(IPv6Address(dst))
        self.summary = f"IPv6 下一头部 {following}"
        self.layer("IPv6", offset, 40, [
            ("版本", 6, offset, 1), ("流量类别", (first >> 20) & 255, offset, 4),
            ("流标签", first & 0xFFFFF, offset, 4), ("载荷长度", payload_length, offset + 4, 2),
            ("下一头部", following, offset + 6, 1), ("跳数限制", hops, offset + 7, 1),
            ("源地址", self.source, offset + 8, 16), ("目的地址", self.destination, offset + 24, 16),
        ])
        declared = offset + 40 + payload_length
        end = min(declared, len(self.data))
        if declared > len(self.data):
            self.issue("truncated", "IPv6 声明的载荷未完整捕获", end)
        offset += 40
        if payload_length == 0 and following != 59:
            self.stop("unsupported", "IPv6 零长度载荷/巨帧不继续解析", offset)
        extension_names = {0: "IPv6 Hop-by-Hop", 43: "IPv6 Routing", 60: "IPv6 Destination"}
        count = 0
        while following in (*extension_names, 44):
            count += 1
            if count > EXTENSION_LIMIT:
                self.stop("limit", "IPv6 扩展头超过 8 层，停止解析", offset)
            if following == 44:
                self.need(offset, 8, end, "IPv6 分片头", declared)
                next_header, reserved, flags, ident = struct.unpack_from("!BBHI", self.data, offset)
                fragment_offset, more = (flags >> 3) * 8, bool(flags & 1)
                self.layer("IPv6 Fragment", offset, 8, [
                    ("下一头部", next_header, offset, 1),
                    ("分片偏移（字节）", fragment_offset, offset + 2, 2),
                    ("更多分片", more, offset + 2, 2), ("标识", ident, offset + 4, 4),
                ])
                if reserved or flags & 6:
                    self.stop("malformed", "IPv6 分片头保留位非零", offset + 1)
                if fragment_offset or more:
                    self.summary = f"IPv6 分片 · 偏移 {fragment_offset} 字节 · M={more}"
                    self.stop("fragmented", "未重组 IPv6 分片，不继续解释上层协议", offset)
                length = 8  # 原子分片无需重组，可以继续。
            else:
                self.need(offset, 2, end, "IPv6 扩展头起始字段", declared)
                next_header, length_units = struct.unpack_from("!BB", self.data, offset)
                length = (length_units + 1) * 8
                self.need(offset, length, end, "IPv6 扩展头", declared)
                self.layer(extension_names[following], offset, length, [
                    ("下一头部", next_header, offset, 1), ("头部长度", length, offset + 1, 1),
                ])
            offset += length
            following = next_header
        if following == 59:
            self.summary = "IPv6 · 无下一头部"
        elif following == 50:
            self.summary = "IPv6 · ESP 加密载荷"
            self.issue("encrypted", "ESP 载荷不解密", offset)
        elif following == 51:
            self.summary = "IPv6 · AH"
            self.issue("unsupported", "当前不解析 AH 及其后续内容", offset)
        else:
            self.transport(following, offset, end, declared, ipv6=True)

    def transport(self, protocol: int, offset: int, end: int, declared: int, *, ipv6: bool) -> None:
        if protocol == 6:
            self.tcp(offset, end, declared)
        elif protocol == 17:
            self.udp(offset, end, declared)
        elif protocol == (58 if ipv6 else 1):
            self.icmp(offset, end, declared, ipv6=ipv6)
        else:
            self.issue("unsupported", f"当前不解析 IP 协议号 {protocol}", offset)

    def tcp(self, offset: int, end: int, declared: int) -> None:
        self.need(offset, 20, end, "TCP 固定头部", declared)
        src, dst, sequence, ack, control, window, checksum, urgent = struct.unpack_from("!HHIIHHHH", self.data, offset)
        header = (control >> 12) * 4
        if header < 20:
            self.stop("malformed", "TCP data offset 小于最小头部长度", offset + 12)
        self.need(offset, header, end, "TCP 可变头部", declared)
        flags = ",".join(name for bit, name in (
            (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
            (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN"),
        ) if control & bit) or "无"
        self.source_port, self.destination_port = src, dst
        self.summary = f"{src} → {dst} [{flags}] Seq={sequence} Ack={ack} 数据={end - offset - header} 字节"
        self.layer("TCP", offset, header, [
            ("源端口", src, offset, 2), ("目的端口", dst, offset + 2, 2),
            ("序列号", sequence, offset + 4, 4), ("确认号", ack, offset + 8, 4),
            ("头部长度", header, offset + 12, 1), ("标志", flags, offset + 13, 1),
            ("窗口", window, offset + 14, 2), ("校验和（未验证）", f"0x{checksum:04x}", offset + 16, 2),
            ("紧急指针", urgent, offset + 18, 2),
        ])
        if header > 20:
            self._options(offset + 20, header - 20)
        if offset + header < end:
            self.http(offset + header, end)

    def udp(self, offset: int, end: int, declared: int) -> None:
        self.need(offset, 8, end, "UDP 头部", declared)
        src, dst, length, checksum = struct.unpack_from("!HHHH", self.data, offset)
        if length < 8 or offset + length > declared:
            self.stop("malformed", "UDP 长度小于 8 或超过 IP 声明的载荷", offset + 4)
        self.source_port, self.destination_port = src, dst
        self.summary = f"{src} → {dst} 数据={length - 8} 字节"
        self.layer("UDP", offset, 8, [
            ("源端口", src, offset, 2), ("目的端口", dst, offset + 2, 2),
            ("长度", length, offset + 4, 2), ("校验和（未验证）", f"0x{checksum:04x}", offset + 6, 2),
        ])
        if offset + length > end:
            self.issue("truncated", "UDP 数据未完整捕获", end)

    def icmp(self, offset: int, end: int, declared: int, *, ipv6: bool) -> None:
        name = "ICMPv6" if ipv6 else "ICMP"
        self.need(offset, 4, end, name + " 通用头部", declared)
        kind, code, checksum = struct.unpack_from("!BBH", self.data, offset)
        names = ({128: "Echo Request", 129: "Echo Reply", 1: "Destination Unreachable",
                  2: "Packet Too Big", 3: "Time Exceeded", 135: "Neighbor Solicitation",
                  136: "Neighbor Advertisement"} if ipv6 else
                 {8: "Echo Request", 0: "Echo Reply", 3: "Destination Unreachable", 11: "Time Exceeded"})
        self.summary = f"{names.get(kind, name)} Type={kind} Code={code}"
        fields = [
            ("类型", kind, offset, 1), ("代码", code, offset + 1, 1),
            ("校验和（未验证）", f"0x{checksum:04x}", offset + 2, 2),
        ]
        echo = kind in ((128, 129) if ipv6 else (0, 8))
        self.layer(name, offset, min(8, end - offset), fields)
        self.need(offset, 8, end, name + " 消息头部", declared)
        if echo:
            identifier, sequence = struct.unpack_from("!HH", self.data, offset + 4)
            layer = self.layers[-1]
            self.layers[-1] = ProtocolLayer(name, offset, 8, layer.fields + (
                PacketField("标识符", str(identifier), offset + 4, 2),
                PacketField("序号", str(sequence), offset + 6, 2),
            ))

    def http(self, offset: int, end: int) -> None:
        data = self.data[offset:min(end, offset + HTTP_LIMIT)]
        newline = data.find(b"\r\n")
        line = data if newline < 0 else data[:newline]
        request = REQUEST.fullmatch(line)
        response = RESPONSE.fullmatch(line)
        if not request and not response:
            if newline < 0 and (data.startswith(b"HTTP/1.") or PARTIAL_REQUEST.match(data)):
                if end - offset > HTTP_LIMIT:
                    self.issue("limit", "疑似 HTTP 起始行超过 16 KiB，未识别为 HTTP", offset)
                else:
                    self.issue("incomplete", "疑似 HTTP 起始行不完整；未将此包识别为 HTTP", offset)
            return
        complete_at = data.find(b"\r\n\r\n")
        header_end = complete_at + 4 if complete_at >= 0 else len(data)
        fields = [("请求行" if request else "状态行", safe_text(line), offset, len(line))]
        self.summary = safe_text(line)
        if newline >= 0:
            position = newline + 2
            # 只解释完整的头字段行，不把消息体或跨段残片当作头字段。
            while position < header_end:
                line_end = data.find(b"\r\n", position, header_end)
                if line_end < 0 or line_end == position:
                    break
                if len(fields) > HTTP_FIELD_LIMIT:
                    self.issue("limit", "HTTP 头字段超过 128 项，未继续解析", offset + position)
                    break
                header_line = data[position:line_end]
                key, separator, value = header_line.partition(b":")
                if not separator or not HEADER_NAME.fullmatch(key) or any(b < 32 and b != 9 or b == 127 for b in value):
                    self.issue("malformed", "HTTP 头字段格式不合法（不支持折叠行）", offset + position)
                    break
                fields.append((key.decode("ascii"), safe_text(value.strip(b" \t")), offset + position, len(header_line)))
                position = line_end + 2
        self.layer("HTTP", offset, header_end, fields)
        if complete_at < 0:
            if end - offset > HTTP_LIMIT:
                self.issue("limit", "HTTP 头超过 16 KiB 解析上限，未完整解析", offset + len(data))
            else:
                self.issue("incomplete", "HTTP 头尚未完整可见；不执行 TCP 流重组", offset + len(data))


def parse_packet(raw: RawPacket) -> ParsedPacket:
    """对任意包字节进行有边界的分层解析；畸形数据通过 issues 返回。"""
    return _Parser(raw).run()


def hex_dump(data: bytes, *, limit: int = 4096) -> str:
    """十六进制与 ASCII 视图，默认限制输出大小，原始 bytes 不被修改。"""
    if limit < 1:
        raise ValueError("显示上限必须大于零。")
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        row = data[offset:min(offset + 16, limit)]
        text = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{offset:08x}  {row.hex(' '):47}  |{text}|")
    if len(data) > limit:
        lines.append(f"… 省略 {len(data) - limit} 字节（原始数据仍保留）")
    return "\n".join(lines)
