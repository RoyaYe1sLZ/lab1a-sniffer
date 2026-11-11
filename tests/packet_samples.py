"""按协议字段独立构造测试报文，不调用生产解析器。"""

import ipaddress
import struct

from lab1a_sniffer.models import RawPacket

REQUEST = b"GET /lab1a?x=1 HTTP/1.1\r\nHost: example.test\r\nX-Test: one\r\nX-Test: two\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"


def checksum(data):
    padded = data + b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def tcp(payload=b"", *, src=12345, dst=8080, options=b"", flags=0x18):
    assert len(options) % 4 == 0
    control = ((20 + len(options)) // 4) << 12 | flags
    return struct.pack("!HHIIHHHH", src, dst, 0x01020304, 0x05060708, control, 4096, 0, 0) + options + payload


def udp(payload=b"sample", *, src=12345, dst=54321):
    return struct.pack("!HHHH", src, dst, 8 + len(payload), 0) + payload


def ipv4(payload, *, protocol=6, options=b"", fragment=0,
         source="192.0.2.1", destination="198.51.100.2"):
    assert len(options) % 4 == 0
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    if protocol in (6, 17) and not fragment:
        position = 16 if protocol == 6 else 6
        pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(payload))
        check = checksum(pseudo + payload)
        payload = payload[:position] + struct.pack("!H", check or 0xFFFF) + payload[position + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0,
                         20 + len(options) + len(payload), 0x1234, fragment, 64, protocol, 0, src, dst) + options
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(payload, *, following=17):
    src = ipaddress.ip_address("2001:db8::1").packed
    dst = ipaddress.ip_address("2001:db8::2").packed
    if following in (6, 17, 58):
        position = {6: 16, 17: 6, 58: 2}[following]
        pseudo = src + dst + struct.pack("!I3xB", len(payload), following)
        check = checksum(pseudo + payload)
        payload = payload[:position] + struct.pack("!H", check or 0xFFFF) + payload[position + 2:]
    return struct.pack("!IHBB16s16s", 0x60012345, len(payload), following, 32, src, dst) + payload


def ethernet(payload, *, ethertype=0x0800):
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ethertype) + payload


def packet(data, *, linktype=1, wire_length=None):
    return RawPacket(1700000000, 123456, len(data) if wire_length is None else wire_length, linktype, data)


def golden_packets():
    echo = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 7) + b"echo"
    echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
    return {
        "http-request": packet(ethernet(ipv4(tcp(REQUEST)))),
        "http-response": packet(ethernet(ipv4(tcp(RESPONSE, src=8080, dst=12345),
                                                source="198.51.100.2", destination="192.0.2.1"))),
        "ipv6-udp": packet(ethernet(ipv6(udp()), ethertype=0x86DD)),
        "icmp-echo": packet(ethernet(ipv4(echo, protocol=1))),
        "icmp6-echo": packet(ethernet(ipv6(struct.pack("!BBHHH", 128, 0, 0, 0x1234, 9) + b"echo",
                                                 following=58), ethertype=0x86DD)),
    }
