from dataclasses import replace
import ctypes
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from lab1a_sniffer._ffi import PacketHeader, get_libpcap
from lab1a_sniffer.models import CaptureInfo, RawPacket
from lab1a_sniffer.pcap import list_interfaces, write_pcap


pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="当前版本仅支持 macOS")
INFO = CaptureInfo("fixture", 1, "EN10MB", 65535)
# 独立构造的 Ethernet/IPv4/UDP 样本，UDP 校验和为 0（IPv4 合法）。
UDP = bytes.fromhex(
    "ffffffffffff0011223344550800"
    "450000200001000040118e95c0000201c6336402"
    "3039d431000c0000"
) + b"test"
PACKET = RawPacket(1700000000, 123456, len(UDP), 1, UDP)


def test_darwin_timeval_does_not_read_alignment_padding_as_microseconds():
    # Apple timeval = int64 seconds + int32 microseconds + 4 字节未定义填充。
    # 将填充设为非零，能发现错误地把 tv_usec 声明为 long 的绑定。
    native_bytes = struct.pack("<qi4sII", 1700000000, 123456, b"\xff" * 4, 42, 100)
    header = PacketHeader.from_buffer_copy(native_bytes)
    assert ctypes.sizeof(PacketHeader) == 24
    assert header.ts.tv_sec == 1700000000
    assert header.ts.tv_usec == 123456
    assert (header.caplen, header.len) == (42, 100)


def read_classic_pcap(path: Path):
    data = path.read_bytes()
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[data[:4]]
    header = struct.unpack_from(order + "IHHIIII", data)
    packets = []
    offset = 24
    while offset < len(data):
        sec, usec, caplen, wirelen = struct.unpack_from(order + "IIII", data, offset)
        offset += 16
        packets.append((sec, usec, caplen, wirelen, data[offset:offset + caplen]))
        offset += caplen
    return header, packets


def test_real_libpcap_loads_and_enumerates():
    assert "libpcap" in get_libpcap().version
    interfaces = list_interfaces()
    assert interfaces
    assert len({interface.name for interface in interfaces}) == len(interfaces)
    assert any(interface.is_loopback for interface in interfaces)


def test_pcap_roundtrip_exact_fields_and_tcpdump(tmp_path):
    path = tmp_path / "中文样本.pcap"
    packets = [PACKET, replace(PACKET, microseconds=999999, data=UDP[:20])]
    write_pcap(path, packets, INFO)
    header, records = read_classic_pcap(path)
    assert header[1:3] == (2, 4)
    assert header[-2:] == (65535, 1)
    assert records == [(p.seconds, p.microseconds, len(p.data), p.wire_length, p.data) for p in packets]
    completed = subprocess.run(
        ["/usr/sbin/tcpdump", "-nn", "-r", str(path), "-c", "1"],
        capture_output=True, text=True, timeout=5, check=True,
    )
    assert "192.0.2.1.12345 > 198.51.100.2.54321" in completed.stdout


def test_raw_dlt_is_mapped_to_portable_pcap_linktype(tmp_path):
    # macOS DLT_RAW=12，文件中的 LINKTYPE_RAW=101；不能直接写 12。
    info = CaptureInfo("raw", 12, "RAW", 65535)
    path = tmp_path / "raw.pcap"
    write_pcap(path, [replace(PACKET, linktype=12, data=UDP[14:], wire_length=len(UDP) - 14)], info)
    header, _ = read_classic_pcap(path)
    assert header[-1] == 101


@pytest.mark.parametrize("packet", [
    replace(PACKET, linktype=0), replace(PACKET, microseconds=1000000),
    replace(PACKET, seconds=-1), replace(PACKET, wire_length=1),
])
def test_invalid_export_preserves_existing_file(tmp_path, packet):
    path = tmp_path / "keep.pcap"
    path.write_bytes(b"original file")
    with pytest.raises(ValueError):
        write_pcap(path, [PACKET, packet], INFO)
    assert path.read_bytes() == b"original file"
    assert list(tmp_path.iterdir()) == [path]


def test_generator_failure_preserves_existing_file(tmp_path):
    path = tmp_path / "keep.pcap"
    path.write_bytes(b"original file")

    def broken_source():
        yield PACKET
        raise RuntimeError("模拟写入过程中失败")

    with pytest.raises(RuntimeError):
        write_pcap(path, broken_source(), INFO)
    assert path.read_bytes() == b"original file"
    assert list(tmp_path.iterdir()) == [path]


def test_snapshot_truncation_is_preserved(tmp_path):
    path = tmp_path / "short.pcap"
    info = replace(INFO, snapshot_length=64)
    write_pcap(path, [replace(PACKET, data=UDP[:14], wire_length=100)], info)
    _, records = read_classic_pcap(path)
    assert records[0][2:4] == (14, 100)
