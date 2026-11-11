from dataclasses import replace
from pathlib import Path
import struct
import sys
import threading

import pytest

from lab1a_sniffer.models import CaptureInfo
from lab1a_sniffer.pcap import FileCancelled, OfflineCapture, PcapError, write_pcap
from lab1a_sniffer.storage import load_capture
from .packet_samples import golden_packets, ipv4, packet, udp


pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="libpcap 文件 API 当前仅支持 macOS")
INFO = CaptureInfo("fixture", 1, "EN10MB", 65535)


def classic_file(*, order="<", version=(2, 4), snaplen=65535, network=1, records=()):
    header = struct.pack(order + "IHHIIII", 0xA1B2C3D4, *version, 0, 0, snaplen, network)
    for seconds, usec, caplen, wirelen, data in records:
        header += struct.pack(order + "IIII", seconds, usec, caplen, wirelen) + data
    return header


@pytest.mark.parametrize("linktype", [0, 1, 12])
def test_offline_roundtrip_preserves_metadata_bytes_and_fields(tmp_path, linktype):
    if linktype == 1:
        original = list(golden_packets().values())
    else:
        data = ipv4(udp(), protocol=17)
        original = [packet((2).to_bytes(4, sys.byteorder) + data if linktype == 0 else data, linktype=linktype)]
    original += [replace(original[0], seconds=0x80000001, microseconds=999999,
                         data=original[0].data[:10], wire_length=100)]
    path = tmp_path / "中文 抓包.pcap"
    info = replace(INFO, linktype=linktype)
    write_pcap(path, original, info)
    with OfflineCapture(path) as source:
        assert source.info.linktype == linktype
        assert source.info.snapshot_length == 65535
        received = []
        while (record := source.read_packet()) is not None:
            received.append(record)
        assert source.read_packet() is None
    assert received == original
    with pytest.raises(PcapError, match="关闭"):
        source.read_packet()
    source.close()


def test_big_endian_global_and_record_headers(tmp_path):
    sample = golden_packets()["http-request"]
    path = tmp_path / "big.pcap"
    path.write_bytes(classic_file(order=">", records=[(sample.seconds, sample.microseconds,
                                                      len(sample.data), len(sample.data), sample.data)]))
    with OfflineCapture(path) as source:
        assert source.read_packet() == sample
        assert source.read_packet() is None


def test_swapped_null_pseudo_header_is_normalized_and_export_remains_readable(tmp_path):
    data = (2).to_bytes(4, "big") + ipv4(udp(), protocol=17)
    path = tmp_path / "null-big.pcap"
    path.write_bytes(classic_file(order=">", network=0, records=[(1, 2, len(data), len(data), data)]))
    loaded = load_capture(path)
    assert loaded.packets[0].protocol == "UDP"
    assert loaded.packets[0].raw.data[:4] == (2).to_bytes(4, sys.byteorder)
    saved = tmp_path / "normalized.pcap"
    write_pcap(saved, [p.raw for p in loaded.packets], loaded.info)
    assert load_capture(saved).packets[0].raw == loaded.packets[0].raw


@pytest.mark.parametrize("content", [
    b"", b"not a capture", classic_file()[:20],
    b"\x0a\x0d\x0d\x0a" + bytes(20), b"\x4d\x3c\xb2\xa1" + bytes(20),
    classic_file(version=(2, 3)), classic_file(snaplen=0), classic_file(snaplen=262145),
    classic_file(network=0x80000001), classic_file() + bytes(8),
    classic_file(records=[(1, 1000000, 1, 1, b"x")]),
    classic_file(records=[(1, 0, 65536, 65536, b"")]),
    classic_file(records=[(1, 0, 2, 1, b"xx")]),
    classic_file(records=[(1, 0, 10, 10, b"short")]),
])
def test_malformed_or_unsupported_files_are_not_silently_truncated(tmp_path, content):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapError):
        load_capture(path)


def test_empty_file_is_a_valid_capture_and_can_be_saved(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(classic_file())
    loaded = load_capture(path)
    assert loaded.packets == () and loaded.memory_cost == loaded.raw_bytes == 0
    output = tmp_path / "empty-copy.pcap"
    write_pcap(output, (), loaded.info)
    assert load_capture(output).packets == ()


def test_limits_and_cancellation_reject_entire_import(tmp_path):
    path = tmp_path / "samples.pcap"
    write_pcap(path, golden_packets().values(), INFO)
    with pytest.raises(PcapError, match="上限"):
        load_capture(path, max_packets=4)
    with pytest.raises(PcapError, match="预算"):
        load_capture(path, max_memory=1)
    with pytest.raises(FileCancelled):
        load_capture(path, cancelled=lambda: True)


def test_save_cancellation_keeps_original_and_removes_temporary_file(tmp_path):
    path = tmp_path / "original.pcap"
    path.write_bytes(b"keep this file")
    with pytest.raises(FileCancelled):
        write_pcap(path, golden_packets().values(), INFO, cancelled=lambda: True)
    assert path.read_bytes() == b"keep this file"
    assert list(tmp_path.iterdir()) == [path]


def test_changed_file_detected_before_accepting_import(tmp_path):
    path = tmp_path / "changed.pcap"
    write_pcap(path, [next(iter(golden_packets().values()))], INFO)
    with OfflineCapture(path) as source:
        assert source.read_packet() is not None
        path.write_bytes(b"changed")
        with pytest.raises(PcapError, match="修改"):
            source.read_packet()


def test_cross_thread_read_rejected_and_owner_can_close(tmp_path):
    path = tmp_path / "test.pcap"
    path.write_bytes(classic_file())
    errors = []
    with OfflineCapture(path) as source:
        def misuse():
            try:
                source.read_packet()
            except RuntimeError as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=misuse)
        thread.start()
        thread.join(2)
        assert errors
        assert source.read_packet() is None
