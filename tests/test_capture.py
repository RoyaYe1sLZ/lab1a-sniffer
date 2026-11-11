from dataclasses import replace
import threading

import pytest

from lab1a_sniffer.capture import CaptureConfig, CaptureSession
from lab1a_sniffer.models import CaptureInfo, KernelStats, RawPacket
from lab1a_sniffer.pcap import PcapError


INFO = CaptureInfo("lo0", 0, "NULL", 65535)
PACKET = RawPacket(1, 123456, 100, 0, bytes(100))


def install_source(monkeypatch, *, fail_read=False, idle=False):
    calls = []

    class Source:
        info = INFO
        selectable_fd = -1

        def __init__(self, *args, **kwargs):
            calls.append(("open", threading.get_ident()))

        def __enter__(self):
            return self

        def read_packet(self):
            calls.append(("read", threading.get_ident()))
            if fail_read:
                raise PcapError("模拟网卡断开")
            return None if idle else PACKET

        def statistics(self):
            return KernelStats(100, 2, 0)

        def __exit__(self, *_):
            calls.append(("close", threading.get_ident()))

    monkeypatch.setattr("lab1a_sniffer.capture.LiveCapture", Source)
    return calls


@pytest.mark.parametrize("changes", [
    {"interface": ""}, {"interface": "lo0\0en0"}, {"bpf": "udp\0tcp"},
    {"duration": -1}, {"duration": 0}, {"duration": float("inf")},
    {"duration": float("nan")}, {"queue_size": 0}, {"max_packets": 0},
    {"max_bytes": 0}, {"snaplen": 63}, {"snaplen": 262145},
])
def test_invalid_configuration(changes):
    with pytest.raises(ValueError):
        replace(CaptureConfig("lo0"), **changes)


def test_queue_backpressure_is_counted_and_native_handle_has_one_owner(monkeypatch):
    calls = install_source(monkeypatch)
    main_thread = threading.get_ident()
    session = CaptureSession(CaptureConfig("lo0", queue_size=2, max_packets=10))
    session.start()
    assert session.wait_ready() == INFO
    assert session.join()
    status = session.status()
    assert (status.packets_read, status.packets_queued, status.queue_dropped) == (10, 2, 8)
    assert status.bytes_read == 1000
    assert status.stop_reason == "达到包数量上限"
    assert status.kernel == KernelStats(100, 2, 0)
    assert len(session.drain()) == 2
    assert session.drain() == []
    assert calls[-1][0] == "close"
    assert len({thread_id for _, thread_id in calls}) == 1
    assert calls[0][1] != main_thread


def test_byte_limit_stops_capture(monkeypatch):
    install_source(monkeypatch)
    session = CaptureSession(CaptureConfig("lo0", max_bytes=150))
    session.start()
    assert session.join()
    assert session.status().packets_read == 2
    assert session.status().stop_reason == "达到捕获字节数上限"


def test_idle_capture_respects_duration(monkeypatch):
    install_source(monkeypatch, idle=True)
    session = CaptureSession(CaptureConfig("lo0", duration=0.05))
    session.start()
    session.wait_ready()
    assert session.join(1)
    assert session.status().packets_read == 0
    assert session.status().stop_reason == "达到时长上限"


def test_stop_request_is_independent_of_new_packets(monkeypatch):
    calls = install_source(monkeypatch, idle=True)
    session = CaptureSession(CaptureConfig("lo0"))
    session.start()
    session.wait_ready()
    session.request_stop()
    assert session.join(1)
    assert session.status().stop_reason == "用户停止"
    assert calls[-1][0] == "close"


def test_initialization_error_wakes_caller(monkeypatch):
    def fail(*args, **kwargs):
        raise PcapError("没有 BPF 权限")

    monkeypatch.setattr("lab1a_sniffer.capture.LiveCapture", fail)
    session = CaptureSession(CaptureConfig("lo0"))
    session.start()
    with pytest.raises(PcapError, match="BPF 权限"):
        session.wait_ready(1)
    assert session.join()
    assert session.finished.is_set()


def test_read_error_releases_handle(monkeypatch):
    calls = install_source(monkeypatch, fail_read=True)
    session = CaptureSession(CaptureConfig("lo0"))
    session.start()
    assert session.join()
    assert session.status().error == "模拟网卡断开"
    assert session.status().stop_reason == "错误停止"
    assert calls[-1][0] == "close"


def test_sessions_cannot_be_started_twice(monkeypatch):
    install_source(monkeypatch, idle=True)
    session = CaptureSession(CaptureConfig("lo0", duration=0.01))
    session.start()
    assert session.join()
    with pytest.raises(RuntimeError):
        session.start()
