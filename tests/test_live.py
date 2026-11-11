import threading

import pytest

from lab1a_sniffer.diagnostics import check_idle_stop, check_loopback, check_physical
from lab1a_sniffer.pcap import LiveCapture, PcapError


pytestmark = pytest.mark.live


def test_loopback_http_udp4_udp6(tmp_path):
    result = check_loopback(tmp_path)
    assert result["passed"], result
    assert result["linktype_name"] == "NULL"
    assert result["status"]["queue_dropped"] == 0


def test_physical_outbound_udp(request, tmp_path):
    result = check_physical(request.config.getoption("--physical-interface"), tmp_path)
    assert result["passed"], result
    assert result["status"]["queue_dropped"] == 0


def test_repeated_idle_stop_releases_native_resources():
    for _ in range(10):
        result = check_idle_stop()
        assert result["passed"], result


def test_invalid_filter_then_successful_reopen():
    with pytest.raises(PcapError, match="BPF"):
        LiveCapture("lo0", bpf="tcp and (")
    with LiveCapture("lo0", bpf="udp port 59123") as capture:
        assert capture.read_packet() is None


def test_closed_and_cross_thread_access_are_rejected():
    capture = LiveCapture("lo0", bpf="udp port 59123")
    errors = []

    def misuse():
        try:
            capture.close()
        except RuntimeError as exc:
            errors.append(str(exc))

    try:
        thread = threading.Thread(target=misuse)
        thread.start()
        thread.join(2)
        assert errors
        assert capture.statistics() is not None
    finally:
        capture.close()
    capture.close()
    with pytest.raises(PcapError, match="已经关闭"):
        capture.read_packet()


def test_nonexistent_interface_reports_error():
    with pytest.raises(PcapError):
        LiveCapture("lab1a-no-such-interface")
