from collections import deque
from dataclasses import replace
import socket
import threading
import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest, QSignalSpy

from lab1a_sniffer.capture import CaptureStatus
from lab1a_sniffer.gui import SnifferWindow
from lab1a_sniffer.gui_controller import CaptureController
from lab1a_sniffer.gui_models import PacketTableModel, packet_memory_cost
from lab1a_sniffer.models import CaptureInfo, Interface
from lab1a_sniffer.parser import parse_packet
from .packet_samples import REQUEST, ethernet, golden_packets, ipv4, packet, tcp


def wait_for(predicate, timeout=2000):
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        if predicate():
            return
        QTest.qWait(10)
    assert predicate(), "等待 Qt 状态超时"


class FakeSession:
    def __init__(self, config):
        self.config = config
        self.info = CaptureInfo(config.interface, 1, "EN10MB", 65535)
        self.is_ready = False
        self.finished = threading.Event()
        self.queue = deque()
        self.result = CaptureStatus(stop_reason="抓包中")

    @property
    def pending_count(self):
        return len(self.queue)

    def start(self):
        self.is_ready = True
        if self.config.bpf == "bad":
            self.result = CaptureStatus(stop_reason="错误停止", error="无效的 BPF 过滤表达式")
            self.info = None
            self.finished.set()

    def drain(self, limit=128):
        return [self.queue.popleft() for _ in range(min(limit, len(self.queue)))]

    def status(self):
        return self.result

    def request_stop(self):
        if not self.result.error:
            self.result = replace(self.result, stop_reason="用户停止")
        self.finished.set()

    def join(self, timeout=3):
        return self.finished.is_set()


@pytest.fixture
def window(qapp, monkeypatch):
    controller = CaptureController(session_factory=FakeSession)
    value = SnifferWindow(controller=controller,
                          interfaces_provider=lambda: [Interface("en0", "", 14), Interface("lo0", "", 7)])
    # 数据丢弃确认在另一项测试中验证；多数生命周期测试明确同意替换。
    monkeypatch.setattr(value, "_confirm_replace", lambda _: True)
    value.show()
    qapp.processEvents()
    yield value
    assert controller.shutdown()
    value.close()
    qapp.processEvents()


def start(window):
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: window.controller.state == "capturing")
    return window.controller.session


def test_model_role_values_and_insert_notification(qapp):
    model = PacketTableModel()
    spy = QSignalSpy(model.rowsInserted)
    samples = [parse_packet(p) for p in golden_packets().values()]
    assert model.append_packets(samples) == 5
    assert spy.count() == 1
    assert model.data(model.index(0, 0)) == "1"
    assert model.data(model.index(0, 2)) == "192.0.2.1"
    assert model.data(model.index(0, 2), Qt.ItemDataRole.ToolTipRole) == "192.0.2.1"
    assert model.data(model.index(0, 4)) == "HTTP"
    assert model.raw_bytes == sum(p.raw.captured_length for p in samples)


def test_cache_budget_counts_parsed_objects_and_never_exceeds_limit(qapp):
    parsed = parse_packet(golden_packets()["http-request"])
    cost = packet_memory_cost(parsed)
    assert cost > parsed.raw.captured_length
    model = PacketTableModel(max_memory=cost * 2)
    assert model.append_packets([parsed] * 5) == 2
    assert model.rowCount() == 2
    assert model.memory_cost <= model.max_memory
    assert model.rejected_count == 3
    assert model.limit_message
    model.clear()
    assert model.rowCount() == model.memory_cost == model.raw_bytes == model.rejected_count == 0
    assert not model.limit_message


def test_packet_count_limit_stops_accepting_rows(qapp):
    parsed = parse_packet(golden_packets()["http-request"])
    model = PacketTableModel(max_packets=2)
    assert model.append_packets([parsed] * 3) == 2
    assert model.append_packets([parsed]) == 0
    assert model.rejected_count == 2


def test_start_stop_and_data_selection_update_all_views(window):
    session = start(window)
    assert not window.interfaces.isEnabled() and window.stop_button.isEnabled()
    session.queue.extend(golden_packets().values())
    wait_for(lambda: window.model.rowCount() == 5)
    assert window.current_packet.protocol == "HTTP"
    assert "GET /lab1a" in window.model.data(window.model.index(0, 6))
    assert "00000000" in window.hex_view.toPlainText()
    assert window.tree.topLevelItemCount() >= 5
    QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: window.controller.state == "idle")
    assert window.start_button.isEnabled() and window.clear_button.isEnabled()
    assert window.model.rowCount() == 5


def test_tcp_field_selects_correct_raw_bytes(window):
    session = start(window)
    session.queue.append(golden_packets()["http-request"])
    wait_for(lambda: window.model.rowCount() == 1)
    tcp_item = next(window.tree.topLevelItem(i) for i in range(window.tree.topLevelItemCount())
                    if window.tree.topLevelItem(i).text(0) == "TCP")
    field = tcp_item.child(0)
    assert field.text(0) == "源端口"
    window.tree.setCurrentItem(field)
    assert window.hex_view.extraSelections()
    assert window.hex_view.textCursor().selectedText() == "30 39"


def test_field_beyond_preview_automatically_shows_full_bytes(window):
    payload = b"GET / HTTP/1.1\r\nX-Padding: " + b"a" * 5000 + b"\r\nHost: example.test\r\n\r\n"
    session = start(window)
    session.queue.append(packet(ethernet(ipv4(tcp(payload)))))
    wait_for(lambda: window.model.rowCount() == 1)
    assert window.full_bytes_button.isEnabled()
    http = window.tree.topLevelItem(window.tree.topLevelItemCount() - 1)
    host = next(http.child(i) for i in range(http.childCount()) if http.child(i).text(0) == "Host")
    window.tree.setCurrentItem(host)
    assert not window.full_bytes_button.isEnabled()
    assert "省略" not in window.hex_view.toPlainText()
    assert window.hex_view.extraSelections()


def test_failed_filter_preserves_previous_packets_and_allows_retry(window):
    session = start(window)
    session.queue.append(golden_packets()["http-request"])
    wait_for(lambda: window.model.rowCount() == 1)
    window.controller.stop()
    wait_for(lambda: window.controller.state == "idle")
    previous = window.model.packets[0]
    window.bpf.setText("bad")
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: window.controller.state == "idle")
    assert window.model.packets == [previous]
    assert "BPF" in window.banner.text()
    window.bpf.clear()
    start(window)
    assert window.model.rowCount() == 0


def test_cache_full_requests_capture_stop(window):
    window.model.max_packets = 1
    session = start(window)
    session.queue.extend(golden_packets().values())
    wait_for(lambda: window.controller.state == "idle")
    assert window.model.rowCount() == 1
    assert window.model.rejected_count == 4
    assert "缓存上限" in window.banner.text()


def test_close_during_capture_waits_for_thread_then_hides_window(window):
    session = start(window)
    window.close()
    assert window._closing
    wait_for(lambda: not window.isVisible())
    assert session.finished.is_set()
    assert window.controller.state == "idle"


def test_clear_resets_table_details_and_statistics(window):
    session = start(window)
    session.queue.append(golden_packets()["http-request"])
    wait_for(lambda: window.model.rowCount() == 1)
    window.controller.stop()
    wait_for(lambda: window.controller.state == "idle")
    QTest.mouseClick(window.clear_button, Qt.MouseButton.LeftButton)
    assert not window.model.rowCount() and not window.tree.topLevelItemCount()
    assert not window.hex_view.toPlainText()
    assert "0 个包" in window.count_label.text()
    assert not window.clear_button.isEnabled()


def test_declining_replacement_leaves_current_capture_data(window, monkeypatch):
    session = start(window)
    session.queue.append(golden_packets()["http-request"])
    wait_for(lambda: window.model.rowCount() == 1)
    window.controller.stop()
    wait_for(lambda: window.controller.state == "idle")
    monkeypatch.setattr(window, "_confirm_replace", lambda _: False)
    QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
    assert window.controller.state == "idle" and window.model.rowCount() == 1


def test_missing_interfaces_disables_capture(qapp):
    value = SnifferWindow(interfaces_provider=lambda: [])
    assert not value.start_button.isEnabled()
    assert "未发现" in value.banner.text()
    value.close()


@pytest.mark.live
def test_real_gui_capture_and_close(qapp):
    value = SnifferWindow(interfaces_provider=lambda: [Interface("lo0", "", 7)])
    value.show()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind(("127.0.0.1", 0))
        value.bpf.setText(f"udp port {sender.getsockname()[1]}")
        QTest.mouseClick(value.start_button, Qt.MouseButton.LeftButton)
        try:
            wait_for(lambda: value.controller.state == "capturing")
            sender.sendto(b"lab1a-real-gui", sender.getsockname())
            wait_for(lambda: value.model.rowCount() >= 1)
            assert value.model.packets[0].protocol == "UDP"
            assert value.model.packets[0].source == "127.0.0.1"
            value.close()
            wait_for(lambda: not value.isVisible())
            assert value.controller.state == "idle"
        finally:
            assert value.controller.shutdown()
            value.close()
