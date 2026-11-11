from pathlib import Path
import threading
import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from lab1a_sniffer.gui import SnifferWindow
from lab1a_sniffer.gui_models import PacketTableModel, ProtocolFilterModel
from lab1a_sniffer.models import CaptureInfo
from lab1a_sniffer.parser import parse_packet
from lab1a_sniffer.pcap import FileCancelled, write_pcap
from lab1a_sniffer.storage import load_capture
from .packet_samples import golden_packets
from .test_gui import wait_for


@pytest.fixture
def file_window(qapp, monkeypatch):
    value = SnifferWindow(interfaces_provider=lambda: [])
    monkeypatch.setattr(value, "_confirm_replace", lambda _: True)
    value.show()
    yield value
    assert value.files.shutdown()
    assert value.controller.shutdown()
    value.dirty = False
    value.close()
    qapp.processEvents()


def sample_file(tmp_path):
    path = tmp_path / "中文 样本.pcap"
    write_pcap(path, golden_packets().values(), CaptureInfo("fixture", 1, "EN10MB", 65535))
    return path


@pytest.mark.parametrize("protocol,count", [("全部", 5), ("HTTP", 2), ("TCP", 2), ("UDP", 1),
                                            ("IPv4", 3), ("IPv6", 2), ("ICMP", 1), ("ICMPv6", 1)])
def test_display_filter_matches_all_layers_and_preserves_source(qapp, protocol, count):
    model = PacketTableModel()
    proxy = ProtocolFilterModel()
    proxy.setSourceModel(model)
    model.append_packets([parse_packet(p) for p in golden_packets().values()])
    proxy.set_protocol(protocol)
    assert proxy.rowCount() == count
    assert model.rowCount() == 5
    if protocol == "TCP":
        assert proxy.data(proxy.index(0, 4)) == "HTTP"


def test_invalid_filter_does_not_change_current_selection(qapp):
    proxy = ProtocolFilterModel()
    proxy.set_protocol("TCP")
    with pytest.raises(ValueError):
        proxy.set_protocol("not-a-protocol")
    assert proxy.protocol == "TCP"


def test_live_insertions_respect_existing_display_filter(qapp):
    model = PacketTableModel()
    proxy = ProtocolFilterModel()
    proxy.setSourceModel(model)
    proxy.set_protocol("HTTP")
    model.append_packets([parse_packet(golden_packets()["ipv6-udp"])])
    assert proxy.rowCount() == 0
    model.append_packets([parse_packet(golden_packets()["http-request"])])
    assert proxy.rowCount() == 1 and model.rowCount() == 2
    assert proxy.data(proxy.index(0, 0)) == "2"
    assert proxy.mapToSource(proxy.index(0, 0)).row() == 1


def test_open_filter_correct_packet_mapping_and_export_all(file_window, tmp_path):
    value = file_window
    path = sample_file(tmp_path)
    assert value.open_file(path)
    wait_for(lambda: not value.files.is_active)
    assert value.model.rowCount() == 5 and value.source_kind == "file" and not value.dirty
    value.display_filter.setCurrentText("UDP")
    assert value.proxy.rowCount() == 1 and value.model.rowCount() == 5
    assert value.current_packet.protocol == "UDP"
    assert "第 3 包" in value.packet_meta.text()
    assert "显示 1 / 全部 5" in value.count_label.text()
    output = tmp_path / "保存 全部.pcap"
    assert value.save_file(output)
    wait_for(lambda: not value.files.is_active)
    reopened = load_capture(output)
    assert [p.raw for p in reopened.packets] == [p.raw for p in value.model.packets]
    assert len(reopened.packets) == 5
    value.display_filter.setCurrentText("全部")
    assert value.proxy.rowCount() == 5


def test_zero_visible_rows_still_exports_all(file_window, tmp_path):
    path = tmp_path / "http-only.pcap"
    original = golden_packets()["http-request"]
    write_pcap(path, [original], CaptureInfo("fixture", 1, "EN10MB", 65535))
    assert file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    file_window.display_filter.setCurrentText("UDP")
    assert file_window.proxy.rowCount() == 0 and file_window.model.rowCount() == 1
    assert "没有符合" in file_window.empty_title.text()
    assert file_window.current_packet is None
    output = tmp_path / "all.pcap"
    assert file_window.save_file(output)
    wait_for(lambda: not file_window.files.is_active)
    assert load_capture(output).packets[0].raw == original


def test_bad_file_and_failed_save_preserve_existing_state(file_window, tmp_path):
    path = sample_file(tmp_path)
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    old = list(file_window.model.packets)
    bad = tmp_path / "broken.pcap"
    bad.write_bytes(path.read_bytes()[:-1])
    file_window.open_file(bad)
    wait_for(lambda: not file_window.files.is_active)
    assert file_window.model.packets == old and file_window.source_path == path
    assert "失败" in file_window.banner.text()
    missing = tmp_path / "missing" / "out.pcap"
    file_window.dirty = True
    assert file_window.save_file(missing)
    wait_for(lambda: not file_window.files.is_active)
    assert file_window.dirty and file_window.model.packets == old


def test_import_over_budget_preserves_old_list(file_window, tmp_path):
    path = sample_file(tmp_path)
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    old = list(file_window.model.packets)
    file_window.model.max_packets = 1
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    assert file_window.model.packets == old
    assert "上限" in file_window.banner.text()


def test_background_import_cancellation_preserves_old_list_and_ui_heartbeat(file_window, tmp_path, monkeypatch):
    from PySide6.QtCore import QTimer
    path = sample_file(tmp_path)
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    old = list(file_window.model.packets)
    entered = threading.Event()

    def slow_load(path, *, cancelled, **kwargs):
        entered.set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if cancelled():
                raise FileCancelled("cancelled")
            time.sleep(.005)
        return load_capture(path)

    monkeypatch.setattr("lab1a_sniffer.gui_files.load_capture", slow_load)
    ticks = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(10)
    assert file_window.open_file(path)
    wait_for(entered.is_set)
    QTest.qWait(80)
    assert ticks and not file_window.start_button.isEnabled() and not file_window.open_button.isEnabled()
    file_window.files.cancel()
    wait_for(lambda: not file_window.files.is_active)
    timer.stop()
    assert file_window.model.packets == old


def test_empty_capture_and_unsaved_close_cancel(file_window, tmp_path, monkeypatch):
    path = tmp_path / "empty.pcap"
    write_pcap(path, [], CaptureInfo("empty", 1, "EN10MB", 65535))
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    assert "没有数据包" in file_window.empty_title.text()
    assert file_window.save_button.isEnabled()
    file_window.dirty = True
    file_window.model.append_packets([parse_packet(golden_packets()["http-request"])])
    monkeypatch.setattr(file_window, "_confirm_replace", lambda _: False)
    file_window.close()
    assert file_window.isVisible()


def test_close_during_save_waits_for_atomic_write(file_window, tmp_path, monkeypatch):
    import lab1a_sniffer.gui_files as tasks
    path = sample_file(tmp_path)
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    entered, release = threading.Event(), threading.Event()
    real_write = tasks.write_pcap

    def slow_write(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return real_write(*args, **kwargs)

    monkeypatch.setattr(tasks, "write_pcap", slow_write)
    output = tmp_path / "close-save.pcap"
    file_window.dirty = True
    file_window.save_file(output)
    wait_for(entered.is_set)
    file_window.close()
    assert file_window.isVisible() and file_window._closing
    release.set()
    wait_for(lambda: not file_window.isVisible())
    assert len(load_capture(output).packets) == 5
    assert not file_window.files.is_active and not file_window.dirty


def test_close_during_import_cancels_worker(file_window, tmp_path, monkeypatch):
    path = sample_file(tmp_path)
    file_window.open_file(path)
    wait_for(lambda: not file_window.files.is_active)
    entered = threading.Event()

    def slow_load(path, *, cancelled, **kwargs):
        entered.set()
        while not cancelled():
            time.sleep(.005)
        raise FileCancelled("cancelled")

    monkeypatch.setattr("lab1a_sniffer.gui_files.load_capture", slow_load)
    file_window.open_file(path)
    wait_for(entered.is_set)
    file_window.close()
    wait_for(lambda: not file_window.isVisible())
    assert not file_window.files.is_active
    assert file_window.model.rowCount() == 5
