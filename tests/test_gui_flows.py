from dataclasses import replace
import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from lab1a_sniffer.gui import SnifferWindow
from lab1a_sniffer.gui_controller import CaptureController
from lab1a_sniffer.models import Interface
from lab1a_sniffer.processes import ProcessIdentity, SocketSnapshot
from lab1a_sniffer.storage import load_capture
from .test_gui import FakeSession, wait_for, start
from .test_flows import segment
from .packet_samples import golden_packets


@pytest.fixture
def flow_window(qapp, monkeypatch):
    controller = CaptureController(session_factory=FakeSession)
    window = SnifferWindow(controller=controller, interfaces_provider=lambda: [Interface('lo0', '', 7)],
                           process_scanner=lambda cancelled: SocketSnapshot(0, 0, {}, '受控快照'))
    monkeypatch.setattr(window, '_confirm_replace', lambda _: True)
    window.show()
    yield window
    assert window.process_monitor.shutdown()
    assert window.controller.shutdown()
    assert window.files.shutdown()
    window.dirty = False
    window.close()
    qapp.processEvents()


def populate(window):
    session = start(window)
    session.queue.extend([segment().raw, segment(700, 101, 18, reverse=True, us=1000).raw,
                          segment(101, 701, 16, us=1100).raw, segment(port=45679).raw,
                          golden_packets()['ipv6-udp']])
    wait_for(lambda: window.model.rowCount() == 5)
    return session


def test_flow_view_direction_timeline_jump_and_combined_filters(flow_window):
    w = flow_window
    populate(w)
    w.tabs.setCurrentIndex(1)
    assert w.flow_panel.table.topLevelItemCount() == 2
    w.flow_panel.table.setCurrentItem(w.flow_panel._items[1])
    assert w.flow_panel.timeline.topLevelItemCount() == 3
    assert '已见三次握手' in w.flow_panel._items[1].text(3)
    assert '→' in w.flow_panel.timeline.topLevelItem(0).text(2)
    assert '←' in w.flow_panel.timeline.topLevelItem(1).text(2)
    w.flow_panel.follow_selected()
    assert w.proxy.rowCount() == 3 and w.model.rowCount() == 5
    w.display_filter.setCurrentText('UDP')
    assert w.proxy.rowCount() == 0 and w.current_packet is None
    w._jump_packet(1)
    assert w.display_filter.currentText() == '全部'
    assert w.proxy.mapToSource(w.table.currentIndex()).row() == 1
    w._follow(None, '')
    assert w.proxy.rowCount() == 5


def test_process_groups_all_observed_flows_and_live_insertions(flow_window):
    w = flow_window
    session = populate(w)
    owner = ProcessIdentity(123, 'Example', 'Thu Nov 12 00:00:00 2026')
    stamp = w.model.flows.flows[1].first_us
    snapshot = SocketSnapshot(stamp, stamp + 2000, {f.key: {owner} for f in w.model.flows.flows.values()})
    w._process_snapshot(snapshot)
    w.tabs.setCurrentIndex(1)
    w.flow_panel.process_filter.setCurrentIndex(1)
    assert w.flow_panel.follow_process.isEnabled()
    w.flow_panel.follow_owner()
    assert w.proxy.rowCount() == 4
    session.queue.append(segment(port=45680).raw)
    wait_for(lambda: w.model.rowCount() == 6)
    assert w.proxy.rowCount() == 4
    snapshot = replace(snapshot, connections={f.key: {owner} for f in w.model.flows.flows.values()})
    w._process_snapshot(snapshot)
    assert w.proxy.rowCount() == 5
    assert 'PID 123' in w.flow_filter_label.text()


def test_follow_filter_export_all_and_offline_resets_processes(flow_window, tmp_path):
    w = flow_window
    populate(w)
    w.controller.stop()
    wait_for(lambda: w.controller.state == 'idle')
    w._follow(('flow', 1), 'TCP 流 1')
    path = tmp_path / 'flows.pcap'
    assert w.save_file(path)
    wait_for(lambda: not w.files.is_active)
    assert len(load_capture(path).packets) == 5
    assert w.open_file(path)
    wait_for(lambda: not w.files.is_active)
    assert len(w.model.flows.flows) == 2 and w.proxy.rowCount() == 5
    assert w._follow_filter is None and not w.process_monitor.enabled
    assert not any(f.owners for f in w.model.flows.flows.values())
    assert '无历史进程' in w.flow_panel.process_status.text()
    w._follow(('flow', 1), 'TCP 流 1')
    w.clear_packets()
    assert not w.model.flows.flows and w.proxy.flow_ids is None
    assert not w.flow_panel.timeline.topLevelItemCount()


def test_timeline_is_paged_and_trace_current_selects_flow(flow_window):
    w = flow_window
    session = start(w)
    session.queue.extend(segment(100 + i, 0, 24).raw for i in range(405))
    wait_for(lambda: w.model.rowCount() == 405)
    w.table.selectRow(201)
    QTest.mouseClick(w.follow_current_button, Qt.MouseButton.LeftButton)
    panel = w.flow_panel
    assert w.tabs.currentIndex() == 1
    assert panel.timeline.topLevelItemCount() == 200
    panel._change_page(1)
    assert panel.timeline.topLevelItem(0).text(0) == '201'
    panel._change_page(1)
    assert panel.timeline.topLevelItemCount() == 5
    assert not panel.next.isEnabled()


def test_close_cancels_inflight_process_snapshot(qapp, monkeypatch):
    import threading, time
    entered = threading.Event()
    def scanner(cancelled):
        entered.set()
        while not cancelled(): time.sleep(.005)
        raise InterruptedError()
    w = SnifferWindow(controller=CaptureController(session_factory=FakeSession),
                      interfaces_provider=lambda: [Interface('lo0', '', 7)], process_scanner=scanner)
    monkeypatch.setattr(w, '_confirm_replace', lambda _: True)
    w.show(); start(w)
    wait_for(entered.is_set)
    w.close()
    wait_for(lambda: not w.isVisible())
    assert not w.process_monitor.is_busy
    assert not any(t.name == 'pcap-process-snapshot' for t in threading.enumerate())


def test_follow_current_clears_conflicting_process_list_filter(flow_window):
    w = flow_window
    populate(w)
    owner = ProcessIdentity(123, 'Example', 'start')
    flow = w.model.flows.flows[1]
    w._process_snapshot(SocketSnapshot(flow.first_us, flow.last_us, {flow.key: {owner}}))
    w.tabs.setCurrentIndex(1)
    w.flow_panel.process_filter.setCurrentIndex(1)
    w.tabs.setCurrentIndex(0)
    w.table.selectRow(3)
    w._follow_current()
    assert w.flow_panel.process_filter.currentData() is None
    assert w.flow_panel._selected == 2
    assert not w.flow_panel._items[2].isHidden()
