"""加分项原生验收：真实 lo0 TCP、多连接进程关联、时序定位与离线回归。"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from PySide6.QtCore import Qt, QEventLoop, QTimer
from PySide6.QtTest import QTest
from lab1a_sniffer.gui import SnifferWindow, create_application
from lab1a_sniffer.flows import endpoint, connection_key
from lab1a_sniffer.storage import load_capture


def wait_for(predicate, timeout=8):
    # 局部 Qt 事件循环会释放 GIL；连续 QTest.qWait 会饿死纯 Python 文件解析线程。
    if predicate():
        return
    loop = QEventLoop()
    timer = QTimer()
    deadline = time.monotonic() + timeout
    def poll():
        if predicate() or time.monotonic() >= deadline:
            loop.quit()
    timer.timeout.connect(poll)
    timer.start(20)
    loop.exec()
    timer.stop()
    assert predicate(), '等待超时'


def main():
    output = Path('artifacts/bonus').resolve()
    output.mkdir(parents=True, exist_ok=True)
    checks = {}
    server = subprocess.Popen([sys.executable, '-u', '-c', '''
import socket, threading
s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen()
print(s.getsockname()[1],flush=True)
def serve(c):
 with c:
  while data:=c.recv(4096): c.sendall(data)
while True:
 c,_=s.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()
'''], stdout=subprocess.PIPE, text=True)
    control = None
    clients = []
    app = create_application()
    app.setQuitOnLastWindowClosed(False)
    window = SnifferWindow()
    window._confirm_replace = lambda _: True
    report = {'checks': checks, 'qt_platform': app.platformName()}
    try:
        port = int(server.stdout.readline())
        window.show()
        checks['native_cocoa'] = app.platformName() == 'cocoa'
        checks['window_exposed'] = QTest.qWaitForWindowExposed(window, 3000)
        window.interfaces.setCurrentIndex(window.interfaces.findData('lo0'))
        window.bpf.setText(f'tcp port {port}')
        QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: window.controller.state == 'capturing')
        keys = []
        for i in range(2):
            c = socket.create_connection(('127.0.0.1', port), timeout=2)
            clients.append(c)
            keys.append(connection_key(endpoint(*c.getsockname()), endpoint(*c.getpeername())))
            c.sendall(f'lab1a-flow-{i}'.encode()); assert c.recv(100) == f'lab1a-flow-{i}'.encode()
        control = subprocess.Popen([sys.executable, '-u', '-c', '''
import socket,sys,time
c=socket.create_connection(('127.0.0.1',int(sys.argv[1])))
c.sendall(b'control'); c.recv(100);print(c.getsockname()[1],flush=True);time.sleep(30)
''', str(port)], stdout=subprocess.PIPE, text=True)
        control_port = int(control.stdout.readline())
        control_key = connection_key(endpoint('127.0.0.1', control_port), endpoint('127.0.0.1', port))
        wait_for(lambda: len(window.model.flows.flows) == 3)
        def owned():
            return all(any(p.pid == os.getpid() for p in f.owners) for f in window.model.flows.flows.values() if f.key in keys)
        wait_for(owned)
        checks['three_distinct_tcp_flows'] = len(window.model.flows.flows) == 3
        checks['all_three_handshakes_observed'] = all(f.established for f in window.model.flows.flows.values())
        checks['same_process_two_flows'] = owned()
        control_flow = next(f for f in window.model.flows.flows.values() if f.key == control_key)
        wait_for(lambda: any(p.pid == control.pid for p in control_flow.owners))
        checks['control_process_distinguished'] = all(p.pid != os.getpid() for p in control_flow.owners)
        window.tabs.setCurrentIndex(1)
        panel = window.flow_panel
        first = next(f for f in window.model.flows.flows.values() if f.key == keys[0])
        panel.table.setCurrentItem(panel._items[first.id])
        checks['timeline_has_both_directions'] = any('←' in panel.timeline.topLevelItem(i).text(2) for i in range(panel.timeline.topLevelItemCount()))
        checks['handshake_timing_shown'] = '未完整观测' not in panel.detail.text()
        timeline_row = panel.timeline.topLevelItem(1).data(0, Qt.ItemDataRole.UserRole)
        panel.packetRequested.emit(timeline_row)
        checks['timeline_maps_to_source_packet'] = window.proxy.mapToSource(window.table.currentIndex()).row() == timeline_row
        checks['follow_one_flow'] = window.proxy.rowCount() == len(first.rows)
        window.tabs.setCurrentIndex(1)
        owner = next(p for p in first.owners if p.pid == os.getpid())
        panel.process_filter.setCurrentIndex(panel.process_filter.findData(owner))
        panel.follow_owner()
        expected = sum(len(f.rows) for f in window.model.flows.flows.values() if owner in f.owners)
        checks['process_filter_all_own_flows_only'] = window.proxy.rowCount() == expected and window.proxy.flow_ids == frozenset(f.id for f in window.model.flows.flows.values() if f.key in keys)
        window.tabs.setCurrentIndex(1)
        panel.table.setCurrentItem(panel._items[first.id])
        QTest.qWait(100)
        window.grab().save(str(output / 'tcp-process-live.png'))
        for c in clients: c.close()
        clients.clear()
        wait_for(lambda: all(f.terminal for f in window.model.flows.flows.values() if f.key in keys))
        checks['four_way_close_observed'] = True
        QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: window.controller.state == 'idle' and not window.process_monitor.is_busy)
        originals = tuple(p.raw for p in window.model.packets)
        pcap = output / 'tcp-process-demo.pcap'
        window.save_file(pcap)
        wait_for(lambda: not window.files.is_active)
        checks['filtered_save_keeps_all_packets'] = tuple(p.raw for p in load_capture(pcap).packets) == originals
        window.open_file(pcap)
        wait_for(lambda: not window.files.is_active)
        checks['offline_rebuilds_three_flows'] = len(window.model.flows.flows) == 3
        checks['offline_no_process_guess'] = not any(f.owners for f in window.model.flows.flows.values()) and not window.process_monitor.enabled
        window.tabs.setCurrentIndex(1)
        panel.table.setCurrentItem(panel._items[1])
        QTest.qWait(100)
        checks['screenshot_saved'] = window.grab().save(str(output / 'tcp-flows-native.png'))
        # 用户提供的 PCAP 仅用于本机回归，绝不收入仓库。
        huawei = Path('artifacts/en0-huawei.pcap')
        if huawei.exists():
            window.open_file(huawei)
            wait_for(lambda: not window.files.is_active)
            target = next(f for f in window.model.flows.flows.values() if f.a.port == 55623 and f.b.port == 443)
            checks['huawei_168_packet_flow'] = len(target.rows) == 168 and target.handshake_us == 13221
            panel.table.setCurrentItem(panel._items[target.id])
            QTest.qWait(100)
            window.grab().save(str(output / 'huawei-flow-native.png'))
        window.dirty = False
        window.close()
        wait_for(lambda: not window.isVisible())
        checks['no_workers_left'] = not any(t.name.startswith(('pcap-', 'capture-')) for t in threading.enumerate() if t is not threading.main_thread())
        report.update(packets=len(originals), passed=all(checks.values()), screenshot=str(output / 'tcp-flows-native.png'))
    finally:
        for c in clients: c.close()
        for p in (control, server):
            if p:
                p.terminate()
                try: p.wait(3)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
                if p.stdout: p.stdout.close()
        window.process_monitor.shutdown(); window.controller.shutdown(); window.files.shutdown()
        window.dirty = False; window.close()
    (output / 'flows-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get('passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
