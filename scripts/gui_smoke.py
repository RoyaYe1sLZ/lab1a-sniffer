"""原生 Qt GUI 验收：受控本机流量、字段选择、十次启停和抓包中关闭。

从项目根目录运行：.venv/bin/python scripts/gui_smoke.py
此脚本会短暂显示真实窗口；截图与 JSON 写到 artifacts/stage3。
"""

import argparse
from collections import Counter
from contextlib import ExitStack, closing
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from lab1a_sniffer.gui import SnifferWindow, create_application


def wait_for(predicate, timeout=5000):
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        if predicate():
            return
        QTest.qWait(10)
    if not predicate():
        raise RuntimeError("GUI 状态等待超时")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/stage3"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    app = create_application()
    app.setQuitOnLastWindowClosed(False)
    window = SnifferWindow()
    checks = {"native_cocoa_platform": app.platformName() == "cocoa"}
    report = {"qt_platform": app.platformName(), "checks": checks}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"Lab1A native GUI capture"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    try:
        with ExitStack() as resources:
            udp4 = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp6 = resources.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
            udp4.bind(("127.0.0.1", 0))
            udp6.bind(("::1", 0))
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, name="gui-smoke-http")
            thread.start()
            resources.callback(server.server_close)
            resources.callback(thread.join, 3)
            resources.callback(server.shutdown)
            window.interfaces.setCurrentIndex(window.interfaces.findData("lo0"))
            window.bpf.setText(
                f"tcp port {server.server_port} or udp port {udp4.getsockname()[1]} "
                f"or udp port {udp6.getsockname()[1]} or icmp or icmp6")
            window.show()
            checks["window_exposed"] = QTest.qWaitForWindowExposed(window, 3000)
            QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
            wait_for(lambda: window.controller.state == "capturing")
            checks["controls_locked_while_capturing"] = not window.interfaces.isEnabled() and window.stop_button.isEnabled()
            udp4.sendto(b"Lab1A IPv4 UDP", udp4.getsockname())
            udp6.sendto(b"Lab1A IPv6 UDP", udp6.getsockname())
            with closing(http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)) as connection:
                connection.request("GET", "/lab1a/gui-demo")
                response = connection.getresponse()
                if response.status != 200 or response.read() != b"Lab1A native GUI capture":
                    raise RuntimeError("本机 HTTP 流量生成失败")
            for command in (["/sbin/ping", "-c", "1", "127.0.0.1"], ["/sbin/ping6", "-c", "1", "::1"]):
                subprocess.run(command, capture_output=True, timeout=3, check=True)
            expected = {"HTTP", "UDP", "ICMP", "ICMPv6"}
            wait_for(lambda: expected <= {p.protocol for p in window.model.packets})
            row = next(i for i, p in enumerate(window.model.packets) if p.protocol == "HTTP")
            window.table.scrollTo(window.proxy.index(row, 0))
            app.processEvents()
            QTest.mouseClick(window.table.viewport(), Qt.MouseButton.LeftButton,
                             pos=window.table.visualRect(window.proxy.index(row, 4)).center())
            checks["row_selection"] = window.current_packet is not None and window.current_packet.protocol == "HTTP"
            window.tree.collapseAll()
            http_item = next(window.tree.topLevelItem(i) for i in range(window.tree.topLevelItemCount())
                             if window.tree.topLevelItem(i).text(0) == "HTTP")
            window.tree.expandItem(http_item)
            window.tree.scrollToItem(http_item.child(0))
            app.processEvents()
            QTest.mouseClick(window.tree.viewport(), Qt.MouseButton.LeftButton,
                             pos=window.tree.visualItemRect(http_item.child(0)).center())
            checks["field_byte_highlight"] = bool(window.hex_view.extraSelections())
            checks["selection_pauses_auto_scroll"] = not window.auto_scroll.isChecked()
            QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
            wait_for(lambda: window.controller.state == "idle")
            checks["packets_retained_after_stop"] = window.model.rowCount() > 0
            checks["no_parse_issues"] = not any(p.issues for p in window.model.packets)
            checks["no_queue_drops"] = window.controller.last_status.queue_dropped == 0
            report["protocol_counts"] = dict(Counter(p.protocol for p in window.model.packets))
            report["cached_packets"] = window.model.rowCount()
            report["cache_bytes"] = window.model.memory_cost
            QTest.qWait(100)
            screenshot = args.output_dir / "gui-native.png"
            checks["screenshot_saved"] = window.grab().save(str(screenshot))
            report["screenshot"] = str(screenshot.resolve())

            def confirm_clear():
                modal = QApplication.activeModalWidget()
                if not isinstance(modal, QMessageBox):
                    raise RuntimeError("清空确认对话框未打开")
                button = next(button for button in modal.buttons()
                              if modal.buttonRole(button) == QMessageBox.ButtonRole.AcceptRole)
                QTest.mouseClick(button, Qt.MouseButton.LeftButton)

            QTimer.singleShot(50, confirm_clear)
            QTest.mouseClick(window.clear_button, Qt.MouseButton.LeftButton)
            checks["clear_resets_views"] = not window.model.rowCount() and not window.tree.topLevelItemCount() and not window.hex_view.toPlainText()
            if not checks["clear_resets_views"]:
                raise RuntimeError("确认清空后界面仍有数据，停止后续验收。")
            window.bpf.setText(f"udp port {udp4.getsockname()[1]}")
            maximum_stop_time = 0
            for _ in range(10):
                QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
                wait_for(lambda: window.controller.state == "capturing")
                QTest.qWait(60)
                started = time.monotonic()
                QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
                wait_for(lambda: window.controller.state == "idle")
                maximum_stop_time = max(maximum_stop_time, time.monotonic() - started)
            checks["ten_idle_start_stop_cycles"] = window.controller.state == "idle"
            report["max_idle_stop_seconds"] = round(maximum_stop_time, 6)
            QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
            wait_for(lambda: window.controller.state == "capturing")
            window.close()
            wait_for(lambda: not window.isVisible())
            checks["close_during_capture"] = window.controller.state == "idle" and window.controller.session is None
            checks["no_capture_threads_left"] = not any(t.name.startswith("pcap-") for t in threading.enumerate())
    finally:
        window.controller.shutdown()
        window.files.shutdown()
        window.dirty = False
        window.close()
        app.processEvents()
    report["passed"] = all(checks.values())
    (args.output_dir / "gui-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
