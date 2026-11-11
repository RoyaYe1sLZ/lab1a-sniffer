"""第四阶段原生窗口验收：协议显示过滤、PCAP 全量导出与错误保留。

运行 .venv/bin/python scripts/gui_files_smoke.py。
文件选择器返回受控路径；其他操作使用真实 Cocoa 窗口、Qt 控件和 libpcap。
"""

import argparse
import json
from pathlib import Path
import subprocess
import threading
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QFileDialog

from lab1a_sniffer.gui import SnifferWindow, create_application
from lab1a_sniffer.pcap import write_pcap
from lab1a_sniffer.storage import load_capture
from gui_smoke import wait_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/stage4"))
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[1] / "samples" / "protocols.pcap"
    app = create_application()
    app.setQuitOnLastWindowClosed(False)
    window = SnifferWindow()
    checks = {"native_cocoa_platform": app.platformName() == "cocoa"}
    report = {"qt_platform": app.platformName(), "file_picker": "controlled paths", "checks": checks}

    def open_path(path):
        with patch.object(QFileDialog, "getOpenFileName", return_value=(str(path), "")):
            QTest.mouseClick(window.open_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: not window.files.is_active)

    def save_path(path):
        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(path), "")):
            QTest.mouseClick(window.save_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: not window.files.is_active)

    def select_filter(name):
        window.display_filter.setFocus()
        QTest.keyClick(window.display_filter, Qt.Key.Key_Home)
        for _ in range(window.display_filter.findText(name)):
            QTest.keyClick(window.display_filter, Qt.Key.Key_Down)
        app.processEvents()

    try:
        window.show()
        checks["window_exposed"] = QTest.qWaitForWindowExposed(window, 3000)
        open_path(source)
        checks["opened_five_packets"] = window.model.rowCount() == 5 and window.source_kind == "file"
        originals = tuple(p.raw for p in window.model.packets)
        counts = {}
        for name, count in (("HTTP", 2), ("TCP", 2), ("UDP", 1), ("IPv4", 3),
                            ("IPv6", 2), ("ICMP", 1), ("ICMPv6", 1)):
            select_filter(name)
            counts[name] = window.proxy.rowCount()
            checks[f"filter_{name}"] = window.proxy.rowCount() == count and window.model.rowCount() == 5
        checks["filtered_row_maps_to_original"] = window.current_packet.protocol == "ICMPv6" and "第 5 包" in window.packet_meta.text()
        select_filter("HTTP")
        checks["http_also_matches_tcp"] = window.proxy.data(window.proxy.index(0, 4)) == "HTTP"
        exported = output / "过滤后保存全部.pcap"
        save_path(exported)
        exported_packets = tuple(p.raw for p in load_capture(exported).packets)
        checks["export_all_hidden_packets_and_timestamps"] = exported_packets == originals
        checks["saved_state"] = not window.dirty and window.source_path == exported
        decoded = subprocess.run(["/usr/sbin/tcpdump", "-nn", "-r", str(exported)],
                                 capture_output=True, text=True, timeout=5, check=True)
        checks["tcpdump_reads_five_packets"] = len(decoded.stdout.strip().splitlines()) == 5
        window.tree.collapseAll()
        http_item = next(window.tree.topLevelItem(i) for i in range(window.tree.topLevelItemCount())
                         if window.tree.topLevelItem(i).text(0) == "HTTP")
        window.tree.expandItem(http_item)
        window.tree.setCurrentItem(http_item.child(0))
        QTest.qWait(100)
        screenshot = output / "gui-files-native.png"
        checks["screenshot_saved"] = window.grab().save(str(screenshot))

        one = output / "仅HTTP.pcap"
        write_pcap(one, originals[:1], window.capture_info)
        select_filter("UDP")
        open_path(one)
        checks["zero_visible_rows_keep_data"] = window.proxy.rowCount() == 0 and window.model.rowCount() == 1
        checks["hidden_selection_cleared"] = window.current_packet is None and not window.tree.topLevelItemCount()
        zero_export = output / "零条显示时保存全部.pcap"
        save_path(zero_export)
        checks["zero_visible_export_still_has_packet"] = tuple(p.raw for p in load_capture(zero_export).packets) == originals[:1]
        broken = output / "损坏文件.pcap"
        broken.write_bytes(one.read_bytes()[:-1])
        before = tuple(window.model.packets)
        open_path(broken)
        checks["bad_file_preserves_previous_data"] = tuple(window.model.packets) == before and "读取失败" in window.banner.text()
        with patch.object(QFileDialog, "getOpenFileName", return_value=("", "")):
            QTest.mouseClick(window.open_button, Qt.MouseButton.LeftButton)
        checks["cancel_file_picker_preserves_data"] = tuple(window.model.packets) == before and not window.files.is_active
        window.close()
        wait_for(lambda: not window.isVisible())
        checks["no_file_or_capture_threads_left"] = not any(t.name.startswith("pcap-") for t in threading.enumerate())
    finally:
        window.files.shutdown()
        window.controller.shutdown()
        window.dirty = False
        window.close()
        app.processEvents()
    report.update(filter_counts=counts, exported_packets=len(exported_packets),
                  screenshot=str(screenshot), passed=all(checks.values()))
    (output / "gui-files-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
