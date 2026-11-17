"""最终验收：真实 GUI 连续抓包，记录 RSS、CPU、事件响应与全量往返。

默认 300 秒、约 20 个本机 UDP 包/秒，不向外部主机发送测试流量。
"""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt
import socket

from lab1a_sniffer.gui import SnifferWindow, create_application
from lab1a_sniffer.storage import load_capture
from gui_smoke import wait_for


def rss_bytes():
    return int(subprocess.check_output(["/bin/ps", "-o", "rss=", "-p", str(os.getpid())], text=True).strip()) * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/final/stability"))
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("seconds 必须大于零")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    app = create_application()
    app.setQuitOnLastWindowClosed(False)
    window = SnifferWindow()
    report = {"seconds_requested": args.seconds, "qt_platform": app.platformName(), "samples": []}
    udp4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp4.bind(("127.0.0.1", 0))
    udp6.bind(("::1", 0))
    udp4.setblocking(False)
    udp6.setblocking(False)
    sent = 0
    maximum_gap = 0.0
    last_beat = time.monotonic()
    started = process_started = 0.0
    heartbeat = QTimer()
    producer = QTimer()
    sampler = QTimer()

    def beat():
        nonlocal last_beat, maximum_gap
        now = time.monotonic()
        maximum_gap = max(maximum_gap, now - last_beat)
        last_beat = now

    def produce():
        nonlocal sent
        sender = udp4 if sent % 2 == 0 else udp6
        sender.sendto(f"lab1a-stability-{sent:08d}".encode() + bytes(40), sender.getsockname())
        try:
            sender.recv(4096)
        except BlockingIOError:
            pass
        sent += 1

    def sample():
        row = {"seconds": round(time.monotonic() - started, 3), "rss_bytes": rss_bytes(),
               "cached_packets": window.model.rowCount(), "cache_budget_bytes": window.model.memory_cost,
               "queue_dropped": window.controller.last_status.queue_dropped,
               "heartbeat_max_gap_seconds": round(maximum_gap, 6)}
        report["samples"].append(row)
        if window.proxy.rowCount():
            window.table.selectRow(window.proxy.rowCount() - 1)
        print(json.dumps(row), flush=True)

    try:
        window.interfaces.setCurrentIndex(window.interfaces.findData("lo0"))
        window.bpf.setText(f"udp port {udp4.getsockname()[1]} or udp port {udp6.getsockname()[1]}")
        window.show()
        QTest.qWaitForWindowExposed(window, 3000)
        QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: window.controller.state == "capturing")
        started = time.monotonic()
        process_started = time.process_time()
        last_beat = started
        heartbeat.timeout.connect(beat)
        heartbeat.start(20)
        producer.timeout.connect(produce)
        producer.start(50)
        sampler.timeout.connect(sample)
        sampler.start(10000)
        sample()
        deadline = started + args.seconds
        while time.monotonic() < deadline:
            QTest.qWait(20)
            if window.controller.state != "capturing":
                raise RuntimeError("稳定性测试期间抓包提前停止")
        producer.stop()
        QTest.qWait(150)
        QTest.mouseClick(window.stop_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: window.controller.state == "idle")
        sampler.stop()
        heartbeat.stop()
        elapsed = time.monotonic() - started
        sample()
        stats = window.controller.last_status
        originals = tuple(p.raw for p in window.model.packets)
        target = args.output_dir / "continuous.pcap"
        window.save_file(target)
        wait_for(lambda: not window.files.is_active)
        reloaded = load_capture(target)
        checks = {
            "native_cocoa_platform": app.platformName() == "cocoa",
            "duration_reached": elapsed >= args.seconds,
            "all_generated_packets_captured": len(originals) == sent,
            "no_queue_drops": stats.queue_dropped == 0,
            "no_kernel_drops": stats.kernel is not None and stats.kernel.dropped == 0,
            "cache_within_budget": window.model.memory_cost <= window.model.max_memory,
            "no_parse_issues": not any(p.issues for p in window.model.packets),
            "ui_heartbeat_under_one_second": maximum_gap < 1,
            "pcap_roundtrip_exact": tuple(p.raw for p in reloaded.packets) == originals,
        }
        window.grab().save(str(args.output_dir / "continuous.png"))
        window.close()
        wait_for(lambda: not window.isVisible())
        checks["no_threads_left"] = not any(t.name.startswith("pcap-") for t in threading.enumerate())
        report.update(checks=checks, passed=all(checks.values()), seconds_elapsed=round(elapsed, 3),
                      generated_packets=sent, captured_packets=len(originals), capture_status=asdict(stats),
                      max_heartbeat_gap_seconds=round(maximum_gap, 6),
                      cpu_seconds=round(time.process_time() - process_started, 3))
    finally:
        for timer in (producer, sampler, heartbeat):
            timer.stop()
        udp4.close()
        udp6.close()
        window.files.shutdown()
        window.controller.shutdown()
        window.dirty = False
        window.close()
        app.processEvents()
    path = args.output_dir / "stability.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "samples"}, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
