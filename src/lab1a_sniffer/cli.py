"""阶段 1 的可运行入口，后续保留为诊断工具。"""

import argparse
from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
import sys

from ._ffi import get_libpcap
from .capture import CaptureConfig, CaptureSession
from .diagnostics import check_idle_stop, check_loopback, check_physical
from .pcap import PcapError, list_interfaces, write_pcap


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="实验 1A 嗅探器 · 阶段 1 抓包基础")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("interfaces", help="列出 libpcap 可用网卡")
    capture = commands.add_parser("capture", help="限时抓包，Ctrl+C 可提前停止")
    capture.add_argument("-i", "--interface", required=True, help="例如 en0 或 lo0")
    capture.add_argument("-f", "--filter", default="", help="BPF 表达式，例如 'tcp or udp'")
    capture.add_argument("-t", "--duration", type=float, default=10, help="秒数，默认 10 秒")
    capture.add_argument("-c", "--count", type=int, default=20000, help="最多捕获包数，默认 20000")
    capture.add_argument("--snaplen", type=int, default=65535, help="单包最多复制字节数")
    capture.add_argument("-w", "--output", type=Path, help="可选，停止后保存为经典 PCAP")
    check = commands.add_parser("selfcheck", help="自动生成测试流量并验证真实抓包")
    check.add_argument("--physical-interface", help="同时验证物理网卡，例如 en0")
    check.add_argument("--output-dir", type=Path, help="可选，保存验收 PCAP 与 JSON 结果")
    return parser


def _capture(args) -> int:
    session = CaptureSession(CaptureConfig(
        args.interface, bpf=args.filter, duration=args.duration,
        snaplen=args.snaplen, max_packets=args.count,
    ))
    packets = []
    session.start()
    try:
        info = session.wait_ready()
        print(f"抓包已启动：{info.interface} · {info.linktype_name}（DLT={info.linktype}）", flush=True)
        for warning in info.warnings:
            print(f"libpcap 提示：{warning}", file=sys.stderr)
        print(f"抓包过滤：{args.filter or '无'}；最长 {args.duration:g} 秒；Ctrl+C 停止", flush=True)
        while not session.finished.is_set():
            batch = session.drain()
            for packet in batch:
                timestamp = datetime.fromtimestamp(packet.seconds).strftime("%H:%M:%S")
                print(f"#{len(packets) + 1:<6} {timestamp}.{packet.microseconds:06d} "
                      f"caplen={packet.captured_length:<6} wirelen={packet.wire_length:<6} "
                      f"DLT={packet.linktype} head={packet.data[:12].hex(' ')}")
                packets.append(packet)
            session.finished.wait(0.05)
    except KeyboardInterrupt:
        print("\n正在停止抓包…", flush=True)
    finally:
        session.request_stop()
        if not session.join():
            raise PcapError("抓包线程未能在 3 秒内退出。")
        packets.extend(session.drain(session.config.queue_size))
    status = session.status()
    print(json.dumps(asdict(status), ensure_ascii=False, indent=2))
    if status.error:
        return 1
    if args.output and session.info:
        write_pcap(args.output, packets, session.info)
        print(f"已保存 {len(packets)} 个包：{args.output.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "interfaces":
            print(get_libpcap().version)
            for interface in list_interfaces():
                flags = ", ".join(name for name, enabled in (
                    ("up", interface.is_up), ("running", interface.is_running),
                    ("loopback", interface.is_loopback),
                ) if enabled)
                print(f"{interface.name:<12} [{flags}] {interface.description}")
            return 0
        if args.command == "capture":
            return _capture(args)
        if args.command == "selfcheck":
            results = {"libpcap": get_libpcap().version, "loopback": check_loopback(args.output_dir)}
            if args.physical_interface:
                results["physical"] = check_physical(args.physical_interface, args.output_dir)
            results["idle_stop"] = check_idle_stop()
            results["passed"] = all(value["passed"] for value in results.values() if isinstance(value, dict))
            print(json.dumps(results, ensure_ascii=False, indent=2))
            if args.output_dir:
                (args.output_dir / "selfcheck.json").write_text(
                    json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return 0 if results["passed"] else 1
    except (PcapError, OSError, ValueError, TimeoutError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    return 0
