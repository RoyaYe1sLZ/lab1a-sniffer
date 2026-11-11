"""网卡、抓包句柄和 PCAP 写入的安全封装，不负责 GUI 或协议解析。"""

from collections.abc import Iterable
import ctypes as C
import os
from pathlib import Path
import tempfile
import threading

from ._ffi import (
    BpfProgram, PacketHeader, PcapError, PcapInterface, PcapStats, Timeval,
    decode, get_libpcap,
)
from .models import CaptureInfo, Interface, KernelStats, RawPacket

__all__ = ["PcapError", "LiveCapture", "list_interfaces", "write_pcap"]


def list_interfaces() -> list[Interface]:
    lib = get_libpcap().lib
    head = C.POINTER(PcapInterface)()
    error = C.create_string_buffer(256)
    if lib.pcap_findalldevs(C.byref(head), error) != 0:
        raise PcapError(f"枚举网卡失败：{decode(error.value)}")
    try:
        interfaces = []
        current = head
        while current:
            value = current.contents
            interfaces.append(Interface(decode(value.name), decode(value.description), value.flags))
            current = value.next
        return interfaces
    finally:
        if head:
            lib.pcap_freealldevs(head)


def _apply_filter(lib, handle: int, expression: str) -> None:
    if "\0" in expression:
        raise ValueError("过滤表达式不能包含 NUL 字符。")
    program = BpfProgram()
    # PCAP_NETMASK_UNKNOWN；不假定某个网卡的 IPv4 掩码。
    if lib.pcap_compile(handle, C.byref(program), expression.encode(), 1, 0xFFFFFFFF) < 0:
        raise PcapError(f"无效的 BPF 过滤表达式：{decode(lib.pcap_geterr(handle))}")
    try:
        if lib.pcap_setfilter(handle, C.byref(program)) < 0:
            raise PcapError(f"应用过滤失败：{decode(lib.pcap_geterr(handle))}")
    finally:
        lib.pcap_freecode(C.byref(program))


class LiveCapture:
    """非阻塞抓包句柄：创建、读取、查询和关闭均须在同一个线程。

    外部线程通过 CaptureSession 的 Event 请求停止，不直接关闭句柄。
    pcap_next_ex 返回的借用指针在下一次读取前复制成 bytes。
    """

    def __init__(self, interface: str, *, bpf: str = "", snaplen: int = 65535,
                 promiscuous: bool = False) -> None:
        if not interface or "\0" in interface:
            raise ValueError("网卡名称不能为空或包含 NUL。")
        if not 64 <= snaplen <= 262144:
            raise ValueError("snaplen 必须在 64 到 262144 字节之间。")
        if "\0" in bpf:
            raise ValueError("过滤表达式不能包含 NUL 字符。")
        self._lib = get_libpcap().lib
        self._owner = threading.get_ident()
        self._handle = None
        error = C.create_string_buffer(256)
        handle = self._lib.pcap_create(interface.encode(), error)
        if not handle:
            raise PcapError(f"创建抓包句柄失败：{decode(error.value)}")
        self._handle = handle
        try:
            for name, value in (
                ("pcap_set_snaplen", snaplen),
                ("pcap_set_promisc", int(promiscuous)),
                ("pcap_set_timeout", 100),
                ("pcap_set_buffer_size", 2 * 1024 * 1024),
                ("pcap_set_immediate_mode", 1),
            ):
                result = getattr(self._lib, name)(handle, value)
                if result < 0:
                    raise PcapError(f"{name} 失败：{decode(self._lib.pcap_statustostr(result))}")
            result = self._lib.pcap_activate(handle)
            if result < 0:
                detail = decode(self._lib.pcap_geterr(handle))
                if result in (-8, -11):
                    detail += "；请检查 /dev/bpf* 的读写权限，程序不会自动修改系统权限。"
                raise PcapError(f"无法在 {interface} 上抓包：{detail}")
            warnings = (decode(self._lib.pcap_statustostr(result)),) if result > 0 else ()
            if bpf.strip():
                _apply_filter(self._lib, handle, bpf)
            if self._lib.pcap_setnonblock(handle, 1, error) < 0:
                raise PcapError(f"设置非阻塞模式失败：{decode(error.value)}")
            linktype = self._lib.pcap_datalink(handle)
            if linktype < 0:
                raise PcapError(f"获取链路类型失败：{decode(self._lib.pcap_geterr(handle))}")
            self.info = CaptureInfo(
                interface, linktype,
                decode(self._lib.pcap_datalink_val_to_name(linktype)) or str(linktype),
                self._lib.pcap_snapshot(handle), warnings,
            )
            self.selectable_fd = self._lib.pcap_get_selectable_fd(handle)
        except BaseException:
            self.close()
            raise

    def _check_owner(self) -> int:
        if threading.get_ident() != self._owner:
            raise RuntimeError("抓包句柄只能由创建它的线程操作。")
        if self._handle is None:
            raise PcapError("抓包句柄已经关闭。")
        return self._handle

    def read_packet(self) -> RawPacket | None:
        handle = self._check_owner()
        header = C.POINTER(PacketHeader)()
        data = C.POINTER(C.c_ubyte)()
        result = self._lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
        if result == 0:
            return None
        if result != 1:
            raise PcapError(f"读取数据包失败（{result}）：{decode(self._lib.pcap_geterr(handle))}")
        if not header:
            raise PcapError("libpcap 返回了空的数据包头指针。")
        value = header.contents
        if value.caplen > self.info.snapshot_length or value.caplen > value.len:
            raise PcapError("libpcap 返回了非法的数据包长度。")
        if not data and value.caplen:
            raise PcapError("libpcap 返回了空的数据指针。")
        return RawPacket(
            value.ts.tv_sec, value.ts.tv_usec, value.len, self.info.linktype,
            C.string_at(data, value.caplen) if value.caplen else b"",
        )

    def statistics(self) -> KernelStats | None:
        handle = self._check_owner()
        stats = PcapStats()
        if self._lib.pcap_stats(handle, C.byref(stats)) < 0:
            return None
        return KernelStats(stats.ps_recv, stats.ps_drop, stats.ps_ifdrop)

    def close(self) -> None:
        if self._handle is not None:
            self._check_owner()
            self._lib.pcap_close(self._handle)
            self._handle = None

    def __enter__(self):
        self._check_owner()
        return self

    def __exit__(self, *_):
        self.close()


def write_pcap(path: str | Path, packets: Iterable[RawPacket], info: CaptureInfo) -> None:
    """用于阶段验收的经典 PCAP 写入，成功后原子替换目标文件。

    由 libpcap 处理 DLT 到 PCAP LINKTYPE 的映射（例如 RAW），不能直接
    把运行平台的 DLT 数值写到 PCAP 全局头中。GUI 文件操作将在阶段 4 接入。
    """
    lib = get_libpcap().lib
    handle = lib.pcap_open_dead(info.linktype, info.snapshot_length)
    if not handle:
        raise PcapError("无法创建 PCAP 写入句柄。")
    target = Path(path)
    temporary = None
    dumper = None
    try:
        # 同目录临时文件，写入错误时保留原文件。
        with tempfile.NamedTemporaryFile(prefix=f".{target.name}.", dir=target.parent, delete=False) as file:
            temporary = Path(file.name)
        dumper = lib.pcap_dump_open(handle, os.fsencode(temporary))
        if not dumper:
            raise PcapError(f"打开 PCAP 文件失败：{decode(lib.pcap_geterr(handle))}")
        for packet in packets:
            if packet.linktype != info.linktype:
                raise ValueError("经典 PCAP 不能混合不同链路类型的数据包。")
            if (not 0 <= packet.microseconds < 1_000_000
                    or not 0 <= packet.seconds <= 0xFFFFFFFF
                    or not packet.captured_length <= packet.wire_length <= 0xFFFFFFFF
                    or packet.captured_length > info.snapshot_length):
                raise ValueError("数据包时间戳或长度不合法，不能写入 PCAP。")
            header = PacketHeader(Timeval(packet.seconds, packet.microseconds),
                                  packet.captured_length, packet.wire_length)
            data = (C.c_ubyte * packet.captured_length).from_buffer_copy(packet.data)
            lib.pcap_dump(dumper, C.byref(header), data)
        if lib.pcap_dump_flush(dumper) != 0:
            raise PcapError("写入 PCAP 失败，请检查剩余磁盘空间。")
        lib.pcap_dump_close(dumper)
        dumper = None
        os.replace(temporary, target)
    finally:
        if dumper:
            lib.pcap_dump_close(dumper)
        lib.pcap_close(handle)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
