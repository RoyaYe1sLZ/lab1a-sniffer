"""网卡、抓包句柄和 PCAP 写入的安全封装，不负责 GUI 或协议解析。"""

from collections.abc import Iterable
import ctypes as C
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading

from ._ffi import (
    BpfProgram, PacketHeader, PcapError, PcapInterface, PcapStats, Timeval,
    decode, get_libpcap,
)
from .models import CaptureInfo, Interface, KernelStats, RawPacket

__all__ = ["PcapError", "LiveCapture", "OfflineCapture", "list_interfaces", "write_pcap"]


class FileCancelled(RuntimeError):
    """文件操作被取消，已有文件和列表应保持原样。"""


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


class OfflineCapture:
    """微秒精度经典 PCAP 2.4 读取；原生句柄仅由创建线程操作。

    先独立核对记录长度，再交给 libpcap，避免 libpcap 容错截短损坏记录。
    libpcap 负责 LINKTYPE/DLT 映射；NULL 伪头根据文件字节序规范化。
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._owner = threading.get_ident()
        self._handle = None
        self._file = None
        self._lib = get_libpcap().lib
        if not stat.S_ISREG(self.path.stat().st_mode):
            raise PcapError("请选择普通 PCAP 文件。")
        try:
            self._file = self.path.open("rb")
            self._original_stat = os.fstat(self._file.fileno())
            header = self._file.read(24)
            magic = header[:4]
            if magic == b"\x0a\x0d\x0d\x0a":
                raise PcapError("本版仅支持经典 .pcap，暂不支持 PCAPNG。")
            if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                raise PcapError("本版仅支持微秒精度 PCAP，不能无损读取纳秒精度文件。")
            self._order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(magic)
            if self._order is None or len(header) != 24:
                raise PcapError("不是有效的经典 PCAP 文件，或文件头已截断。")
            _, major, minor, _, _, snaplen, network = struct.unpack(self._order + "IHHIIII", header)
            if (major, minor) != (2, 4):
                raise PcapError("当前仅支持 PCAP 2.4 文件。")
            if not 1 <= snaplen <= 262144:
                raise PcapError("PCAP snaplen 必须在 1 到 262144 字节之间。")
            if network >> 16:
                raise PcapError("暂不支持带额外全局链路标志的 PCAP 文件。")
            error = C.create_string_buffer(256)
            self._handle = self._lib.pcap_open_offline(os.fsencode(self.path), error)
            if not self._handle:
                raise PcapError(f"打开 PCAP 失败：{decode(error.value)}")
            kind = self._lib.pcap_datalink(self._handle)
            if kind < 0:
                raise PcapError("无法获取 PCAP 链路类型。")
            self.info = CaptureInfo(str(self.path), kind,
                decode(self._lib.pcap_datalink_val_to_name(kind)) or str(kind), snaplen)
        except BaseException:
            self.close()
            raise

    def _check(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError("离线句柄只能由创建它的线程操作。")
        if self._handle is None or self._file is None:
            raise PcapError("PCAP 文件已经关闭。")

    def read_packet(self) -> RawPacket | None:
        self._check()
        record = self._file.read(16)
        if not record:
            current = self.path.stat()
            before = self._original_stat
            if (current.st_ino, current.st_size, current.st_mtime_ns) != (before.st_ino, before.st_size, before.st_mtime_ns):
                raise PcapError("文件在读取过程中被修改，请重试。")
            return None
        if len(record) != 16:
            raise PcapError("PCAP 记录头被截断。")
        seconds, usec, caplen, wirelen = struct.unpack(self._order + "IIII", record)
        if not usec < 1_000_000 or caplen > self.info.snapshot_length or caplen > wirelen:
            raise PcapError("PCAP 记录中的时间戳或长度不合法。")
        if self._file.tell() + caplen > self._original_stat.st_size:
            raise PcapError("PCAP 数据包内容被截断。")
        prefix = self._file.read(min(caplen, 4))
        self._file.seek(caplen - len(prefix), os.SEEK_CUR)
        header = C.POINTER(PacketHeader)()
        data = C.POINTER(C.c_ubyte)()
        result = self._lib.pcap_next_ex(self._handle, C.byref(header), C.byref(data))
        if result != 1:
            raise PcapError(f"读取 PCAP 失败：{decode(self._lib.pcap_geterr(self._handle)) or result}")
        if not header or not data and caplen:
            raise PcapError("libpcap 返回了无效的数据包指针。")
        value = header.contents
        if (value.caplen, value.len, value.ts.tv_usec) != (caplen, wirelen, usec) or (value.ts.tv_sec & 0xFFFFFFFF) != seconds:
            raise PcapError("PCAP 记录与 libpcap 读取结果不一致。")
        copied = C.string_at(data, caplen) if caplen else b""
        if self.info.linktype == 0 and caplen >= 4:
            # Darwin 自带 libpcap 不一定转换 DLT_NULL 的地址族字段。
            # 伪头不是线上 IP 内容；统一为本机字节序，确保导出后的文件仍可读。
            family = int.from_bytes(prefix, "little" if self._order == "<" else "big")
            copied = family.to_bytes(4, sys.byteorder) + copied[4:]
        return RawPacket(seconds, usec, wirelen, self.info.linktype, copied)

    def close(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError("离线句柄只能由创建它的线程关闭。")
        if self._handle is not None:
            self._lib.pcap_close(self._handle)
            self._handle = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()


def write_pcap(path: str | Path, packets: Iterable[RawPacket], info: CaptureInfo,
               *, cancelled=lambda: False) -> None:
    """经典 PCAP 写入，成功后原子替换目标文件。

    由 libpcap 处理 DLT 到 PCAP LINKTYPE 的映射（例如 RAW），不能直接
    把运行平台的 DLT 数值写到 PCAP 全局头中。
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
            if cancelled():
                raise FileCancelled("已取消保存。")
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
        if cancelled():
            raise FileCancelled("已取消保存。")
        os.replace(temporary, target)
    finally:
        if dumper:
            lib.pcap_dump_close(dumper)
        lib.pcap_close(handle)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
