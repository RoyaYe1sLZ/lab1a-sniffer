"""libpcap 的 C ABI 声明；只在此文件维护指针和原生结构体。

参考 libpcap 1.10.1 的 pcap/pcap.h 与 Apple XNU 的 timeval 定义。
64 位 macOS 的秒字段为 long，微秒为 int32，随后有自然对齐填充。
不能把 Linux 的两个 long 布局照搬到 macOS，也不能使用 packed 结构体。
"""

import ctypes as C
from ctypes.util import find_library
from functools import lru_cache
import sys


class PcapError(RuntimeError):
    """libpcap 操作失败，消息适合直接显示给用户。"""


class Timeval(C.Structure):
    _fields_ = [("tv_sec", C.c_long), ("tv_usec", C.c_int32)]


class PacketHeader(C.Structure):
    _fields_ = [("ts", Timeval), ("caplen", C.c_uint32), ("len", C.c_uint32)]


class PcapInterface(C.Structure):
    pass


PcapInterface._fields_ = [
    ("next", C.POINTER(PcapInterface)),
    ("name", C.c_char_p),
    ("description", C.c_char_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint),
]


class BpfProgram(C.Structure):
    _fields_ = [("bf_len", C.c_uint), ("bf_insns", C.c_void_p)]


class PcapStats(C.Structure):
    _fields_ = [
        ("ps_recv", C.c_uint), ("ps_drop", C.c_uint), ("ps_ifdrop", C.c_uint)
    ]


def decode(value: bytes | None) -> str:
    return (value or b"").decode("utf-8", errors="replace")


class Libpcap:
    def __init__(self) -> None:
        if sys.platform != "darwin" or C.sizeof(C.c_void_p) != 8:
            raise PcapError("当前版本仅支持 64 位 macOS。")
        path = find_library("pcap")
        if not path:
            raise PcapError("未找到系统 libpcap。")
        try:
            self.lib = C.CDLL(path)
        except OSError as exc:
            raise PcapError(f"无法加载 libpcap：{exc}") from exc
        self.path = path
        ptr = C.c_void_p
        char = C.c_char_p
        integer = C.c_int
        pp_header = C.POINTER(C.POINTER(PacketHeader))
        pp_data = C.POINTER(C.POINTER(C.c_ubyte))
        self._bind("pcap_lib_version", [], char)
        self._bind("pcap_findalldevs", [C.POINTER(C.POINTER(PcapInterface)), char], integer)
        self._bind("pcap_freealldevs", [C.POINTER(PcapInterface)], None)
        self._bind("pcap_create", [char, char], ptr)
        for name in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout",
                     "pcap_set_buffer_size", "pcap_set_immediate_mode"):
            self._bind(name, [ptr, integer], integer)
        self._bind("pcap_activate", [ptr], integer)
        self._bind("pcap_statustostr", [integer], char)
        self._bind("pcap_geterr", [ptr], char)
        self._bind("pcap_setnonblock", [ptr, integer, char], integer)
        self._bind("pcap_get_selectable_fd", [ptr], integer)
        self._bind("pcap_next_ex", [ptr, pp_header, pp_data], integer)
        self._bind("pcap_stats", [ptr, C.POINTER(PcapStats)], integer)
        self._bind("pcap_datalink", [ptr], integer)
        self._bind("pcap_datalink_val_to_name", [integer], char)
        self._bind("pcap_snapshot", [ptr], integer)
        self._bind("pcap_close", [ptr], None)
        self._bind("pcap_compile", [ptr, C.POINTER(BpfProgram), char, integer, C.c_uint32], integer)
        self._bind("pcap_setfilter", [ptr, C.POINTER(BpfProgram)], integer)
        self._bind("pcap_freecode", [C.POINTER(BpfProgram)], None)
        self._bind("pcap_open_dead", [integer, integer], ptr)
        self._bind("pcap_open_offline", [char, char], ptr)
        self._bind("pcap_dump_open", [ptr, char], ptr)
        self._bind("pcap_dump", [ptr, C.POINTER(PacketHeader), C.POINTER(C.c_ubyte)], None)
        self._bind("pcap_dump_flush", [ptr], integer)
        self._bind("pcap_dump_close", [ptr], None)

    def _bind(self, name: str, arguments: list, result: object) -> None:
        function = getattr(self.lib, name)
        function.argtypes = arguments
        function.restype = result

    @property
    def version(self) -> str:
        return decode(self.lib.pcap_lib_version())


@lru_cache(maxsize=1)
def get_libpcap() -> Libpcap:
    return Libpcap()
