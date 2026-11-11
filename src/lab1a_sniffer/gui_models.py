"""数据包表格与缓存限额；仅在 Qt 主线程更新。"""

from dataclasses import fields, is_dataclass
from datetime import datetime
import sys

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from .models import ParsedPacket


def packet_memory_cost(packet: ParsedPacket) -> int:
    """计算本包 Python 对象占用；跨包共享对象重复计费，作为保守缓存预算。

    除原始字节外也计算字段、字符串及容器，避免只限制原始字节而忽略解析对象。
    此值不是整个进程的 RSS，也不包含 Qt 渲染开销。
    """
    seen = set()

    def size(value):
        if id(value) in seen:
            return 0
        seen.add(id(value))
        result = sys.getsizeof(value)
        if is_dataclass(value) and not isinstance(value, type):
            result += sum(size(getattr(value, field.name)) for field in fields(value))
        elif isinstance(value, (tuple, list, frozenset)):
            result += sum(size(item) for item in value)
        return result

    return size(packet)


class PacketTableModel(QAbstractTableModel):
    HEADERS = ("序号", "时间", "源地址", "目的地址", "协议", "长度", "摘要")
    COLORS = {"HTTP": "#087e8b", "TCP": "#2563a6", "UDP": "#7755aa",
              "ICMP": "#a36c15", "ICMPv6": "#a36c15"}

    def __init__(self, parent=None, *, max_packets=20000, max_memory=128 * 1024 * 1024):
        super().__init__(parent)
        if max_packets < 1 or max_memory < 1:
            raise ValueError("缓存限额必须大于零。")
        self.packets: list[ParsedPacket] = []
        self.max_packets = max_packets
        self.max_memory = max_memory
        self.raw_bytes = 0
        self.memory_cost = 0
        self.limit_message = ""
        self.rejected_count = 0

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.packets)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return super().headerData(section, orientation, role)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.packets):
            return None
        packet, column = self.packets[index.row()], index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return str(index.row() + 1)
            if column == 1:
                return datetime.fromtimestamp(packet.raw.seconds).strftime("%H:%M:%S") + f".{packet.raw.microseconds:06d}"
            return {2: packet.source or "—", 3: packet.destination or "—", 4: packet.protocol,
                    5: str(packet.raw.wire_length), 6: packet.summary[:512]}.get(column)
        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            return QColor(self.COLORS.get(packet.protocol, "#536478"))
        if role == Qt.ItemDataRole.ToolTipRole:
            if column in (2, 3):
                return packet.source if column == 2 else packet.destination
            text = packet.summary[:2048]
            if packet.issues:
                text += "\n" + "\n".join(issue.message for issue in packet.issues)
            return text
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignVCenter | (
                Qt.AlignmentFlag.AlignRight if column in (0, 5) else Qt.AlignmentFlag.AlignLeft)
        return None

    def append_packets(self, packets: list[ParsedPacket]) -> int:
        accepted = []
        for packet in packets:
            if self.limit_message:
                self.rejected_count += 1
                continue
            cost = packet_memory_cost(packet)
            if len(self.packets) + len(accepted) >= self.max_packets:
                self.limit_message = f"达到 {self.max_packets:,} 个包的缓存上限，已停止抓包。"
            elif self.memory_cost + cost > self.max_memory:
                self.limit_message = f"达到 {self.max_memory // (1024 * 1024)} MiB 的解析缓存预算，已停止抓包。"
            if self.limit_message:
                self.rejected_count += 1
                continue
            accepted.append(packet)
            self.memory_cost += cost
            self.raw_bytes += packet.raw.captured_length
        if accepted:
            start = len(self.packets)
            self.beginInsertRows(QModelIndex(), start, start + len(accepted) - 1)
            self.packets.extend(accepted)
            self.endInsertRows()
        return len(accepted)

    def clear(self):
        self.beginResetModel()
        self.packets.clear()
        self.raw_bytes = self.memory_cost = self.rejected_count = 0
        self.limit_message = ""
        self.endResetModel()
