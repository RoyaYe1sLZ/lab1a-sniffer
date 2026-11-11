"""数据包表格与缓存限额；仅在 Qt 主线程更新。"""

from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from .models import ParsedPacket
from .storage import LoadedCapture, packet_memory_cost


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

    def replace_capture(self, capture: LoadedCapture):
        if len(capture.packets) > self.max_packets or capture.memory_cost > self.max_memory:
            raise ValueError("导入结果超过模型缓存预算。")
        self.beginResetModel()
        self.packets = list(capture.packets)
        self.memory_cost = capture.memory_cost
        self.raw_bytes = capture.raw_bytes
        self.limit_message = ""
        self.rejected_count = 0
        self.endResetModel()


class ProtocolFilterModel(QSortFilterProxyModel):
    PROTOCOLS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.protocol = "全部"
        self.setDynamicSortFilter(True)

    def set_protocol(self, protocol: str):
        if protocol not in self.PROTOCOLS:
            raise ValueError("未知的协议显示过滤条件。")
        self.beginFilterChange()
        self.protocol = protocol
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        return model is not None and 0 <= source_row < len(model.packets) and model.packets[source_row].matches_protocol(self.protocol)
