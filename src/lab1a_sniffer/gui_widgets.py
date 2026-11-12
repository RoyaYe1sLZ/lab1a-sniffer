"""可复用的轻量界面组件：协议按钮组、开关、矢量图标和表格绘制。"""
from PySide6.QtCore import Qt, Signal, QSize, QRectF, QPointF
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QHBoxLayout,
                              QPushButton, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QWidget)


def line_icon(kind, color="#526f7b"):
    pixmap = QPixmap(40, 40)
    pixmap.fill(Qt.GlobalColor.transparent)
    pixmap.setDevicePixelRatio(2)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(color), 1.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    path = QPainterPath()
    if kind == "open":
        path.moveTo(2, 6); path.lineTo(2, 16); path.lineTo(17, 16); path.lineTo(18, 7)
        path.lineTo(9, 7); path.lineTo(7, 4); path.lineTo(2, 4); path.lineTo(2, 6)
        path.lineTo(16, 6)
    elif kind == "save":
        path.moveTo(10, 2); path.lineTo(10, 12); path.moveTo(6, 8); path.lineTo(10, 12); path.lineTo(14, 8)
        path.moveTo(3, 13); path.lineTo(3, 17); path.lineTo(17, 17); path.lineTo(17, 13)
    elif kind == "refresh":
        path.arcMoveTo(QRectF(4, 4, 12, 12), 45); path.arcTo(QRectF(4, 4, 12, 12), 45, 290)
        path.moveTo(13, 2); path.lineTo(17, 5); path.lineTo(13, 7)
    elif kind == "trace":
        path.moveTo(3, 16); path.lineTo(16, 3); path.moveTo(7, 3); path.lineTo(16, 3); path.lineTo(16, 12)
    painter.drawPath(path)
    painter.end()
    return QIcon(pixmap)


class NetworkMark(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(28, 28)
        self.setAccessibleName("网络嗅探器")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#16888a"), 1.7))
        points = (QPointF(14, 5), QPointF(4, 23), QPointF(24, 23))
        for a, b in ((0, 1), (1, 2), (2, 0)):
            painter.drawLine(points[a], points[b])
        painter.setBrush(QColor("#16888a"))
        for p in points:
            painter.drawEllipse(p, 3, 3)


class ChoiceBox(QComboBox):
    """保留标准下拉框行为，用矢量箭头适配高分辨率屏幕。"""
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#718692" if self.isEnabled() else "#b5c0c8"), 1.5,
                            Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        x, y = self.width() - 14, self.height() / 2
        path = QPainterPath()
        path.moveTo(x - 3, y - 1)
        path.lineTo(x, y + 2)
        path.lineTo(x + 3, y - 1)
        painter.drawPath(path)


class ProtocolSelector(QWidget):
    currentTextChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("protocolSelector")
        self.setAccessibleName("协议显示过滤")
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._names = []
        self._current = ""
        self.buttons = {}
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(5)
        self.group.buttonClicked.connect(lambda button: self.setCurrentText(button.text()))

    def addItems(self, names):
        for name in names:
            if name in self.buttons:
                continue
            button = QPushButton(name)
            button.setObjectName("protocolChip")
            button.setCheckable(True)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setAccessibleName(f"显示 {name} 协议")
            button.setToolTip(f"只显示包含 {name} 层的包" if name != "全部" else "显示全部协议")
            self.group.addButton(button)
            self._layout.addWidget(button)
            self._names.append(name)
            self.buttons[name] = button
        if not self._current and self._names:
            self.setCurrentText(self._names[0])

    def currentText(self):
        return self._current

    def findText(self, text):
        return self._names.index(text) if text in self._names else -1

    def setCurrentText(self, text):
        if text not in self.buttons:
            return
        self.buttons[text].setChecked(True)
        if text != self._current:
            self._current = text
            self.currentTextChanged.emit(text)

    def keyPressEvent(self, event):
        pos = self.findText(self._current)
        if event.key() == Qt.Key.Key_Home:
            pos = 0
        elif event.key() == Qt.Key.Key_End:
            pos = len(self._names) - 1
        elif event.key() in (Qt.Key.Key_Right, Qt.Key.Key_Down):
            pos = min(pos + 1, len(self._names) - 1)
        elif event.key() in (Qt.Key.Key_Left, Qt.Key.Key_Up):
            pos = max(0, pos - 1)
        else:
            return super().keyPressEvent(event)
        if self._names:
            self.setCurrentText(self._names[pos])
        event.accept()


class ToggleSwitch(QCheckBox):
    def sizeHint(self):
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 51, 26)

    def hitButton(self, pos):
        return self.rect().contains(pos)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(self.font())
        painter.setPen(QColor("#6e8290" if self.isEnabled() else "#a9b4bd"))
        painter.drawText(self.rect().adjusted(0, 0, -46, 0), Qt.AlignmentFlag.AlignVCenter, self.text())
        track = QRectF(self.width() - 36, (self.height() - 18) / 2, 34, 18)
        painter.setPen(Qt.PenStyle.NoPen)
        track_color = ("#16888a" if self.isEnabled() else "#b6cfca") if self.isChecked() else "#c7d3dc"
        painter.setBrush(QColor(track_color))
        painter.drawRoundedRect(track, 9, 9)
        painter.setBrush(QColor("white"))
        painter.drawEllipse(QRectF(track.x() + (18 if self.isChecked() else 2), track.y() + 2, 14, 14))
        if self.hasFocus():
            painter.setPen(QPen(QColor("#16888a"), 1, Qt.PenStyle.DotLine))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(self.rect().adjusted(0, 1, -1, -1), 5, 5)


class PacketDelegate(QStyledItemDelegate):
    PALETTE = {"TCP": ("#e8f0fc", "#35699d"), "UDP": ("#f3edfb", "#8054a7"),
               "HTTP": ("#def3ed", "#127c72"), "ICMP": ("#fff2d7", "#a47926"),
               "ICMPv6": ("#fff2d7", "#a47926")}

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() in (0, 1, 2, 3, 5):
            option.font = QFont("Menlo", 10)

    def paint(self, painter, option, index):
        if index.column() != 4:
            super().paint(painter, option, index)
            if index.column() == 0 and option.state & QStyle.StateFlag.State_Selected:
                painter.fillRect(option.rect.x(), option.rect.y() + 3, 3, option.rect.height() - 6, QColor("#16888a"))
            return
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        name = opt.text
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        background, foreground = self.PALETTE.get(name, ("#edf1f4", "#647c8a"))
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont("PingFang SC", 10)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        width = min(opt.rect.width() - 10, painter.fontMetrics().horizontalAdvance(name) + 16)
        badge = QRectF(opt.rect.x() + 6, opt.rect.center().y() - 9, width, 19)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(background))
        painter.drawRoundedRect(badge, 4, 4)
        painter.setPen(QColor(foreground))
        painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, name)
        painter.restore()
