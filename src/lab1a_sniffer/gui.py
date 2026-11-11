"""实验 1A 的 Qt Widgets 界面：抓包、显示过滤与 PCAP 文件浏览。"""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QSizePolicy, QSplitter, QStackedWidget, QTableView, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from .capture import CaptureConfig, CaptureStatus
from .gui_controller import CaptureController
from .gui_files import FileController
from .gui_models import PacketTableModel, ProtocolFilterModel
from .parser import hex_dump
from .pcap import list_interfaces


STYLE = """
QMainWindow, QWidget#root { background: #f1f4f8; color: #20334c; }
QWidget { font-family: 'PingFang SC'; font-size: 12px; color: #20334c; }
QFrame#hero { background: #152940; border-radius: 10px; }
QLabel#eyebrow { color: #a7b9cf; font-size: 11px; }
QLabel#title { color: #ffffff; font-size: 23px; font-weight: 600; }
QLabel#subtitle { color: #b9c8da; }
QLabel#stateBadge { border-radius: 6px; padding: 7px 14px; font-weight: 600; }
QFrame#controls, QFrame#panel { background: #ffffff; border: 1px solid #dce3ed; border-radius: 8px; }
QLabel#formLabel { color: #65758b; font-size: 11px; }
QLabel#panelTitle { font-size: 13px; font-weight: 600; }
QLabel#muted { color: #7a899c; font-size: 11px; }
QLabel#packetCount { color: #52708f; background: #edf3f9; border-radius: 4px; padding: 3px 9px; }
QLabel#emptyTitle { color: #3c536f; font-size: 17px; font-weight: 600; }
QLabel#emptyHint { color: #7b8b9e; font-size: 12px; }
QLabel#banner { background: #fff4df; color: #825817; border: 1px solid #f0dbb4;
                border-radius: 6px; padding: 9px 12px; }
QComboBox, QLineEdit { background: #ffffff; border: 1px solid #cfdae7; border-radius: 5px;
                       padding: 7px 9px; selection-background-color: #d7e9fa; }
QComboBox:focus, QLineEdit:focus { border: 1px solid #4688bd; }
QPushButton { background: #f8fafc; border: 1px solid #cfdae7; border-radius: 5px;
              padding: 8px 13px; font-weight: 500; }
QPushButton:hover { background: #eef4fa; border-color: #99b3cf; }
QPushButton:pressed { background: #e0ebf6; }
QPushButton#start { background: #197b83; color: white; border-color: #197b83; }
QPushButton#start:hover { background: #126970; }
QPushButton:disabled { background: #f0f3f6; color: #a8b3c1; border-color: #e0e6ee; }
QPushButton#start:disabled { background: #dbe9ea; color: #93adaf; border-color: #dbe9ea; }
QTableView { border: none; background: white; alternate-background-color: #f7f9fc;
             selection-background-color: #deedf8; selection-color: #163a5a; gridline-color: #edf1f6; }
QHeaderView::section { background: #f4f7fb; color: #65758b; border: none;
                       border-bottom: 1px solid #e1e8f0; padding: 8px 9px; font-size: 11px; }
QTreeWidget { background: white; border: none; selection-background-color: #deedf8;
              selection-color: #163a5a; outline: 0; }
QTreeWidget::item { padding: 3px 1px; }
QPlainTextEdit#hexView { background: #17283d; color: #d9e4f0; border: none; border-radius: 5px;
                        font-family: 'Menlo'; font-size: 11px; selection-background-color: #335d82; }
QSplitter::handle { background: #f1f4f8; }
QCheckBox { color: #65758b; spacing: 6px; }
QScrollBar:vertical { width: 11px; background: #f4f7fa; }
QScrollBar::handle:vertical { background: #c5d1df; border-radius: 4px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


def label(text="", name="", parent=None):
    widget = QLabel(text, parent)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if name:
        widget.setObjectName(name)
    return widget


def byte_size(value):
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"


class SnifferWindow(QMainWindow):
    def __init__(self, *, controller=None, interfaces_provider=list_interfaces,
                 max_packets=20000, max_memory=128 * 1024 * 1024):
        super().__init__()
        self.setObjectName("SnifferWindow")
        self.setWindowTitle("网络嗅探器 · 实验 1A")
        self.setMinimumSize(980, 660)
        geometry = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1320, int(geometry.width() * .92)), min(860, int(geometry.height() * .9)))
        self.controller = controller or CaptureController(self)
        self.files = FileController(self)
        self.model = PacketTableModel(self, max_packets=max_packets, max_memory=max_memory)
        self.proxy = ProtocolFilterModel(self)
        self.proxy.setSourceModel(self.model)
        self._interfaces_provider = interfaces_provider
        self.capture_info = None
        self.source_path = None
        self.source_kind = ""
        self.dirty = False
        self.current_packet = None
        self._hex_limit = 4096
        self._closing = False
        self._last_status = CaptureStatus()
        self._build()
        self.controller.sessionStarted.connect(self._session_started)
        self.controller.batchReady.connect(self._append_packets)
        self.controller.statusChanged.connect(self._update_status)
        self.controller.problem.connect(self._problem)
        self.controller.stateChanged.connect(self._state_changed)
        self.files.stateChanged.connect(self._file_state_changed)
        self.files.completed.connect(self._file_completed)
        self.files.problem.connect(self._problem)
        self.refresh_interfaces()
        self._state_changed("idle")
        self._update_status(self._last_status)

    def _build(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 16, 18, 12)
        outer.setSpacing(12)

        hero = QFrame()
        hero.setObjectName("hero")
        header = QHBoxLayout(hero)
        header.setContentsMargins(21, 14, 21, 14)
        titles = QVBoxLayout()
        titles.setSpacing(3)
        titles.addWidget(label("软件与系统安全 / 实验 1A", "eyebrow"))
        titles.addWidget(label("网络嗅探器", "title"))
        header.addLayout(titles)
        header.addStretch()
        self.badge = label("● 就绪", "stateBadge")
        header.addWidget(self.badge)
        outer.addWidget(hero)

        controls = QFrame()
        controls.setObjectName("controls")
        bar = QHBoxLayout(controls)
        bar.setContentsMargins(16, 12, 16, 12)
        bar.setSpacing(12)
        nic = QVBoxLayout()
        nic.setSpacing(5)
        nic.addWidget(label("网络接口", "formLabel"))
        nic_row = QHBoxLayout()
        self.interfaces = QComboBox()
        self.interfaces.setObjectName("interfaceCombo")
        self.interfaces.setMinimumWidth(170)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.setObjectName("refreshButton")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        nic_row.addWidget(self.interfaces)
        nic_row.addWidget(self.refresh_button)
        nic.addLayout(nic_row)
        bar.addLayout(nic)
        filters = QVBoxLayout()
        filters.setSpacing(5)
        filters.addWidget(label("抓包过滤 · BPF", "formLabel"))
        self.bpf = QLineEdit()
        self.bpf.setObjectName("bpfEdit")
        self.bpf.setPlaceholderText("例如 tcp or udp，留空捕获全部")
        self.bpf.setClearButtonEnabled(True)
        self.bpf.setMinimumWidth(230)
        self.bpf.returnPressed.connect(self.start_capture)
        filters.addWidget(self.bpf)
        bar.addLayout(filters, 1)
        actions = QVBoxLayout()
        actions.addWidget(label("操作", "formLabel"))
        buttons = QHBoxLayout()
        self.start_button = QPushButton("▶  开始抓包")
        self.start_button.setObjectName("start")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("■  停止")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.clicked.connect(self.controller.stop)
        self.clear_button = QPushButton("清空")
        self.clear_button.setObjectName("clearButton")
        self.clear_button.clicked.connect(self.clear_packets)
        for button in (self.start_button, self.stop_button, self.clear_button):
            buttons.addWidget(button)
        actions.addLayout(buttons)
        bar.addLayout(actions)
        outer.addWidget(controls)

        self.banner = label("", "banner")
        self.banner.setWordWrap(True)
        self.banner.hide()
        outer.addWidget(self.banner)

        vertical = QSplitter(Qt.Orientation.Vertical)
        vertical.setHandleWidth(10)
        packet_panel, packet_layout = self._panel()
        packet_header = QHBoxLayout()
        packet_header.addWidget(label("数据包", "panelTitle"))
        self.count_label = label("0 个包", "packetCount")
        packet_header.addWidget(self.count_label)
        packet_header.addStretch()
        packet_header.addWidget(label("显示过滤", "formLabel"))
        self.display_filter = QComboBox()
        self.display_filter.setObjectName("displayFilter")
        self.display_filter.addItems(ProtocolFilterModel.PROTOCOLS)
        self.display_filter.setMinimumWidth(100)
        self.display_filter.setToolTip("仅改变显示；HTTP 包也匹配其 TCP 和 IP 层。")
        self.display_filter.currentTextChanged.connect(self._filter_changed)
        packet_header.addWidget(self.display_filter)
        self.open_button = QPushButton("打开 PCAP")
        self.open_button.setObjectName("openButton")
        self.open_button.clicked.connect(lambda: self.open_file())
        self.save_button = QPushButton("保存全部")
        self.save_button.setObjectName("saveButton")
        self.save_button.setToolTip("保存全部缓存包，不受显示过滤影响。")
        self.save_button.clicked.connect(lambda: self.save_file())
        packet_header.addWidget(self.open_button)
        packet_header.addWidget(self.save_button)
        self.auto_scroll = QCheckBox("自动滚动")
        self.auto_scroll.setChecked(True)
        self.auto_scroll.setToolTip("新包到达时滚动至底部；点击数据包可暂停自动滚动。")
        packet_header.addWidget(self.auto_scroll)
        packet_layout.addLayout(packet_header)
        self.source_label = label("尚未捕获或打开文件", "muted")
        self.source_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        packet_layout.addWidget(self.source_label)
        self.table = QTableView()
        self.table.setObjectName("packetTable")
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setMinimumSectionSize(48)
        for column, width in enumerate((56, 128, 180, 180, 80, 64)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(self._select_packet)
        self.table.clicked.connect(lambda _: self.auto_scroll.setChecked(False))
        self.empty = QWidget()
        empty_layout = QVBoxLayout(self.empty)
        empty_layout.addStretch()
        self.empty_title = label("准备捕获第一个数据包", "emptyTitle")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint = label("选择网络接口并点击开始抓包。\n回环流量请选择 lo0，常规网络访问请选择 en0。", "emptyHint")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_title)
        empty_layout.addWidget(self.empty_hint)
        empty_layout.addStretch()
        self.packet_stack = QStackedWidget()
        self.packet_stack.addWidget(self.table)
        self.packet_stack.addWidget(self.empty)
        self.packet_stack.setCurrentWidget(self.empty)
        packet_layout.addWidget(self.packet_stack, 1)
        packet_panel.setMinimumHeight(170)
        vertical.addWidget(packet_panel)

        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.setHandleWidth(10)
        details_panel, details_layout = self._panel()
        details_layout.addWidget(label("协议详情", "panelTitle"))
        self.packet_meta = label("选择一个数据包，查看封装层次与字段。", "muted")
        self.packet_meta.setWordWrap(True)
        details_layout.addWidget(self.packet_meta)
        self.tree = QTreeWidget()
        self.tree.setObjectName("protocolTree")
        self.tree.setHeaderLabels(["字段", "值"])
        self.tree.setColumnWidth(0, 190)
        self.tree.header().setStretchLastSection(True)
        self.tree.currentItemChanged.connect(self._select_field)
        details_layout.addWidget(self.tree, 1)
        lower.addWidget(details_panel)

        raw_panel, raw_layout = self._panel()
        raw_header = QHBoxLayout()
        raw_header.addWidget(label("原始字节", "panelTitle"))
        raw_header.addStretch()
        self.raw_meta = label("十六进制 / ASCII", "muted")
        raw_header.addWidget(self.raw_meta)
        self.full_bytes_button = QPushButton("显示全部")
        self.full_bytes_button.setObjectName("fullBytesButton")
        self.full_bytes_button.setEnabled(False)
        self.full_bytes_button.clicked.connect(self._show_all_bytes)
        raw_header.addWidget(self.full_bytes_button)
        raw_layout.addLayout(raw_header)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setObjectName("hexView")
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setFont(QFont("Menlo", 11))
        self.hex_view.document().setDocumentMargin(12)
        self.hex_view.setPlaceholderText("选中数据包后显示原始字节。")
        raw_layout.addWidget(self.hex_view, 1)
        lower.addWidget(raw_panel)
        lower.setSizes([480, 740])
        lower.setMinimumHeight(220)
        vertical.addWidget(lower)
        vertical.setSizes([340, 290])
        outer.addWidget(vertical, 1)

        footer = QHBoxLayout()
        self.link_label = label("接口 —  ·  链路 —", "muted")
        self.link_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.stats_label = label("", "muted")
        footer.addWidget(self.link_label, 1)
        footer.addStretch()
        footer.addWidget(self.stats_label)
        outer.addLayout(footer)
        menu = self.menuBar().addMenu("嗅探器")
        menu.addAction("退出", self.close, QKeySequence.StandardKey.Quit)

    def _panel(self):
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(13, 10, 13, 10)
        layout.setSpacing(8)
        return panel, layout

    def refresh_interfaces(self):
        if self.controller.is_active or self.files.is_active:
            return
        previous = self.interfaces.currentData()
        try:
            interfaces = self._interfaces_provider()
        except Exception as exc:
            self._problem(f"读取接口失败：{exc}")
            return
        self.interfaces.clear()
        for interface in interfaces:
            kind = "本地回环" if interface.is_loopback else "无线接口" if interface.flags & 8 else "网络接口"
            self.interfaces.addItem(f"{interface.name} · {kind}", interface.name)
        index = self.interfaces.findData(previous or "en0")
        if index >= 0:
            self.interfaces.setCurrentIndex(index)
        if not interfaces:
            self._problem("未发现可用网络接口，请检查系统网络配置。")
        self.start_button.setEnabled(bool(interfaces) and not self._closing)

    def _confirm_replace(self, message):
        if not self.model.rowCount() or not self.dirty:
            return True
        dialog = QMessageBox(self)
        dialog.setWindowTitle("替换当前数据")
        dialog.setText(message)
        dialog.setInformativeText(f"当前有 {self.model.rowCount():,} 个尚未保存的数据包。\n如需保留，请取消并点击“保存全部”。")
        accept = dialog.addButton("放弃并继续", QMessageBox.ButtonRole.AcceptRole)
        cancel = dialog.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(cancel)
        dialog.exec()
        return dialog.clickedButton() == accept

    def open_file(self, path=None):
        if self.controller.is_active or self.files.is_active or self._closing:
            return False
        if path is None:
            path, _ = QFileDialog.getOpenFileName(self, "打开经典 PCAP 文件", "",
                                                 "经典 PCAP (*.pcap *.cap);;所有文件 (*)")
        if not path or not self._confirm_replace("打开新文件将替换当前列表。是否继续？"):
            return False
        self.banner.hide()
        self._loading_path = Path(path).expanduser().resolve()
        return self.files.load(self._loading_path, max_packets=self.model.max_packets,
                               max_memory=self.model.max_memory)

    def save_file(self, path=None):
        if self.controller.is_active or self.files.is_active or self._closing or self.capture_info is None:
            return False
        if path is None:
            suggested = str(self.source_path or Path.cwd() / "capture.pcap")
            path, _ = QFileDialog.getSaveFileName(self, "保存全部缓存包", suggested, "经典 PCAP (*.pcap)")
        if not path:
            return False
        path = Path(path).expanduser().resolve()
        if not path.suffix:
            path = path.with_suffix(".pcap")
        elif path.suffix.lower() != ".pcap":
            self._problem("保存格式为经典 PCAP，请使用 .pcap 扩展名。")
            return False
        self.banner.hide()
        packets = tuple(packet.raw for packet in self.model.packets)
        return self.files.save(path, packets, self.capture_info)

    def _file_completed(self, operation, result):
        if operation == "loading":
            self._clear_details()
            self.model.replace_capture(result)
            self.capture_info = result.info
            self.source_path = self._loading_path
            self.source_kind = "file"
            self.controller.last_error = ""
            self._last_status = CaptureStatus(packets_read=len(result.packets), bytes_read=result.raw_bytes,
                                              stop_reason="离线文件")
            self.link_label.setText(f"文件 {self.source_path.name}  ·  链路 {result.info.linktype_name} ({result.info.linktype})")
            self.link_label.setToolTip(str(self.source_path))
            if self.proxy.rowCount():
                self.table.selectRow(0)
        else:
            self.source_path = Path(result)
            if self.source_kind == "file":
                self.link_label.setText(f"文件 {self.source_path.name}  ·  链路 {self.capture_info.linktype_name} ({self.capture_info.linktype})")
                self.link_label.setToolTip(str(self.source_path))
        self.dirty = False
        self.banner.hide()
        self._update_status(self._last_status)
        self._refresh_packet_view()

    def _file_state_changed(self, operation):
        closing = self._closing and operation == "idle"
        if closing:
            self._closing = False
        self._state_changed(self.controller.state)
        if closing:
            QTimer.singleShot(0, self.close)

    def _filter_changed(self, protocol):
        source = self.proxy.mapToSource(self.table.currentIndex())
        self.proxy.set_protocol(protocol)
        self.table.selectionModel().clearCurrentIndex()
        view = self.proxy.mapFromSource(source) if source.isValid() else QModelIndex()
        if view.isValid():
            self.table.selectRow(view.row())
        elif self.proxy.rowCount():
            self.table.selectRow(0)
        else:
            self._clear_details()
        self._refresh_packet_view()
        self._update_status(self._last_status)

    def _refresh_packet_view(self):
        visible, total = self.proxy.rowCount(), self.model.rowCount()
        self.packet_stack.setCurrentWidget(self.table if visible else self.empty)
        if total and not visible:
            title, hint = "没有符合显示过滤的数据包", f"全部 {total:,} 个包仍保留，可切换为“全部”查看。"
        elif self.files.is_active and self.files.operation == "loading":
            title, hint = "正在读取文件…", "读取成功后才替换当前列表。"
        elif self.source_kind == "file" and not total:
            title, hint = "文件中没有数据包", "这是一个有效的空 PCAP 文件。"
        elif self.controller.is_active:
            title, hint = "正在等待数据包…", "将显示符合抓包过滤和显示过滤条件的数据。"
        else:
            title, hint = "准备捕获第一个数据包", "选择网络接口开始抓包，或打开一个经典 PCAP 文件。"
        self.empty_title.setText(title)
        self.empty_hint.setText(hint)

    def start_capture(self):
        if self.controller.is_active or self.files.is_active or self._closing:
            return
        interface = self.interfaces.currentData()
        if not interface:
            self._problem("请先选择网络接口。")
            return
        if not self._confirm_replace("开始新抓包将替换当前列表。是否继续？"):
            return
        self.banner.hide()
        try:
            config = CaptureConfig(interface, bpf=self.bpf.text().strip())
        except ValueError as exc:
            self._problem(str(exc))
            return
        if not self.controller.start(config):
            self._state_changed("idle")

    def clear_packets(self):
        if self.controller.is_active or self.files.is_active or not self._confirm_replace("清空当前数据包列表？"):
            return
        self.model.clear()
        self.capture_info = None
        self.source_path = None
        self.source_kind = ""
        self.dirty = False
        self._clear_details()
        self._last_status = CaptureStatus()
        self.controller.last_error = ""
        self.banner.hide()
        self.packet_stack.setCurrentWidget(self.empty)
        self._state_changed("idle")
        self._update_status(self._last_status)
        self.link_label.setText("接口 —  ·  链路 —")

    def _session_started(self, info):
        self.model.clear()
        self.capture_info = info
        self.source_path = None
        self.source_kind = "live"
        self.dirty = False
        self._clear_details()
        self.packet_stack.setCurrentWidget(self.empty)
        self.link_label.setText(f"接口 {info.interface}  ·  链路 {info.linktype_name} ({info.linktype})")
        if info.warnings:
            self._problem("；".join(info.warnings))

    def _append_packets(self, packets):
        before = self.proxy.rowCount()
        added = self.model.append_packets(packets)
        if added:
            self.dirty = True
            self._refresh_packet_view()
            if before == 0 and self.proxy.rowCount():
                self.table.selectRow(0)
            if self.auto_scroll.isChecked() and self.proxy.rowCount():
                self.table.scrollToBottom()
        if self.model.limit_message and self.controller.state != "stopping":
            self._problem(self.model.limit_message)
            self.controller.stop()
        self._update_status(self._last_status)

    def _state_changed(self, state):
        active = state != "idle" or self.files.is_active
        for widget in (self.interfaces, self.refresh_button, self.bpf):
            widget.setEnabled(not active and not self._closing)
        self.start_button.setEnabled(not active and not self._closing and self.interfaces.count() > 0)
        self.stop_button.setEnabled(state in ("starting", "capturing") and not self._closing and not self.files.is_active)
        self.clear_button.setEnabled(not active and not self._closing and self.model.rowCount() > 0)
        self.open_button.setEnabled(not active and not self._closing)
        self.save_button.setEnabled(not active and not self._closing and self.capture_info is not None)
        text = {"idle": "离线浏览" if self.source_kind == "file" else "已停止" if self.capture_info else "就绪",
                "starting": "正在打开接口", "capturing": "正在抓包", "stopping": "正在停止"}[state]
        if self.files.is_active:
            text = "正在读取文件" if self.files.operation == "loading" else "正在保存文件"
        background, foreground = ("#d9f2eb", "#116851") if state == "capturing" else ("#e9eff6", "#3f5975")
        if self._closing:
            text = "正在安全关闭"
        elif self.controller.last_error and state == "idle" and not self.files.is_active:
            text = "抓包失败"
            background, foreground = "#fbe4de", "#a64432"
        self.badge.setText("● " + text)
        self.badge.setStyleSheet(f"background: {background}; color: {foreground};")
        self.empty_title.setText("正在等待数据包…" if active else "准备捕获第一个数据包")
        self.empty_hint.setText("接口已打开后，将显示符合抓包过滤条件的数据。" if active else
                                "选择网络接口并点击开始抓包。\n回环流量请选择 lo0，常规网络访问请选择 en0。")
        self._refresh_packet_view()
        if state == "idle" and self._closing and not self.files.is_active:
            QTimer.singleShot(0, self.close)
        elif state == "idle" and self._last_status.stop_reason.startswith("达到") and not self.banner.isVisible():
            self._problem(self._last_status.stop_reason + "，本轮抓包已停止。")

    def _update_status(self, status):
        self._last_status = status
        visible, total = self.proxy.rowCount(), self.model.rowCount()
        self.count_label.setText(f"显示 {visible:,} / 全部 {total:,}")
        dropped = str(status.kernel.dropped) if status.kernel is not None else "—"
        text = (f"已捕获 {status.packets_read:,}  ·  缓存 {byte_size(self.model.memory_cost)}"
                f"  ·  队列丢弃 {status.queue_dropped:,}  ·  内核丢包 {dropped}")
        if self.model.rejected_count:
            text += f"  ·  未入缓存 {self.model.rejected_count:,}"
        self.stats_label.setText(text)
        if status.kernel:
            self.stats_label.setToolTip(f"内核接收 {status.kernel.received}；接口丢包 {status.kernel.interface_dropped}（部分平台不支持）")
        if self.source_kind == "file":
            self.stats_label.setText(f"离线 {total:,} 个包  ·  缓存 {byte_size(self.model.memory_cost)}")
        origin = f"离线 · {self.source_path.name}" if self.source_kind == "file" and self.source_path else (
            f"实时 · {self.capture_info.interface}" if self.capture_info else "尚未捕获或打开文件")
        if self.capture_info:
            origin += " · 未保存" if self.dirty else " · 已保存" if self.source_path else ""
        self.source_label.setText(origin)
        self.source_label.setToolTip(str(self.source_path) if self.source_path else origin)
        self.setWindowTitle((self.source_path.name + " · " if self.source_path else "") + "网络嗅探器 · 实验 1A" + (" *" if self.dirty else ""))

    def _problem(self, message):
        self.banner.setText(message)
        self.banner.show()

    def _clear_details(self):
        self.current_packet = None
        self.tree.clear()
        self.hex_view.clear()
        self.hex_view.setExtraSelections([])
        self.full_bytes_button.setEnabled(False)
        self.raw_meta.setText("十六进制 / ASCII")
        self.packet_meta.setText("选择一个数据包，查看封装层次与字段。")

    def _select_packet(self, current, previous):
        source = self.proxy.mapToSource(current)
        if not source.isValid() or not 0 <= source.row() < self.model.rowCount():
            self._clear_details()
            return
        packet = self.model.packets[source.row()]
        self.current_packet = packet
        self.tree.clear()
        self._hex_limit = 4096
        self._render_hex()
        raw = packet.raw
        self.packet_meta.setText(f"第 {source.row() + 1} 包 · 已捕获 {raw.captured_length} / 线上 {raw.wire_length} 字节"
                                 + (f" · {len(packet.issues)} 条解析提示" if packet.issues else ""))
        frame = QTreeWidgetItem(self.tree, ["帧", f"{raw.captured_length} 字节"])
        timestamp = datetime.fromtimestamp(raw.seconds).strftime("%Y-%m-%d %H:%M:%S") + f".{raw.microseconds:06d}"
        QTreeWidgetItem(frame, ["时间戳", timestamp])
        QTreeWidgetItem(frame, ["链路类型", str(raw.linktype)])
        for layer in packet.layers:
            item = QTreeWidgetItem(self.tree, [layer.name, f"偏移 {layer.offset}，{layer.length} 字节"])
            item.setData(0, Qt.ItemDataRole.UserRole, (layer.offset, layer.length))
            for field in layer.fields:
                child = QTreeWidgetItem(item, [field.name, field.value])
                child.setToolTip(1, field.value)
                child.setData(0, Qt.ItemDataRole.UserRole, (field.offset, field.length))
        if packet.issues:
            issues = QTreeWidgetItem(self.tree, ["解析提示", str(len(packet.issues))])
            for issue in packet.issues:
                child = QTreeWidgetItem(issues, [issue.kind, issue.message])
                child.setToolTip(1, issue.message)
                child.setData(0, Qt.ItemDataRole.UserRole, (issue.offset, 1))
        self.tree.expandAll()
        self.tree.scrollToTop()

    def _render_hex(self):
        if self.current_packet is None:
            return
        data = self.current_packet.raw.data
        self.hex_view.setPlainText(hex_dump(data, limit=self._hex_limit))
        shown = min(len(data), self._hex_limit)
        self.raw_meta.setText(f"{shown:,} / {len(data):,} 字节 · HEX / ASCII")
        self.full_bytes_button.setEnabled(shown < len(data))

    def _show_all_bytes(self):
        if self.current_packet is not None:
            self._hex_limit = max(4096, len(self.current_packet.raw.data))
            self._render_hex()

    def _select_field(self, current, previous):
        self.hex_view.setExtraSelections([])
        if current is None or self.current_packet is None:
            return
        span = current.data(0, Qt.ItemDataRole.UserRole)
        if not span:
            return
        start, length = span
        end = min(start + length, len(self.current_packet.raw.data))
        if end > self._hex_limit:
            self._show_all_bytes()
        selections = []
        for row in range(start // 16, (end + 15) // 16):
            left, right = max(start, row * 16) % 16, min(end - row * 16, 16)
            block = self.hex_view.document().findBlockByNumber(row)
            if not block.isValid() or left >= right:
                continue
            for a, b in ((10 + left * 3, 10 + right * 3 - 1), (60 + left, 60 + right)):
                selection = QTextEdit.ExtraSelection()
                cursor = QTextCursor(self.hex_view.document())
                cursor.setPosition(block.position() + a)
                cursor.setPosition(block.position() + b, QTextCursor.MoveMode.KeepAnchor)
                selection.cursor = cursor
                selection.format.setBackground(QColor("#356a83"))
                selection.format.setForeground(QColor("#ffffff"))
                selections.append(selection)
        self.hex_view.setExtraSelections(selections)
        if selections:
            self.hex_view.setTextCursor(selections[0].cursor)
            self.hex_view.ensureCursorVisible()

    def closeEvent(self, event):
        if self.files.is_active:
            self._closing = True
            if self.files.operation == "loading":
                self.files.cancel()
            self._state_changed(self.controller.state)
            event.ignore()
            return
        if not self._closing and not self._confirm_replace("关闭窗口会放弃尚未保存的数据。是否继续？"):
            event.ignore()
            return
        if self.controller.is_active:
            self._closing = True
            self.controller.stop()
            event.ignore()
        else:
            event.accept()


def create_application():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["lab1a-sniffer"])
        app.setApplicationName("Lab1A Sniffer")
        app.setApplicationDisplayName("网络嗅探器 · 实验 1A")
        app.setStyle("Fusion")
        app.setFont(QFont("PingFang SC", 12))
    app.setStyleSheet(STYLE)
    return app


def run_gui() -> int:
    app = create_application()
    window = SnifferWindow()
    app.aboutToQuit.connect(window.controller.shutdown)
    app.aboutToQuit.connect(window.files.shutdown)
    window.show()
    return app.exec()
