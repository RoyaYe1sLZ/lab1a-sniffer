"""实验 1A 的 Qt Widgets 界面：抓包、显示过滤与 PCAP 文件浏览。"""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QSizePolicy, QSplitter, QStackedWidget, QTableView, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget, QTabWidget,
)

from .capture import CaptureConfig, CaptureStatus
from .gui_controller import CaptureController
from .gui_files import FileController
from .gui_flows import FlowPanel
from .gui_processes import ProcessController
from .gui_models import PacketTableModel, ProtocolFilterModel
from .parser import hex_dump
from .pcap import list_interfaces


from .gui_theme import STYLE
from .gui_widgets import ChoiceBox, NetworkMark, PacketDelegate, ProtocolSelector, ToggleSwitch, line_icon


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
                 max_packets=20000, max_memory=128 * 1024 * 1024, process_scanner=None):
        super().__init__()
        self.setObjectName("SnifferWindow")
        self.setWindowTitle("网络嗅探器 · 实验 1A")
        self.setMinimumSize(980, 660)
        geometry = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1320, int(geometry.width() * .92)), min(860, int(geometry.height() * .9)))
        self.controller = controller or CaptureController(self)
        self.files = FileController(self)
        self.process_monitor = ProcessController(self, **({"scanner": process_scanner} if process_scanner else {}))
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
        self._follow_filter = None
        self._flow_dirty = True
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
        self.process_monitor.completed.connect(self._process_snapshot)
        self.process_monitor.statusChanged.connect(self.flow_panel.process_status.setText)
        self.process_monitor.idle.connect(self._process_idle)
        self.flow_timer = QTimer(self)
        self.flow_timer.setInterval(500)
        self.flow_timer.timeout.connect(self._refresh_flows)
        self.flow_timer.start()
        self.refresh_interfaces()
        self._state_changed("idle")
        self._update_status(self._last_status)

    def _build(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 8, 14, 10)
        outer.setSpacing(9)

        header_frame = QFrame()
        header_frame.setObjectName("appHeader")
        header = QHBoxLayout(header_frame)
        header.setContentsMargins(2, 3, 2, 4)
        header.setSpacing(12)
        header.addWidget(NetworkMark())
        header.addWidget(label("网络嗅探器", "title"))
        header.addWidget(label("实验 1A", "subtitle"))
        header.addStretch()
        self.clear_button = QPushButton("清空")
        self.clear_button.setObjectName("quietAction")
        self.clear_button.setToolTip("清空当前缓存；有未保存数据时会要求确认。")
        self.clear_button.clicked.connect(self.clear_packets)
        header.addWidget(self.clear_button)
        self.badge = label("● 就绪", "stateBadge")
        header.addWidget(self.badge)
        outer.addWidget(header_frame)

        controls = QFrame()
        controls.setObjectName("controls")
        bar = QHBoxLayout(controls)
        bar.setContentsMargins(12, 10, 12, 10)
        bar.setSpacing(9)
        bar.addWidget(label("网络接口", "formLabel"))
        self.interfaces = ChoiceBox()
        self.interfaces.setObjectName("interfaceCombo")
        self.interfaces.setFixedWidth(150)
        bar.addWidget(self.interfaces)
        self.refresh_button = QPushButton()
        self.refresh_button.setObjectName("quietAction")
        self.refresh_button.setIcon(line_icon("refresh"))
        self.refresh_button.setFixedSize(28, 32)
        self.refresh_button.setToolTip("刷新网络接口")
        self.refresh_button.setAccessibleName("刷新网络接口")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        bar.addWidget(self.refresh_button)
        bar.addSpacing(5)
        bar.addWidget(label("抓包过滤 · BPF", "formLabel"))
        self.bpf = QLineEdit()
        self.bpf.setObjectName("bpfEdit")
        self.bpf.setAccessibleName("抓包过滤表达式")
        self.bpf.setPlaceholderText("tcp or udp，留空捕获全部")
        self.bpf.setClearButtonEnabled(True)
        self.bpf.setMinimumWidth(130)
        self.bpf.returnPressed.connect(self.start_capture)
        bar.addWidget(self.bpf, 1)
        self.start_button = QPushButton("▶  开始抓包")
        self.start_button.setObjectName("start")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("■  停止抓包")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.clicked.connect(self.controller.stop)
        self.capture_actions = QStackedWidget()
        self.capture_actions.setFixedSize(112, 34)
        self.capture_actions.addWidget(self.start_button)
        self.capture_actions.addWidget(self.stop_button)
        bar.addWidget(self.capture_actions)
        self.open_button = QPushButton("打开 PCAP")
        self.open_button.setObjectName("openButton")
        self.open_button.setIcon(line_icon("open"))
        self.open_button.clicked.connect(lambda: self.open_file())
        self.save_button = QPushButton("保存全部")
        self.save_button.setObjectName("saveButton")
        self.save_button.setIcon(line_icon("save"))
        self.save_button.setToolTip("保存全部缓存包，不受协议、连接或进程显示过滤影响。")
        self.save_button.clicked.connect(lambda: self.save_file())
        bar.addWidget(self.open_button)
        bar.addWidget(self.save_button)
        outer.addWidget(controls)

        metrics = QFrame()
        metrics.setObjectName("metrics")
        metric_bar = QHBoxLayout(metrics)
        metric_bar.setContentsMargins(16, 8, 16, 8)
        metric_bar.setSpacing(20)
        self.metric_labels = {}
        for index, (key, title) in enumerate((("captured", "已捕获"), ("visible", "当前显示"),
                                              ("flows", "TCP 连接"), ("bytes", "数据量"))):
            if index:
                divider = QFrame()
                divider.setObjectName("metricDivider")
                divider.setFixedSize(1, 22)
                metric_bar.addWidget(divider)
            group = QHBoxLayout()
            group.setSpacing(12)
            group.addWidget(label(title, "metricCaption"))
            value = label("0", "metricValue")
            self.metric_labels[key] = value
            group.addWidget(value)
            group.addStretch()
            metric_bar.addLayout(group, 1)
        self.metric_labels["bytes"].setToolTip("当前缓存包的原始字节总量；Python 对象缓存预算另见底栏。")
        outer.addWidget(metrics)

        self.banner = label("", "banner")
        self.banner.setWordWrap(True)
        self.banner.hide()
        outer.addWidget(self.banner)
        vertical = QSplitter(Qt.Orientation.Vertical)
        vertical.setHandleWidth(8)
        packet_panel, packet_layout = self._panel()
        packet_header = QHBoxLayout()
        packet_header.setSpacing(12)
        packet_header.addWidget(label("数据包列表", "panelTitle"))
        self.display_filter = ProtocolSelector()
        self.display_filter.addItems(ProtocolFilterModel.PROTOCOLS)
        self.display_filter.setToolTip("仅改变显示；HTTP 包也匹配其 TCP 和 IP 层。方向键可以切换协议。")
        self.display_filter.currentTextChanged.connect(self._filter_changed)
        packet_header.addWidget(self.display_filter)
        packet_header.addStretch()
        self.auto_scroll = ToggleSwitch("自动滚动")
        self.auto_scroll.setChecked(True)
        self.auto_scroll.setToolTip("新包到达时滚动至底部；点击数据包可暂停自动滚动。")
        packet_header.addWidget(self.auto_scroll)
        packet_layout.addLayout(packet_header)
        self.source_label = label("尚未捕获或打开文件", "muted")
        self.source_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.count_label = label("显示 0 / 全部 0", "packetCount")
        self.table = QTableView()
        self.table.setObjectName("packetTable")
        self.table.setModel(self.proxy)
        self.table.setItemDelegate(PacketDelegate(self.table))
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setMinimumSectionSize(45)
        for column, width in enumerate((50, 132, 160, 160, 76, 58)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(self._select_packet)
        self.table.clicked.connect(lambda _: self.auto_scroll.setChecked(False))
        self.empty = QWidget()
        empty_layout = QVBoxLayout(self.empty)
        empty_layout.addStretch()
        mark_row = QHBoxLayout()
        mark_row.addStretch()
        mark_row.addWidget(NetworkMark())
        mark_row.addStretch()
        empty_layout.addLayout(mark_row)
        self.empty_title = label("准备捕获第一个数据包", "emptyTitle")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint = label("选择网络接口开始抓包，或打开一个 PCAP 文件。", "emptyHint")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_title)
        empty_layout.addWidget(self.empty_hint)
        empty_layout.addStretch()
        self.packet_stack = QStackedWidget()
        self.packet_stack.addWidget(self.table)
        self.packet_stack.addWidget(self.empty)
        self.packet_stack.setCurrentWidget(self.empty)
        packet_layout.addWidget(self.packet_stack, 1)
        follow_bar = QHBoxLayout()
        self.follow_current_button = QPushButton("追踪 TCP 流")
        self.follow_current_button.setObjectName("quietAction")
        self.follow_current_button.setIcon(line_icon("trace", "#147e82"))
        self.follow_current_button.setEnabled(False)
        self.follow_current_button.setToolTip("查看所选数据包所属连接的方向时序。")
        self.follow_current_button.clicked.connect(self._follow_current)
        follow_bar.addWidget(self.follow_current_button)
        follow_bar.addWidget(self.source_label, 1)
        self.flow_filter_label = label("连接过滤：全部", "muted")
        self.flow_filter_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        follow_bar.addWidget(self.flow_filter_label, 1)
        self.clear_flow_button = QPushButton("取消连接过滤")
        self.clear_flow_button.setObjectName("quietAction")
        self.clear_flow_button.clicked.connect(lambda: self._follow(None, ""))
        follow_bar.addWidget(self.count_label)
        follow_bar.addWidget(self.clear_flow_button)
        packet_layout.addLayout(follow_bar)
        packet_panel.setMinimumHeight(190)
        vertical.addWidget(packet_panel)

        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.setHandleWidth(8)
        details_panel, details_layout = self._panel()
        details_layout.addWidget(label("协议详情", "panelTitle"))
        self.packet_meta = label("选择一个数据包，查看封装层次与字段。", "muted")
        self.packet_meta.setWordWrap(True)
        details_layout.addWidget(self.packet_meta)
        self.tree = QTreeWidget()
        self.tree.setObjectName("protocolTree")
        self.tree.setHeaderLabels(["字段", "值"])
        self.tree.setColumnWidth(0, 160)
        self.tree.header().setStretchLastSection(True)
        self.tree.setUniformRowHeights(True)
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
        self.full_bytes_button.setObjectName("quietAction")
        self.full_bytes_button.setEnabled(False)
        self.full_bytes_button.clicked.connect(self._show_all_bytes)
        raw_header.addWidget(self.full_bytes_button)
        raw_layout.addLayout(raw_header)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setObjectName("hexView")
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setFont(QFont("Menlo", 11))
        self.hex_view.document().setDocumentMargin(14)
        self.hex_view.setPlaceholderText("选择数据包后，显示十六进制与 ASCII。")
        raw_layout.addWidget(self.hex_view, 1)
        lower.addWidget(raw_panel)
        lower.setSizes([450, 790])
        lower.setMinimumHeight(230)
        vertical.addWidget(lower)
        vertical.setSizes([360, 240])
        vertical.setStretchFactor(0, 3)
        vertical.setStretchFactor(1, 2)
        self.tabs = QTabWidget()
        self.tabs.setObjectName("workspaceTabs")
        self.tabs.addTab(vertical, "数据包")
        self.flow_panel = FlowPanel(self.model)
        self.flow_panel.followRequested.connect(self._follow)
        self.flow_panel.packetRequested.connect(self._jump_packet)
        self.flow_panel.processEnabled.connect(self._process_enabled)
        self.tabs.addTab(self.flow_panel, "TCP 流与进程")
        self.tabs.currentChanged.connect(lambda _: self._refresh_flows(force=True))
        outer.addWidget(self.tabs, 1)
        footer = QHBoxLayout()
        footer.setContentsMargins(2, 2, 2, 0)
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
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(7)
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
            self._reset_flows()
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
        self.clear_flow_button.setEnabled(self._follow_filter is not None)
        self.clear_flow_button.setVisible(self._follow_filter is not None)
        self.flow_filter_label.setVisible(self._follow_filter is not None)
        self.packet_stack.setCurrentWidget(self.table if visible else self.empty)
        if total and not visible:
            title, hint = "没有符合显示过滤的数据包", f"全部 {total:,} 个包仍保留，可切换协议为“全部”并取消连接过滤查看。"
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
        self._reset_flows()
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
        self._reset_flows()
        self._process_enabled(self.flow_panel.process_check.isChecked())
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
            self._flow_dirty = True
            self._sync_flow_filter()
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
        self.flow_panel.process_check.setEnabled(self.source_kind == "live" and state == "capturing" and not self._closing)
        if state == "idle" or self._closing:
            self.process_monitor.set_enabled(False)
            if self.source_kind == "live":
                self.flow_panel.process_status.setText("抓包已停止，保留本轮已观测的进程线索。经典 PCAP 不保存进程信息。")
        for widget in (self.interfaces, self.refresh_button, self.bpf):
            widget.setEnabled(not active and not self._closing)
        self.start_button.setEnabled(not active and not self._closing and self.interfaces.count() > 0)
        self.capture_actions.setCurrentWidget(self.start_button if state == "idle" else self.stop_button)
        self.stop_button.setEnabled(state in ("starting", "capturing") and not self._closing and not self.files.is_active)
        self.clear_button.setEnabled(not active and not self._closing and self.model.rowCount() > 0)
        self.open_button.setEnabled(not active and not self._closing)
        self.save_button.setEnabled(not active and not self._closing and self.capture_info is not None)
        text = {"idle": "离线浏览" if self.source_kind == "file" else "已停止" if self.capture_info else "就绪",
                "starting": "正在打开接口", "capturing": "正在抓包", "stopping": "正在停止"}[state]
        if self.files.is_active:
            text = "正在读取文件" if self.files.operation == "loading" else "正在保存文件"
        background, foreground = ("#e0f3ec", "#197861") if state == "capturing" else ("#eaf0f3", "#667e8c")
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
        self.metric_labels["captured"].setText(f"{total if self.source_kind == 'file' else status.packets_read:,}")
        self.metric_labels["visible"].setText(f"{visible:,}")
        self.metric_labels["flows"].setText(f"{len(self.model.flows.flows):,}")
        self.metric_labels["bytes"].setText(byte_size(self.model.raw_bytes))
        dropped = str(status.kernel.dropped) if status.kernel is not None else "—"
        text = (f"缓存 {byte_size(self.model.memory_cost)}"
                f"  ·  队列丢弃 {status.queue_dropped:,}  ·  内核丢包 {dropped}")
        if self.model.rejected_count:
            text += f"  ·  未入缓存 {self.model.rejected_count:,}"
        self.stats_label.setText(text)
        if status.kernel:
            self.stats_label.setToolTip(f"内核接收 {status.kernel.received}；接口丢包 {status.kernel.interface_dropped}（部分平台不支持）")
        if self.source_kind == "file":
            self.stats_label.setText(f"离线浏览  ·  缓存 {byte_size(self.model.memory_cost)}")
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
        self.follow_current_button.setEnabled(False)
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
        self.follow_current_button.setEnabled(source.row() in self.model.flows.row_flow)
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
                selection.format.setBackground(QColor("#237c7c"))
                selection.format.setForeground(QColor("#ffffff"))
                selections.append(selection)
        self.hex_view.setExtraSelections(selections)
        if selections:
            self.hex_view.setTextCursor(selections[0].cursor)
            self.hex_view.ensureCursorVisible()

    def _reset_flows(self):
        self.process_monitor.set_enabled(False)
        self._follow_filter = None
        self.proxy.set_flows()
        self.flow_filter_label.setText("连接过滤：全部")
        self.flow_panel.reset()
        self._flow_dirty = True
        if self.source_kind == "file":
            self.flow_panel.process_status.setText("离线 PCAP 无历史进程信息，只分析 TCP 流；不查询当前进程进行猜测。")

    def _refresh_flows(self, *, force=False):
        if force or (self._flow_dirty and self.tabs.currentIndex() == 1):
            self.flow_panel.refresh()
            self._flow_dirty = False

    def _sync_flow_filter(self):
        ids = None
        if self._follow_filter:
            kind, value = self._follow_filter
            ids = {value} if kind == "flow" else {f.id for f in self.model.flows.flows.values() if value in f.owners}
        if (None if ids is None else frozenset(ids)) != self.proxy.flow_ids:
            self.proxy.set_flows(ids)

    def _follow(self, target, title):
        self._follow_filter = target
        self._sync_flow_filter()
        self.flow_filter_label.setText("连接过滤：" + (title or "全部"))
        self.flow_filter_label.setToolTip(self.flow_filter_label.text())
        self.tabs.setCurrentIndex(0)
        if self.proxy.rowCount():
            self.table.selectRow(0)
        else:
            self._clear_details()
        self._refresh_packet_view()
        self._update_status(self._last_status)

    def _follow_current(self):
        source = self.proxy.mapToSource(self.table.currentIndex())
        flow_id = self.model.flows.row_flow.get(source.row()) if source.isValid() else None
        if flow_id is not None:
            self._follow(("flow", flow_id), f"TCP 流 {flow_id}")
            self.flow_panel.process_filter.setCurrentIndex(0)
            self.flow_panel.refresh()
            self.flow_panel.table.setCurrentItem(self.flow_panel._items[flow_id])
            self.tabs.setCurrentIndex(1)

    def _jump_packet(self, row):
        if not 0 <= row < self.model.rowCount():
            return
        self.display_filter.setCurrentText("全部")
        flow_id = self.model.flows.row_flow.get(row)
        self._follow(("flow", flow_id), f"TCP 流 {flow_id}")
        index = self.proxy.mapFromSource(self.model.index(row, 0))
        if index.isValid():
            self.table.selectRow(index.row())
            self.table.scrollTo(index)
            self.auto_scroll.setChecked(False)

    def _process_enabled(self, enabled):
        active = enabled and self.source_kind == "live" and self.controller.state in ("starting", "capturing") and not self._closing
        self.process_monitor.set_enabled(active)
        if active:
            self.flow_panel.process_status.setText("正在采集当前用户 TCP 套接字快照…")
        elif self.source_kind == "live" and not enabled:
            self.flow_panel.process_status.setText("进程采样已关闭，保留已观测的线索。")

    def _process_snapshot(self, snapshot):
        if self.source_kind != "live":
            return
        self.model.flows.associate(snapshot)
        self._flow_dirty = True
        self._sync_flow_filter()
        self._refresh_packet_view()
        self._update_status(self._last_status)
        stamp = datetime.fromtimestamp(snapshot.ended_us / 1e6).strftime("%H:%M:%S")
        self.flow_panel.process_status.setText(f"快照 {stamp} · {snapshot.message}")

    def _process_idle(self):
        if self._closing and not self.controller.is_active and not self.files.is_active:
            QTimer.singleShot(0, self.close)

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
        elif self.process_monitor.is_busy:
            self._closing = True
            self.process_monitor.set_enabled(False)
            event.ignore()
        else:
            self.flow_timer.stop()
            self.process_monitor.shutdown()
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
    app.aboutToQuit.connect(window.process_monitor.shutdown)
    window.show()
    return app.exec()
