"""TCP 连接浏览、按进程聚合与分页方向时序。"""
from datetime import datetime
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QTreeWidget, QTreeWidgetItem, QComboBox, QSplitter, QCheckBox)
from .flows import tcp_segment


def plain(text):
    value = QLabel(text)
    value.setTextFormat(Qt.TextFormat.PlainText)
    value.setWordWrap(True)
    return value


class FlowPanel(QWidget):
    followRequested = Signal(object, str)
    packetRequested = Signal(int)
    processEnabled = Signal(bool)
    PAGE_SIZE = 200

    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self._items = {}
        self._selected = None
        self._page = 0
        self._signature = None
        self._processes = ()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 10, 8, 8)
        toolbar = QHBoxLayout()
        self.process_filter = QComboBox()
        self.process_filter.setMinimumWidth(250)
        self.process_filter.addItem("全部进程 / 未关联", None)
        self.process_filter.currentIndexChanged.connect(self._process_changed)
        toolbar.addWidget(plain("进程"))
        toolbar.addWidget(self.process_filter)
        self.follow = QPushButton("仅看所选连接")
        self.follow.clicked.connect(self.follow_selected)
        toolbar.addWidget(self.follow)
        self.follow_process = QPushButton("查看该进程已关联 TCP 包")
        self.follow_process.clicked.connect(self.follow_owner)
        toolbar.addWidget(self.follow_process)
        self.all_packets = QPushButton("取消连接过滤")
        self.all_packets.clicked.connect(lambda: self.followRequested.emit(None, ""))
        toolbar.addWidget(self.all_packets)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        options = QHBoxLayout()
        self.process_check = QCheckBox("实时关联本机进程")
        self.process_check.setChecked(True)
        self.process_check.toggled.connect(self.processEnabled)
        options.addWidget(self.process_check)
        self.process_status = plain("开始实时抓包后，每约 1 秒查询当前用户的 TCP 套接字。")
        options.addWidget(self.process_status, 1)
        layout.addLayout(options)
        self.summary = plain("尚无 TCP 连接。实时抓包与离线 PCAP 均可建立连接索引。")
        layout.addWidget(self.summary)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = QTreeWidget()
        self.table.setObjectName("flowTable")
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(105)
        self.table.setHeaderLabels(["流", "端点 A", "端点 B", "观测状态", "A→B 包/字节", "B→A 包/字节", "进程线索"])
        for column, width in enumerate((50, 220, 220, 115, 135, 135, 180)):
            self.table.setColumnWidth(column, width)
        self.table.currentItemChanged.connect(self._selection_changed)
        split.addWidget(self.table)
        bottom = QWidget()
        bottom.setMinimumHeight(250)
        lower = QVBoxLayout(bottom)
        lower.setContentsMargins(0, 8, 0, 0)
        self.detail = plain("选择连接后查看方向、相对时间和 TCP 标志；双击时序行定位原始包。")
        lower.addWidget(self.detail)
        self.timeline = QTreeWidget()
        self.timeline.setObjectName("flowTimeline")
        self.timeline.setRootIsDecorated(False)
        self.timeline.setMinimumHeight(130)
        self.timeline.setHeaderLabels(["原包序号", "相对时间 ms", "A                 B", "TCP 标志 / Seq / Ack", "载荷字节"])
        for column, width in enumerate((85, 105, 150, 550, 85)):
            self.timeline.setColumnWidth(column, width)
        self.timeline.itemDoubleClicked.connect(lambda item, _: self.packetRequested.emit(item.data(0, Qt.ItemDataRole.UserRole)))
        lower.addWidget(self.timeline, 1)
        paging = QHBoxLayout()
        self.previous = QPushButton("上一页")
        self.previous.clicked.connect(lambda: self._change_page(-1))
        self.next = QPushButton("下一页")
        self.next.clicked.connect(lambda: self._change_page(1))
        self.page_label = plain("")
        self.page_label.setWordWrap(False)
        paging.addWidget(self.previous)
        paging.addWidget(self.next)
        paging.addWidget(self.page_label)
        paging.addStretch()
        lower.addLayout(paging)
        split.addWidget(bottom)
        split.setSizes([130, 270])
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        self._buttons()

    def reset(self):
        self._selected, self._page, self._signature = None, 0, None
        self.table.clear()
        self._items.clear()
        self._processes = ()
        self.process_filter.blockSignals(True)
        self.process_filter.clear()
        self.process_filter.addItem("全部进程 / 未关联", None)
        self.process_filter.blockSignals(False)
        self.refresh()

    def refresh(self):
        tracker = self.model.flows
        owners = tuple(sorted({p for f in tracker.flows.values() for p in f.owners}))
        if owners != self._processes:
            selected = self.process_filter.currentData()
            self.process_filter.blockSignals(True)
            self.process_filter.clear()
            self.process_filter.addItem("全部进程 / 未关联", None)
            for owner in owners:
                self.process_filter.addItem(str(owner), owner)
                self.process_filter.setItemData(self.process_filter.count() - 1, f"启动时间：{owner.started}", Qt.ItemDataRole.ToolTipRole)
            self.process_filter.setCurrentIndex(max(0, self.process_filter.findData(selected)))
            self.process_filter.blockSignals(False)
            self._processes = owners
        selected_owner = self.process_filter.currentData()
        self.table.setUpdatesEnabled(False)
        visible = 0
        for flow in tracker.flows.values():
            item = self._items.get(flow.id)
            if item is None:
                item = QTreeWidgetItem(self.table)
                item.setData(0, Qt.ItemDataRole.UserRole, flow.id)
                self._items[flow.id] = item
            values = [str(flow.id), str(flow.a), str(flow.b), flow.state,
                      f"{flow.counts[0]} / {flow.wire_bytes[0]:,}", f"{flow.counts[1]} / {flow.wire_bytes[1]:,}",
                      "; ".join(str(p) for p in flow.owners) or "未关联"]
            for col, text in enumerate(values):
                if item.text(col) != text:
                    item.setText(col, text)
                item.setToolTip(col, text)
            item.setHidden(selected_owner is not None and selected_owner not in flow.owners)
            visible += not item.isHidden()
        self.table.setUpdatesEnabled(True)
        if self._selected is not None and (self._selected not in self._items or self._items[self._selected].isHidden()):
            self.table.setCurrentItem(None)
            self._selected = None
        self.summary.setText(f"TCP 连接：显示 {visible} / 全部 {len(tracker.flows)} · 已索引 {len(tracker.row_flow):,} 个包"
                             + (f" · 索引容量已满，另有 {tracker.untracked} 个 TCP 包未跟踪（原包仍保留）" if tracker.untracked else "")
                             + "。A 为观测到的发起方；中途捕获时 A 为首包发送方。字节含链路头，重传会重复计数。")
        self._render_timeline()
        self._buttons()

    def _buttons(self):
        self.follow.setEnabled(self._selected is not None)
        self.follow_process.setEnabled(self.process_filter.currentData() is not None)

    def _process_changed(self, *_):
        self.refresh()

    def _selection_changed(self, current, previous):
        self._selected = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        self._page, self._signature = 0, None
        self._render_timeline()
        self._buttons()

    def _change_page(self, delta):
        self._page = max(0, self._page + delta)
        self._render_timeline()

    def _render_timeline(self):
        flow = self.model.flows.flows.get(self._selected)
        signature = (id(flow), len(flow.rows), self._page, flow.state, len(flow.owners)) if flow else None
        if signature == self._signature and flow is not None:
            return
        self._signature = signature
        self.timeline.clear()
        if flow is None:
            self.detail.setText("选择连接后查看方向、相对时间和 TCP 标志；双击时序行定位原始包。")
            self.page_label.setText("无连接")
            self.previous.setEnabled(False)
            self.next.setEnabled(False)
            return
        pages = max(1, (len(flow.rows) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._page = min(self._page, pages - 1)
        start = self._page * self.PAGE_SIZE
        for row in flow.rows[start:start + self.PAGE_SIZE]:
            packet = self.model.packets[row]
            seg = tcp_segment(packet)
            direction = "A ───────→ B" if seg.source == flow.a else "A ←─────── B"
            item = QTreeWidgetItem(self.timeline, [str(row + 1), f"{(packet.raw.timestamp_us - flow.first_us) / 1000:.3f}",
                                                  direction, packet.summary, str(seg.payload_length)])
            item.setData(0, Qt.ItemDataRole.UserRole, row)
        handshake = f"{flow.handshake_us / 1000:.3f} ms" if flow.handshake_us is not None else "未完整观测"
        owners = "; ".join(f"{p}（快照 {datetime.fromtimestamp(t / 1e6).strftime('%H:%M:%S')}）" for p, t in flow.owners.items())
        self.detail.setText(f"流 {flow.id} · A={flow.a} · B={flow.b}\n"
                            f"握手观测时长 {handshake} · 时长 {(flow.last_us - flow.first_us) / 1000:.3f} ms · "
                            f"捕获载荷 A→B {flow.payload_bytes[0]:,} / B→A {flow.payload_bytes[1]:,} 字节\n"
                            + (f"套接字持有者线索：{owners}" if owners else "进程未关联；离线 PCAP 不包含历史进程信息。"))
        self.page_label.setText(f"第 {self._page + 1} / {pages} 页 · 每页最多 {self.PAGE_SIZE} 个包")
        self.previous.setEnabled(self._page > 0)
        self.next.setEnabled(self._page + 1 < pages)

    def follow_selected(self):
        if self._selected is not None:
            self.followRequested.emit(("flow", self._selected), f"TCP 流 {self._selected}")

    def follow_owner(self):
        owner = self.process_filter.currentData()
        if owner is not None:
            self.followRequested.emit(("process", owner), str(owner))
