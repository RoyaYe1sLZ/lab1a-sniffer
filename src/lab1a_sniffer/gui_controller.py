"""Qt 主线程中的非阻塞会话调度；原生抓包仍由 CaptureSession 工作线程执行。"""

import time

from PySide6.QtCore import QObject, QTimer, Signal

from .capture import CaptureConfig, CaptureSession, CaptureStatus
from .parser import parse_packet


class CaptureController(QObject):
    stateChanged = Signal(str)
    sessionStarted = Signal(object)
    batchReady = Signal(object)
    statusChanged = Signal(object)
    problem = Signal(str)

    def __init__(self, parent=None, *, session_factory=CaptureSession):
        super().__init__(parent)
        self._session_factory = session_factory
        self.session = None
        self.state = "idle"
        self.info = None
        self.last_status = CaptureStatus()
        self.last_error = ""
        self._accepted = False
        self._started_at = 0.0
        self.timer = QTimer(self)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self._poll)

    @property
    def is_active(self):
        return self.state != "idle"

    def _state(self, value):
        self.state = value
        self.stateChanged.emit(value)

    def start(self, config: CaptureConfig) -> bool:
        if self.is_active:
            return False
        self.last_error = ""
        self.last_status = CaptureStatus()
        self._accepted = False
        self._started_at = time.monotonic()
        try:
            self.session = self._session_factory(config)
            self.session.start()
        except Exception as exc:
            self.session = None
            self.last_error = str(exc)
            self.problem.emit(self.last_error)
            return False
        self._state("starting")
        self.timer.start()
        return True

    def stop(self):
        if self.session is not None:
            self.session.request_stop()
            self._state("stopping")

    def _fail(self, message):
        if not self.last_error:
            self.last_error = message
            self.problem.emit(message)
        self.stop()

    def _poll(self):
        session = self.session
        if session is None:
            return
        if not session.is_ready and time.monotonic() - self._started_at > 5:
            self._fail("打开抓包接口超时，正在等待抓包线程退出。")
        if session.is_ready and not self._accepted and self.state == "starting":
            status = session.status()
            if status.error:
                self._fail(status.error)
            elif session.info is not None:
                self.info = session.info
                self._accepted = True
                self.sessionStarted.emit(self.info)
                self._state("capturing")
        batch = session.drain(128)
        if batch and self._accepted:
            try:
                parsed = [parse_packet(raw) for raw in batch]
            except Exception as exc:
                self._fail(f"协议解析失败，已请求停止：{exc}")
            else:
                self.batchReady.emit(parsed)
        self.last_status = session.status()
        self.statusChanged.emit(self.last_status)
        if session.finished.is_set() and session.pending_count == 0 and session.join(0):
            if self.last_status.error and not self.last_error:
                self.last_error = self.last_status.error
                self.problem.emit(self.last_error)
            self.timer.stop()
            self.session = None
            self._state("idle")

    def shutdown(self) -> bool:
        """事件循环已退出时的兜底清理；正常关闭由窗口异步等待 idle。"""
        self.timer.stop()
        if self.session is None:
            return True
        self.session.request_stop()
        stopped = self.session.join(3)
        if stopped:
            self.last_status = self.session.status()
            self.session = None
            self._state("idle")
        return stopped
