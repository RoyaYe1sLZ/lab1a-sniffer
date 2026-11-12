"""异步采样进程信息；工作线程不访问 Qt 控件，关闭时可取消子进程。"""
import threading
from PySide6.QtCore import QObject, QTimer, Signal
from .processes import collect_snapshot


class ProcessController(QObject):
    completed = Signal(object)
    statusChanged = Signal(str)
    idle = Signal()

    def __init__(self, parent=None, *, scanner=collect_snapshot):
        super().__init__(parent)
        self.scanner = scanner
        self.enabled = False
        self._thread = None
        self._cancel = threading.Event()
        self._done = threading.Event()
        self._result = None
        self._error = ""
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self._poll)
        self._ticks = 0

    @property
    def is_busy(self):
        return self._thread is not None

    def set_enabled(self, enabled):
        self.enabled = enabled
        if enabled:
            self.timer.start()
            self._ticks = 10
            self._poll()
        else:
            self._cancel.set()
            if not self.is_busy:
                self.timer.stop()

    def _poll(self):
        if self._thread is not None:
            if not self._done.is_set():
                return
            self._thread.join(0)
            if self._thread.is_alive():
                return
            self._thread = None
            if self.enabled and not self._cancel.is_set():
                if self._error:
                    self.statusChanged.emit(self._error)
                elif self._result is not None:
                    self.completed.emit(self._result)
            self._result = None
            self.idle.emit()
        if not self.enabled:
            self.timer.stop()
            return
        self._ticks += 1
        if self._ticks < 10:
            return
        self._ticks = 0
        self._cancel.clear()
        self._done.clear()
        self._result, self._error = None, ""

        def run():
            try:
                self._result = self.scanner(self._cancel.is_set)
            except InterruptedError:
                pass
            except Exception as exc:
                self._error = f"进程信息不可用：{exc}"
            finally:
                self._done.set()

        self._thread = threading.Thread(target=run, name="pcap-process-snapshot")
        try:
            self._thread.start()
        except RuntimeError as exc:
            self._thread = None
            self.statusChanged.emit(f"进程采样线程无法启动：{exc}")

    def shutdown(self):
        self.set_enabled(False)
        if self._thread is not None:
            self._thread.join(3)
            if self._thread.is_alive():
                return False
            self._thread = None
        self.timer.stop()
        self._result = None
        return True
