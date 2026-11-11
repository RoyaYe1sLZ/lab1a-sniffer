"""文件工作线程与 Qt 调度；读取结果完整成功后才交给窗口替换。"""

import threading

from PySide6.QtCore import QObject, QTimer, Signal

from .pcap import FileCancelled, write_pcap
from .storage import load_capture


class FileController(QObject):
    stateChanged = Signal(str)
    completed = Signal(str, object)
    problem = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.operation = "idle"
        self._thread = None
        self._cancel = threading.Event()
        self._finished = threading.Event()
        self._result = None
        self._error = ""
        self._cancelled = False
        self.timer = QTimer(self)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self._poll)

    @property
    def is_active(self):
        return self._thread is not None

    def _start(self, operation, function):
        if self.is_active:
            return False
        self._cancel.clear()
        self._finished.clear()
        self._result, self._error, self._cancelled = None, "", False

        def run():
            try:
                self._result = function(self._cancel.is_set)
            except FileCancelled:
                self._cancelled = True
            except Exception as exc:
                self._error = str(exc)
            finally:
                self._finished.set()

        self._thread = threading.Thread(target=run, name=f"pcap-file-{operation}")
        try:
            self._thread.start()
        except Exception as exc:
            self._thread = None
            self.problem.emit(str(exc))
            return False
        self.operation = operation
        self.stateChanged.emit(operation)
        self.timer.start()
        return True

    def load(self, path, *, max_packets, max_memory):
        return self._start("loading", lambda cancelled: load_capture(
            path, max_packets=max_packets, max_memory=max_memory, cancelled=cancelled))

    def save(self, path, packets, info):
        def save(cancelled):
            write_pcap(path, packets, info, cancelled=cancelled)
            return path
        return self._start("saving", save)

    def cancel(self):
        self._cancel.set()

    def _poll(self):
        if self._thread is None or not self._finished.is_set():
            return
        self._thread.join(0)
        if self._thread.is_alive():
            return
        operation = self.operation
        self._thread = None
        self.operation = "idle"
        self.timer.stop()
        if self._error:
            self.problem.emit(("读取失败：" if operation == "loading" else "保存失败：") + self._error)
        elif not self._cancelled:
            self.completed.emit(operation, self._result)
        self._result = None
        self.stateChanged.emit("idle")

    def shutdown(self):
        self.timer.stop()
        if self._thread is not None:
            self.cancel()
            self._thread.join(3)
            if self._thread.is_alive():
                return False
            self._thread = None
            self._result = None
            self.operation = "idle"
        return True
