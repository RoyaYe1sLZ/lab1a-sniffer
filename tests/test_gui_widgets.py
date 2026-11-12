"""协议标签替换下拉框后，真实点击与键盘仍需驱动同一显示过滤逻辑。"""
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from .test_gui_files import file_window, sample_file
from .test_gui import wait_for


def test_protocol_chips_filter_and_keep_all_source_packets(file_window, tmp_path):
    w = file_window
    w.open_file(sample_file(tmp_path))
    wait_for(lambda: not w.files.is_active)
    QTest.mouseClick(w.display_filter.buttons['HTTP'], Qt.MouseButton.LeftButton)
    assert w.proxy.rowCount() == 2 and w.model.rowCount() == 5
    assert w.display_filter.currentText() == 'HTTP'
    assert sum(b.isChecked() for b in w.display_filter.buttons.values()) == 1
    QTest.mouseClick(w.display_filter.buttons['UDP'], Qt.MouseButton.LeftButton)
    assert w.proxy.rowCount() == 1 and w.current_packet.protocol == 'UDP'
    QTest.mouseClick(w.display_filter.buttons['全部'], Qt.MouseButton.LeftButton)
    assert w.proxy.rowCount() == 5


def test_protocol_selector_keyboard_and_global_file_actions(file_window, tmp_path):
    w = file_window
    w.open_file(sample_file(tmp_path))
    wait_for(lambda: not w.files.is_active)
    selector = w.display_filter
    selector.setFocus()
    QTest.keyClick(selector, Qt.Key.Key_Home)
    QTest.keyClick(selector, Qt.Key.Key_Down)
    assert selector.currentText() == 'HTTP' and w.proxy.rowCount() == 2
    QTest.keyClick(selector, Qt.Key.Key_End)
    assert selector.currentText() == 'ICMPv6' and w.proxy.rowCount() == 1
    for key, expected in [('captured', '5'), ('visible', '1'), ('flows', '1')]:
        assert w.metric_labels[key].text() == expected
    w.tabs.setCurrentIndex(1)
    assert w.open_button.isVisible() and w.save_button.isVisible()
