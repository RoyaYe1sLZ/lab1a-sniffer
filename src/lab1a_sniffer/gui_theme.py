"""浅色工作台主题；界面配色集中管理，不影响抓包及协议逻辑。"""

STYLE = """
QWidget { font-family: 'PingFang SC'; font-size: 12px; color: #243344; }
QMainWindow, QWidget#root { background: #f6f8fa; }
QFrame#appHeader { background: transparent; border: none; }
QLabel#title { color: #182936; font-size: 19px; font-weight: 600; }
QLabel#subtitle, QLabel#formLabel, QLabel#metricCaption { color: #71808f; font-size: 11px; }
QLabel#stateBadge { border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 600; }
QFrame#controls, QFrame#metrics, QFrame#panel, QFrame#flowControls {
    background: #ffffff; border: 1px solid #e0e7ec; border-radius: 9px;
}
QFrame#metricDivider { background: #e3e9ee; border: none; }
QLabel#metricValue { color: #1e3342; font-size: 21px; font-weight: 600; }
QLabel#panelTitle { color: #263b49; font-size: 12px; font-weight: 600; }
QLabel#muted, QLabel#packetCount { color: #798895; font-size: 11px; }
QLabel#packetCount { font-weight: 500; }
QLabel#emptyTitle { color: #415765; font-size: 17px; font-weight: 500; }
QLabel#emptyHint { color: #82909d; font-size: 12px; }
QLabel#banner { background: #fff6e7; color: #936a23; border: 1px solid #f0dfbc;
    border-radius: 7px; padding: 8px 12px; }
QComboBox, QLineEdit { background: #ffffff; border: 1px solid #d5dfe6; border-radius: 6px;
    padding: 6px 9px; min-height: 18px; selection-background-color: #d8eeeb; }
QComboBox { padding-right: 24px; }
QComboBox::drop-down { border: none; width: 23px; }
QComboBox::down-arrow { image: none; }
QComboBox QAbstractItemView { background: white; border: 1px solid #d5dfe6;
    selection-background-color: #e2f2ef; selection-color: #146f72; padding: 4px; }
QComboBox:focus, QLineEdit:focus { border: 1px solid #4aa5a2; }
QComboBox:disabled, QLineEdit:disabled { background: #f5f7f9; color: #8d9ba7; border-color: #e5eaef; }
QPushButton { background: #ffffff; border: 1px solid #d5dfe6; border-radius: 6px;
    padding: 6px 10px; min-height: 18px; font-weight: 500; }
QPushButton:hover { background: #f1f7f7; border-color: #a8cbc9; }
QPushButton:pressed { background: #e3f0ee; }
QPushButton:focus { border-color: #62aaa6; }
QPushButton:disabled { background: #f6f8fa; color: #a3aeb8; border-color: #e5ebef; }
QPushButton#start, QPushButton#stopButton, QPushButton#primaryAction {
    color: white; background: #147e82; border-color: #147e82; font-weight: 600;
}
QPushButton#start:hover, QPushButton#stopButton:hover, QPushButton#primaryAction:hover { background: #106d71; }
QPushButton#start:disabled, QPushButton#stopButton:disabled, QPushButton#primaryAction:disabled {
    background: #dbecea; color: #8aadaa; border-color: #dbecea;
}
QPushButton#quietAction { color: #66808c; background: transparent; border-color: transparent; }
QPushButton#quietAction:hover { color: #147b7e; background: #e9f3f1; border-color: #d5e9e5; }
QPushButton#quietAction:disabled { color: #abb6be; }
QWidget#protocolSelector { background: transparent; }
QPushButton#protocolChip { background: #fbfcfd; border: 1px solid #dce4e9; border-radius: 12px;
    padding: 3px 10px; min-height: 17px; font-size: 11px; font-weight: 500; }
QPushButton#protocolChip:hover { background: #eef7f5; border-color: #a7d0ca; }
QPushButton#protocolChip:checked { background: #147e82; border-color: #147e82; color: white; }
QTabWidget::pane { border: none; background: transparent; }
QTabBar { background: transparent; }
QTabBar::tab { background: transparent; color: #7a8996; padding: 9px 16px 11px;
    border: none; border-bottom: 3px solid transparent; margin-right: 12px; font-size: 12px; }
QTabBar::tab:selected { color: #146c70; border-bottom-color: #148b89; font-weight: 600; }
QTabBar::tab:hover:!selected { color: #3e6f76; border-bottom-color: #c6e1dd; }
QTableView, QTreeWidget { background: #ffffff; alternate-background-color: #fbfcfd;
    border: none; color: #314655; selection-background-color: #ddf0ed;
    selection-color: #1a454b; gridline-color: #f0f3f5; outline: none; }
QTableView::item { padding: 3px 7px; border-bottom: 1px solid #f0f3f5; }
QTreeWidget::item { padding: 4px 5px; }
QTreeWidget::item:selected { background: #ddf0ed; color: #1a454b; }
QHeaderView { background: #f5f8fa; }
QHeaderView::section { background: #f5f8fa; color: #718390; border: none;
    border-bottom: 1px solid #e2e9ed; padding: 7px 8px; font-size: 11px; font-weight: 500; }
QTreeWidget#flowTable, QTreeWidget#flowTimeline { border: 1px solid #e0e7ec; border-radius: 7px; }
QLabel#flowDetail { color: #48616e; background: #eef6f4; border: 1px solid #dcece7;
    border-radius: 7px; padding: 9px 12px; font-size: 11px; }
QLabel#flowSummary { color: #687e8b; font-size: 11px; padding: 4px 0; }
QPlainTextEdit#hexView { background: #1d2c3b; color: #dce6ec; border: none;
    border-radius: 7px; font-family: 'Menlo'; font-size: 11px; selection-background-color: #206e73; }
QSplitter::handle { background: transparent; }
QSplitter::handle:hover { background: #d8e9e6; border-radius: 3px; }
QCheckBox { color: #718390; spacing: 7px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #bccbd2; border-radius: 3px; background: white; }
QCheckBox::indicator:checked { background: #16888a; border-color: #16888a; }
QCheckBox::indicator:disabled { background: #edf1f4; border-color: #d5dfe5; }
QScrollBar:vertical { width: 9px; background: transparent; margin: 2px; }
QScrollBar::handle:vertical { background: #c9d5dc; border-radius: 3px; min-height: 26px; }
QScrollBar::handle:vertical:hover { background: #9fb9bf; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QScrollBar:horizontal { height: 9px; background: transparent; margin: 2px; }
QScrollBar::handle:horizontal { background: #c9d5dc; border-radius: 3px; min-width: 26px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: none; }
QToolTip { color: #314957; background: #ffffff; border: 1px solid #d2e2e5; padding: 6px; }
QMenuBar { background: #f6f8fa; }
QMenu { background: white; border: 1px solid #d5dfe6; padding: 4px; }
QMenu::item { padding: 6px 16px; }
QMenu::item:selected { background: #e2f2ef; color: #147e82; }
"""
