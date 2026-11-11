import sys
import os

import pytest


def pytest_addoption(parser):
    parser.addoption("--run-live", action="store_true", help="运行真实抓包验收")
    parser.addoption("--physical-interface", default="en0", help="验收物理网卡，默认 en0")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "live" in item.keywords:
            if not config.getoption("--run-live"):
                item.add_marker(pytest.mark.skip(reason="真实抓包需要显式传入 --run-live"))
            elif sys.platform != "darwin":
                item.add_marker(pytest.mark.skip(reason="当前抓包封装仅支持 macOS"))


@pytest.fixture(scope="session")
def qapp():
    # 常规测试使用无屏幕平台；原生 Cocoa 视觉验收另在独立进程执行。
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from lab1a_sniffer.gui import create_application
    app = create_application()
    app.setQuitOnLastWindowClosed(False)
    yield app
    app.processEvents()
