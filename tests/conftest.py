import sys

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
