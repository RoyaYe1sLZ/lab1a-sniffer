from dataclasses import replace
import socket
import sys
import threading
import time
import os

import pytest
from lab1a_sniffer.processes import (ProcessIdentity, SocketSnapshot, parse_lsof, collect_snapshot, _run)
from lab1a_sniffer.flows import FlowTracker, endpoint, connection_key
from lab1a_sniffer.gui_processes import ProcessController
from .test_flows import segment, add
from .test_gui import wait_for


def test_lsof_fields_ipv4_ipv6_shared_socket_listeners_and_invalid_names():
    result = parse_lsof('p12\ncBrowser Helper\nf4\nn192.0.2.1:45678->198.51.100.2:443\n'
                        'f5\nn*:80\nf6\nn[2001:db8::1]:50000->[2001:db8::2]:443\n'
                        'p13\ncOther\nn192.0.2.1:45678->198.51.100.2:443\n'
                        'n127.0.0.1:123->invalid:443\npBAD\ncBad\nn192.0.2.1:1->198.51.100.2:2\n')
    assert len(result) == 2
    assert len(result[connection_key(endpoint('192.0.2.1', 45678), endpoint('198.51.100.2', 443))]) == 2
    assert len(result[connection_key(endpoint('2001:db8::1', 50000), endpoint('2001:db8::2', 443))]) == 1


def test_socket_snapshot_matches_full_tuple_time_and_preserves_history():
    tracker = FlowTracker()
    add(tracker, segment(), segment(port=45679))
    flow = tracker.flows[1]
    owner = ProcessIdentity(10, 'Python', 'start 1')
    stamp = flow.last_us
    snapshot = SocketSnapshot(stamp, stamp + 1000, {flow.key: {owner}})
    assert tracker.associate(snapshot)
    assert owner in flow.owners and not tracker.flows[2].owners
    assert not tracker.associate(SocketSnapshot(stamp, stamp + 2000, {}))
    assert owner in flow.owners
    old = FlowTracker(); add(old, segment())
    assert not old.associate(replace(snapshot, started_us=stamp + 3_000_000, ended_us=stamp + 3_000_100))
    future = FlowTracker(); add(future, segment())
    assert not future.associate(replace(snapshot, ended_us=stamp - 1))
    assert owner != replace(owner, started='start 2')


def test_subprocess_timeout_cancellation_and_failure_cleanup():
    with pytest.raises(TimeoutError):
        _run([sys.executable, '-c', 'import time; time.sleep(10)'], lambda: False, timeout=.1)
    cancel = threading.Event()
    timer = threading.Timer(.1, cancel.set); timer.start()
    try:
        with pytest.raises(InterruptedError):
            _run([sys.executable, '-c', 'import time; time.sleep(10)'], cancel.is_set)
    finally:
        timer.join()
    with pytest.raises(FileNotFoundError):
        _run(['/no-such-lsof'], lambda: False)


def test_async_monitor_keeps_qt_responsive_and_cancels(qapp):
    entered = threading.Event()
    def slow(cancelled):
        entered.set()
        while not cancelled(): time.sleep(.005)
        raise InterruptedError()
    monitor = ProcessController(scanner=slow)
    monitor.set_enabled(True)
    wait_for(entered.is_set)
    monitor.set_enabled(False)
    wait_for(lambda: not monitor.is_busy)
    assert monitor.shutdown()
    assert not any(t.name == 'pcap-process-snapshot' for t in threading.enumerate())


@pytest.mark.live
def test_real_current_process_socket_snapshot():
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0)); server.listen()
        with socket.create_connection(server.getsockname()) as client:
            accepted, _ = server.accept()
            with accepted:
                result = collect_snapshot()
                key = connection_key(endpoint(*client.getsockname()), endpoint(*client.getpeername()))
                assert any(p.pid == os.getpid() and p.started for p in result.connections[key])


def test_pid_changed_during_snapshot_is_not_attributed(monkeypatch):
    import lab1a_sniffer.processes as module
    responses = iter([(0, ' 10 Thu Nov 12 00:00:00 2026\n', ''),
                      (0, 'p10\ncOld\nn192.0.2.1:45678->198.51.100.2:443\n', ''),
                      (0, ' 10 Thu Nov 12 00:00:01 2026\n', '')])
    monkeypatch.setattr(module, '_run', lambda *a, **kw: next(responses))
    snapshot = module.collect_snapshot()
    assert not any(snapshot.connections.values())


def test_process_query_errors_are_reported_without_stopping_monitor(qapp):
    def failing(cancelled):
        raise PermissionError('denied')
    messages = []
    monitor = ProcessController(scanner=failing)
    monitor.statusChanged.connect(messages.append)
    monitor.set_enabled(True)
    wait_for(lambda: bool(messages))
    assert 'denied' in messages[0]
    assert monitor.shutdown()
