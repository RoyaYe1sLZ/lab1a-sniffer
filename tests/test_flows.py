"""连接索引使用独立构造的 TCP 报文；不依赖摘要文字判断状态。"""
from dataclasses import replace
import struct

from lab1a_sniffer.flows import FlowTracker, tcp_segment
from lab1a_sniffer.parser import parse_packet
from .packet_samples import ethernet, ipv4, ipv6, packet, golden_packets


def segment(seq=100, ack=0, flags=2, *, reverse=False, port=45678, payload=b"", us=0, v6=False):
    sport, dport = (443, port) if reverse else (port, 443)
    rawtcp = struct.pack('!HHIIHHHH', sport, dport, seq, ack, (5 << 12) | flags, 4096, 0, 0) + payload
    if v6:
        ip = ipv6(rawtcp, following=6)
        if reverse:
            ip = ip[:8] + ip[24:40] + ip[8:24] + ip[40:]
        raw = packet(ethernet(ip, ethertype=0x86DD))
    else:
        a, b = ('198.51.100.2', '192.0.2.1') if reverse else ('192.0.2.1', '198.51.100.2')
        raw = packet(ethernet(ipv4(rawtcp, source=a, destination=b)))
    return parse_packet(replace(raw, microseconds=us))


def add(tracker, *packets):
    for packet in packets:
        tracker.add(len(tracker.row_flow), packet)


def test_bidirectional_handshake_ecn_and_counters():
    tracker = FlowTracker()
    add(tracker, segment(flags=0xC2, us=10), segment(700, 101, 0x52, reverse=True, us=1010),
        segment(101, 701, 16, us=1110), segment(101, 701, 24, payload=b'hello', us=2010))
    flow = tracker.flows[1]
    assert flow.state == '已见三次握手' and flow.handshake_us == 1100
    assert flow.rows == [0, 1, 2, 3] and flow.counts == [3, 1]
    assert flow.payload_bytes == [5, 0]
    assert flow.a.port == 45678 and flow.b.port == 443


def test_syn_retransmission_and_port_reuse_create_correct_generations():
    tracker = FlowTracker()
    add(tracker, segment(), segment(), segment(200))
    assert len(tracker.flows) == 2
    assert tracker.flows[1].rows == [0, 1] and tracker.flows[2].rows == [2]
    add(tracker, segment(201, 0, 4), segment(200))
    assert len(tracker.flows) == 3 and tracker.flows[2].state == 'RST 结束'


def test_connections_with_different_ports_and_ipv6_are_distinct():
    tracker = FlowTracker()
    add(tracker, segment(), segment(port=45679), segment(v6=True), segment(reverse=True, v6=True, flags=18, ack=101))
    assert len(tracker.flows) == 3
    assert tracker.flows[3].counts == [1, 1]


def test_midstream_does_not_claim_handshake_and_synack_first_orients_initiator():
    tracker = FlowTracker()
    add(tracker, segment(100, 500, 24))
    assert tracker.flows[1].state == '中途捕获'
    other = FlowTracker()
    add(other, segment(700, 101, 18, reverse=True), segment(101, 701, 16))
    assert other.flows[1].a.port == 45678
    assert not other.flows[1].established


def test_wrong_ack_never_claims_completed_handshake():
    tracker = FlowTracker()
    add(tracker, segment(), segment(700, 999, 18, reverse=True), segment(101, 701, 16))
    assert not tracker.flows[1].established


def test_four_way_close_requires_fin_acknowledgements_and_handles_wrap():
    tracker = FlowTracker()
    add(tracker, segment(0xFFFFFFFF, 0, 1), segment(10, 0, 16, reverse=True))
    flow = tracker.flows[1]
    assert flow.state == '关闭中'
    add(tracker, segment(10, 0, 17, reverse=True))
    assert flow.state == '关闭中'
    add(tracker, segment(0, 11, 16))
    assert flow.state == 'FIN 已确认'


def test_rejected_handshake_ack_and_truncated_payload_dont_invent_close():
    p = segment(100, 0, 1, payload=b'long')
    raw = replace(p.raw, data=p.raw.data[:-2])
    short = parse_packet(raw)
    tracker = FlowTracker()
    add(tracker, short)
    assert not tracker.flows[1].fin


def test_payload_length_excludes_ethernet_padding():
    p = segment(payload=b'abc')
    padded = parse_packet(replace(p.raw, data=p.raw.data + b'\0' * 30, wire_length=p.raw.wire_length + 30))
    assert tcp_segment(padded).payload_length == 3


def test_index_caps_do_not_discard_source_packets():
    tracker = FlowTracker(max_flows=1, max_packets=2)
    for i, p in enumerate([segment(), segment(port=45679), segment(), segment()]):
        tracker.add(i, p)
    assert len(tracker.flows) == 1 and tracker.row_flow == {0: 1, 2: 1} and tracker.untracked == 2
    assert tcp_segment(parse_packet(golden_packets()['icmp-echo'])) is None


def test_wrong_final_sequence_never_claims_handshake_and_syn_data_uses_sequence_space():
    tracker = FlowTracker()
    add(tracker, segment(), segment(700, 101, 18, reverse=True), segment(999, 701, 16))
    assert not tracker.flows[1].established
    tracker = FlowTracker()
    add(tracker, segment(payload=b'abc'), segment(700, 104, 18, reverse=True), segment(104, 701, 16))
    assert tracker.flows[1].established
