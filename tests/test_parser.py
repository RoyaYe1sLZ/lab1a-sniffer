from dataclasses import replace
import json
import random
import struct
import sys

import pytest

from lab1a_sniffer.formatting import packet_text, packet_to_dict
from lab1a_sniffer.parser import hex_dump, parse_packet, safe_text
from .packet_samples import REQUEST, RESPONSE, ethernet, golden_packets, ipv4, ipv6, packet, tcp, udp


def layer_fields(parsed, layer):
    return {field.name: field.value for item in parsed.layers if item.name == layer for field in item.fields}


def test_ethernet_ipv4_tcp_http_request_fields_and_protocol_membership():
    parsed = parse_packet(golden_packets()["http-request"])
    assert parsed.protocol == "HTTP"
    assert [layer.name for layer in parsed.layers] == ["Ethernet", "IPv4", "TCP", "HTTP"]
    assert parsed.source == "192.0.2.1" and parsed.destination == "198.51.100.2"
    assert (parsed.source_port, parsed.destination_port) == (12345, 8080)
    assert parsed.summary == "GET /lab1a?x=1 HTTP/1.1"
    assert layer_fields(parsed, "TCP")["序列号"] == str(0x01020304)
    assert layer_fields(parsed, "TCP")["标志"] == "ACK,PSH"
    assert layer_fields(parsed, "IPv4")["TTL"] == "64"
    assert layer_fields(parsed, "Ethernet")["源 MAC"] == "66:77:88:99:aa:bb"
    assert layer_fields(parsed, "HTTP")["Host"] == "example.test"
    assert [f.value for f in parsed.layers[-1].fields if f.name == "X-Test"] == ["one", "two"]
    assert all(parsed.matches_protocol(name) for name in ("HTTP", "TCP", "ipv4", "全部"))
    assert not parsed.matches_protocol("UDP")
    assert not parsed.issues


def test_http_response_and_header_boundary_excludes_body():
    parsed = parse_packet(golden_packets()["http-response"])
    assert parsed.summary == "HTTP/1.1 200 OK"
    assert (parsed.source, parsed.destination) == ("198.51.100.2", "192.0.2.1")
    assert layer_fields(parsed, "HTTP")["Content-Length"] == "2"
    assert parsed.layers[-1].length == len(RESPONSE) - 2
    assert not parsed.issues


@pytest.mark.parametrize("port", [80, 443, 8080, 49152])
def test_http_identification_does_not_depend_on_port(port):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(REQUEST, dst=port)))))
    assert parsed.protocol == "HTTP"
    assert not parsed.issues


@pytest.mark.parametrize("payload", [b"\x16\x03\x03\x00\x02xx", b"hello world", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                                     b"GET / HTTP/1.1junk\r\n\r\n"])
def test_port_80_does_not_make_arbitrary_payload_http(payload):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(payload, dst=80)))))
    assert parsed.protocol == "TCP"


@pytest.mark.parametrize("payload", [b"GET / HTTP/1.1", b"GET / HTTP/1.1\r\nHost: ex", b"HTTP/1.1 200 OK\r\n"])
def test_partial_http_headers_are_explicit(payload):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(payload)))))
    assert parsed.protocol == "HTTP"
    assert any(issue.kind == "incomplete" for issue in parsed.issues)
    assert "Host" not in layer_fields(parsed, "HTTP")


@pytest.mark.parametrize("payload", [b"GET / HT", b"HTTP/1."])
def test_partial_start_line_is_not_confirmed_http(payload):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(payload)))))
    assert parsed.protocol == "TCP"
    assert any(issue.kind == "incomplete" for issue in parsed.issues)


@pytest.mark.parametrize("header", [b"Bad Header: x", b" Host: folded", b"NoColon", b"Host: a\x1b[31m"])
def test_bad_http_headers_report_issue(header):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\n" + header + b"\r\n\r\n")))))
    assert parsed.protocol == "HTTP"
    assert any(issue.kind == "malformed" for issue in parsed.issues)


def test_http_header_limit_and_body_are_bounded():
    oversized = b"GET / HTTP/1.1\r\nX-Long: " + b"x" * 20000
    parsed = parse_packet(packet(ethernet(ipv4(tcp(oversized)))))
    assert parsed.layers[-1].length <= 16384
    assert any(issue.kind == "limit" for issue in parsed.issues)
    body = b"POST / HTTP/1.1\r\nContent-Length: 20000\r\n\r\n" + b"x" * 20000
    parsed = parse_packet(packet(ethernet(ipv4(tcp(body)))))
    assert not parsed.issues
    assert parsed.layers[-1].length < 100
    huge_line = b"GET /" + b"x" * 20000
    parsed = parse_packet(packet(ethernet(ipv4(tcp(huge_line)))))
    assert parsed.protocol == "TCP"
    assert any(issue.kind == "limit" for issue in parsed.issues)


def test_http_field_count_is_bounded():
    headers = b"GET / HTTP/1.1\r\n" + b"X: a\r\n" * 200 + b"\r\n"
    parsed = parse_packet(packet(ethernet(ipv4(tcp(headers)))))
    assert len(parsed.layers[-1].fields) == 129  # 起始行 + 最多 128 项。
    assert any(issue.kind == "limit" for issue in parsed.issues)


@pytest.mark.parametrize("family", [24, 28, 30])
def test_null_ipv6_family_and_byte_order(family):
    raw = family.to_bytes(4, sys.byteorder) + ipv6(udp())
    parsed = parse_packet(packet(raw, linktype=0))
    assert [layer.name for layer in parsed.layers] == ["NULL", "IPv6", "UDP"]
    assert parsed.source == "2001:db8::1"
    assert not parsed.issues


@pytest.mark.parametrize("linktype,header", [(0, (2).to_bytes(4, sys.byteorder)), (108, (2).to_bytes(4, "big"))])
def test_null_and_loop_ipv4(linktype, header):
    parsed = parse_packet(packet(header + ipv4(udp(), protocol=17), linktype=linktype))
    assert parsed.protocol == "UDP"
    assert parsed.destination_port == 54321
    assert not parsed.issues


@pytest.mark.parametrize("kind,network", [(12, ipv4(udp(), protocol=17)), (101, ipv6(udp())),
                                       (228, ipv4(udp(), protocol=17)), (229, ipv6(udp()))])
def test_raw_ip_linktypes(kind, network):
    parsed = parse_packet(packet(network, linktype=kind))
    assert parsed.protocol == "UDP"
    assert not parsed.issues


def test_vlan_encapsulation_and_offsets():
    frame = ethernet(struct.pack("!HH", 123, 0x0800) + ipv4(tcp(REQUEST)), ethertype=0x8100)
    parsed = parse_packet(packet(frame))
    assert [layer.name for layer in parsed.layers] == ["Ethernet", "VLAN", "IPv4", "TCP", "HTTP"]
    assert layer_fields(parsed, "VLAN")["VLAN ID"] == "123"
    assert parsed.layers[2].offset == 18
    assert not parsed.issues


def test_ipv4_and_tcp_options_control_actual_payload_offset():
    frame = ethernet(ipv4(tcp(REQUEST, options=b"\x02\x04\x05\xb4"), options=b"\x01" * 4))
    parsed = parse_packet(packet(frame))
    assert parsed.protocol == "HTTP"
    assert [layer.offset for layer in parsed.layers] == [0, 14, 38, 62]
    assert layer_fields(parsed, "TCP")["头部长度"] == "24"
    assert not parsed.issues


def test_ethernet_padding_is_not_tcp_payload():
    parsed = parse_packet(packet(ethernet(ipv4(tcp())) + REQUEST))
    assert parsed.protocol == "TCP"
    assert not parsed.issues


@pytest.mark.parametrize("fragment", [0x2000, 1, 0x2001])
def test_ipv4_fragments_do_not_claim_transport_or_application_protocol(fragment):
    parsed = parse_packet(packet(ethernet(ipv4(tcp(REQUEST), fragment=fragment))))
    assert parsed.protocol == "IPv4"
    assert not parsed.matches_protocol("TCP")
    assert any(issue.kind == "fragmented" for issue in parsed.issues)


@pytest.mark.parametrize("extension", [0, 43, 60])
def test_ipv6_extension_header_is_skipped_using_its_length(extension):
    extension_data = bytes([17, 0]) + bytes(6)
    parsed = parse_packet(packet(ethernet(ipv6(extension_data + udp(), following=extension), ethertype=0x86DD)))
    assert parsed.protocol == "UDP"
    assert parsed.layers[-1].offset == 14 + 40 + 8
    assert not parsed.issues


@pytest.mark.parametrize("flags", [1, 8, 9])
def test_ipv6_fragments_stop_before_transport(flags):
    fragment = struct.pack("!BBHI", 6, 0, flags, 123)
    parsed = parse_packet(packet(ethernet(ipv6(fragment + tcp(REQUEST), following=44), ethertype=0x86DD)))
    assert not parsed.matches_protocol("TCP")
    assert any(issue.kind == "fragmented" for issue in parsed.issues)


def test_ipv6_atomic_fragment_can_continue_to_tcp():
    fragment = struct.pack("!BBHI", 6, 0, 0, 123)
    parsed = parse_packet(packet(ipv6(fragment + tcp(REQUEST), following=44), linktype=12))
    assert parsed.protocol == "HTTP"
    assert not parsed.issues


@pytest.mark.parametrize("following,kind", [(50, "encrypted"), (51, "unsupported"), (132, "unsupported")])
def test_unhandled_ipv6_protocols_are_explicit(following, kind):
    parsed = parse_packet(packet(ipv6(b"x" * 16, following=following), linktype=12))
    assert any(issue.kind == kind for issue in parsed.issues)
    assert not parsed.matches_protocol("TCP")


def test_extension_nesting_limit():
    extensions = (bytes([0, 0]) + bytes(6)) * 9
    parsed = parse_packet(packet(ipv6(extensions + udp(), following=0), linktype=12))
    assert any(issue.kind == "limit" for issue in parsed.issues)


def test_ipv6_no_next_header_and_jumbogram_boundary():
    assert not parse_packet(packet(ipv6(b"", following=59), linktype=12)).issues
    parsed = parse_packet(packet(ipv6(b"", following=0) + bytes(100), linktype=12))
    assert any(issue.kind == "unsupported" for issue in parsed.issues)
    assert parsed.protocol == "IPv6"


@pytest.mark.parametrize("key,protocol,sequence", [("icmp-echo", "ICMP", "7"), ("icmp6-echo", "ICMPv6", "9")])
def test_icmp_echo_identifiers_and_sequences(key, protocol, sequence):
    parsed = parse_packet(golden_packets()[key])
    assert parsed.protocol == protocol
    assert "Echo Request" in parsed.summary
    assert layer_fields(parsed, protocol)["标识符"] == str(0x1234)
    assert layer_fields(parsed, protocol)["序号"] == sequence
    assert not parsed.issues


def test_icmp_error_does_not_discover_embedded_tcp_as_actual_transport():
    embedded = ipv4(tcp(REQUEST))
    error = struct.pack("!BBHI", 3, 1, 0, 0) + embedded
    parsed = parse_packet(packet(ethernet(ipv4(error, protocol=1))))
    assert parsed.protocol == "ICMP"
    assert not parsed.matches_protocol("TCP")


@pytest.mark.parametrize("network,position,value", [
    (ipv4(tcp()), 0, b"\x44"),
    (ipv4(tcp()), 2, b"\x00\x13"),
    (ipv4(tcp()), 20 + 12, b"\x40"),
    (ipv4(tcp()), 20 + 12, b"\xf0"),
    (ipv4(udp(), protocol=17), 20 + 4, b"\x00\x07"),
    (ipv4(udp(), protocol=17), 20 + 4, b"\xff\xff"),
])
def test_malformed_declared_header_lengths(network, position, value):
    data = network[:position] + value + network[position + len(value):]
    parsed = parse_packet(packet(data, linktype=12))
    assert any(issue.kind == "malformed" for issue in parsed.issues)


def test_truncated_payload_preserves_visible_transport_fields():
    data = ethernet(ipv4(udp(b"x" * 50), protocol=17))
    parsed = parse_packet(packet(data[:-30], wire_length=len(data)))
    assert parsed.protocol == "UDP"
    assert parsed.destination_port == 54321
    assert any(issue.kind == "truncated" for issue in parsed.issues)


def test_every_capture_prefix_of_golden_packets_is_safe_and_fields_stay_in_bounds():
    for original in golden_packets().values():
        for size in range(len(original.data) + 1):
            parsed = parse_packet(replace(original, data=original.data[:size]))
            for layer in parsed.layers:
                assert 0 <= layer.offset <= size
                assert 0 <= layer.length <= size - layer.offset
                for field in layer.fields:
                    assert 0 <= field.offset <= size
                    assert 0 <= field.length <= size - field.offset
            assert all(0 <= issue.offset <= size for issue in parsed.issues)


def test_deterministic_random_untrusted_input_does_not_raise():
    rng = random.Random(20261111)
    for _ in range(1500):
        data = rng.randbytes(rng.randrange(0, 512))
        linktype = rng.choice([0, 1, 12, 101, 108, 228, 229, 9999])
        parsed = parse_packet(packet(data, linktype=linktype))
        assert parsed.raw.data == data


def test_unsupported_link_and_address_family_do_not_guess():
    for original in [packet(b"anything", linktype=9999), packet(bytes(4), linktype=0),
                     packet(ethernet(bytes(20), ethertype=0x0806))]:
        assert any(issue.kind == "unsupported" for issue in parse_packet(original).issues)


def test_json_text_and_hex_are_safe_and_preserve_raw_bytes():
    original = golden_packets()["http-request"]
    parsed = parse_packet(original)
    report = packet_to_dict(parsed)
    assert json.loads(json.dumps(report))["source_port"] == 12345
    assert "Host: example.test" in packet_text(parsed, details=True)
    assert "00000000" in packet_text(parsed, show_hex=True)
    assert safe_text(b"x\x1b\n\x9b") == "x\\x1b\\x0a\\x9b"
    rendered = hex_dump(b"\x00\xffhello" * 1000, limit=32)
    assert "省略" in rendered and "|..hello" in rendered
    assert parsed.raw == original
