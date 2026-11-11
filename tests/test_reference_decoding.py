import subprocess
import sys

import pytest

from lab1a_sniffer.models import CaptureInfo
from lab1a_sniffer.parser import parse_packet
from lab1a_sniffer.pcap import write_pcap
from .packet_samples import golden_packets


@pytest.mark.skipif(sys.platform != "darwin", reason="使用 macOS 系统 libpcap 与 tcpdump")
def test_golden_protocol_fields_agree_with_independent_tcpdump(tmp_path):
    samples = golden_packets()
    path = tmp_path / "reference.pcap"
    write_pcap(path, samples.values(), CaptureInfo("reference", 1, "EN10MB", 65535))
    result = subprocess.run(
        ["/usr/sbin/tcpdump", "-nn", "-S", "-vv", "-r", str(path)],
        capture_output=True, text=True, timeout=5, check=True,
    )
    output = result.stdout
    assert "192.0.2.1.12345 > 198.51.100.2.8080" in output
    assert "198.51.100.2.8080 > 192.0.2.1.12345" in output
    assert "seq 16909060:" in output and "ack 84281096" in output
    assert "ttl 64" in output and "hlim 32" in output
    assert "2001:db8::1.12345 > 2001:db8::2.54321" in output
    assert "echo request, id 4660, seq 7" in output
    assert "echo request, id 4660, seq 9" in output
    assert "incorrect" not in output and "bad cksum" not in output
    assert [parse_packet(p).protocol for p in samples.values()] == ["HTTP", "HTTP", "UDP", "ICMP", "ICMPv6"]
    assert not any(parse_packet(p).issues for p in samples.values())
