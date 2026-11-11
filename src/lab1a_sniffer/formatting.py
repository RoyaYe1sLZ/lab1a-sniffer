"""CLI 与后续 GUI 共用的可读展示数据，不包含原生指针。"""

from dataclasses import asdict

from .models import ParsedPacket
from .parser import hex_dump


def packet_to_dict(packet: ParsedPacket) -> dict:
    return {
        "timestamp_us": packet.raw.timestamp_us,
        "linktype": packet.raw.linktype,
        "captured_length": packet.raw.captured_length,
        "wire_length": packet.raw.wire_length,
        "protocol": packet.protocol,
        "protocols": [layer.name for layer in packet.layers],
        "source": packet.source, "destination": packet.destination,
        "source_port": packet.source_port, "destination_port": packet.destination_port,
        "summary": packet.summary,
        "layers": [asdict(layer) for layer in packet.layers],
        "issues": [asdict(issue) for issue in packet.issues],
    }


def _endpoint(address: str, port: int | None) -> str:
    if port is None:
        return address or "?"
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def packet_text(packet: ParsedPacket, *, details: bool = False, show_hex: bool = False) -> str:
    source = _endpoint(packet.source, packet.source_port)
    destination = _endpoint(packet.destination, packet.destination_port)
    lines = [f"{packet.protocol} {source} → {destination} | {packet.summary}"]
    if details:
        for layer in packet.layers:
            lines.append(f"  {layer.name} [偏移 {layer.offset}，头部 {layer.length} 字节]")
            for field in layer.fields:
                lines.append(f"    {field.name}: {field.value}")
    for issue in packet.issues:
        lines.append(f"  提示 [{issue.kind} @ {issue.offset}]: {issue.message}")
    if show_hex:
        lines.append(hex_dump(packet.raw.data))
    return "\n".join(lines)
