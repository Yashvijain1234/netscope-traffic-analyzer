"""Streaming traffic statistics engine.

``TrafficAnalyzer`` consumes :class:`PacketRecord` objects one at a time and
maintains running aggregates: protocol mix, byte/packet counts, top talkers,
busiest conversations, port usage, and a per-second throughput timeline. It is
intentionally O(1) per packet so it can keep up with a live capture.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .models import PacketRecord


@dataclass
class TrafficAnalyzer:
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    protocol_packets: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    app_protocols: Counter = field(default_factory=Counter)

    bytes_by_src: Counter = field(default_factory=Counter)
    bytes_by_dst: Counter = field(default_factory=Counter)
    packets_by_flow: Counter = field(default_factory=Counter)
    bytes_by_flow: Counter = field(default_factory=Counter)
    dst_port_hits: Counter = field(default_factory=Counter)

    # Throughput timeline keyed by integer second offset from start.
    _bytes_per_second: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    def update(self, rec: PacketRecord) -> None:
        if self.total_packets == 0:
            self.start_time = rec.timestamp
        self.end_time = rec.timestamp

        self.total_packets += 1
        self.total_bytes += rec.length

        self.protocol_packets[rec.protocol] += 1
        self.protocol_bytes[rec.protocol] += rec.length
        if rec.app_protocol:
            self.app_protocols[rec.app_protocol] += 1

        self.bytes_by_src[rec.src_ip] += rec.length
        self.bytes_by_dst[rec.dst_ip] += rec.length
        self.packets_by_flow[rec.flow_key] += 1
        self.bytes_by_flow[rec.flow_key] += rec.length
        if rec.dst_port is not None:
            self.dst_port_hits[rec.dst_port] += 1

        second = int(rec.timestamp - self.start_time)
        self._bytes_per_second[second] += rec.length

    # ----- derived metrics -------------------------------------------------
    @property
    def duration(self) -> float:
        return max(self.end_time - self.start_time, 1e-6)

    @property
    def avg_packet_size(self) -> float:
        return self.total_bytes / self.total_packets if self.total_packets else 0.0

    @property
    def throughput_bps(self) -> float:
        """Average throughput in bits per second over the capture window."""
        return (self.total_bytes * 8) / self.duration

    @property
    def peak_bps(self) -> float:
        if not self._bytes_per_second:
            return 0.0
        return max(self._bytes_per_second.values()) * 8

    def top_talkers(self, n: int = 5) -> List[Tuple[str, int]]:
        return self.bytes_by_src.most_common(n)

    def top_destinations(self, n: int = 5) -> List[Tuple[str, int]]:
        return self.bytes_by_dst.most_common(n)

    def top_flows(self, n: int = 5) -> List[Tuple[tuple, int]]:
        return self.bytes_by_flow.most_common(n)

    def top_ports(self, n: int = 5) -> List[Tuple[int, int]]:
        return self.dst_port_hits.most_common(n)

    def summary(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(self.duration, 3),
            "avg_packet_size_bytes": round(self.avg_packet_size, 2),
            "throughput_bps": round(self.throughput_bps, 2),
            "peak_bps": round(self.peak_bps, 2),
            "protocol_packets": dict(self.protocol_packets),
            "protocol_bytes": dict(self.protocol_bytes),
            "app_protocols": dict(self.app_protocols),
            "top_talkers": self.top_talkers(),
            "top_destinations": self.top_destinations(),
            "top_ports": self.top_ports(),
        }
