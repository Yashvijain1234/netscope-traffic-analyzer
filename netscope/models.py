"""Core data structures shared across NetScope modules.

A ``PacketRecord`` is a normalized, library-agnostic view of a single packet.
Decoupling the rest of the pipeline from Scapy keeps the analyzer and detectors
easy to unit test and lets the simulation backend run without root access or a
live network interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str           # "TCP", "UDP", "ICMP", "ARP", "OTHER"
    length: int             # total frame length in bytes
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None   # e.g. "S", "SA", "PA"
    app_protocol: Optional[str] = None  # best-effort L7 guess: "DNS", "HTTP", "HTTPS", "TLS"

    @property
    def flow_key(self) -> tuple:
        """Bidirectional-agnostic 5-tuple used to group a conversation."""
        endpoints = sorted([
            (self.src_ip, self.src_port or 0),
            (self.dst_ip, self.dst_port or 0),
        ])
        return (endpoints[0], endpoints[1], self.protocol)
