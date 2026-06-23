"""Heuristic anomaly detectors.

These are deliberately simple, explainable thresholds rather than ML models so
the behavior is easy to reason about in an interview:

* **PortScanDetector** - one source hitting many distinct destination ports on
  the same host within a time window (classic horizontal/vertical scan).
* **SynFloodDetector** - a flood of TCP SYN packets toward a victim without the
  matching ACKs that complete a handshake.

Each detector consumes the same :class:`PacketRecord` stream as the analyzer
and emits :class:`Alert` objects.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Set, Tuple

from .models import PacketRecord


@dataclass
class Alert:
    severity: str       # "low" | "medium" | "high"
    kind: str
    source: str
    detail: str
    timestamp: float

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "source": self.source,
            "detail": self.detail,
            "timestamp": round(self.timestamp, 3),
        }


@dataclass
class PortScanDetector:
    """Flag a source that probes more than ``port_threshold`` distinct ports on
    a single destination within ``window_seconds``."""

    port_threshold: int = 15
    window_seconds: float = 5.0
    # (src, dst) -> deque[(timestamp, port)]
    _seen: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _fired: Set[Tuple[str, str]] = field(default_factory=set)

    def feed(self, rec: PacketRecord) -> List[Alert]:
        if rec.protocol != "TCP" or rec.dst_port is None:
            return []
        key = (rec.src_ip, rec.dst_ip)
        window = self._seen[key]
        window.append((rec.timestamp, rec.dst_port))

        cutoff = rec.timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        distinct_ports = {p for _, p in window}
        if len(distinct_ports) >= self.port_threshold and key not in self._fired:
            self._fired.add(key)
            return [Alert(
                severity="high", kind="port_scan", source=rec.src_ip,
                detail=(f"{rec.src_ip} probed {len(distinct_ports)} distinct ports "
                        f"on {rec.dst_ip} within {self.window_seconds:.0f}s"),
                timestamp=rec.timestamp,
            )]
        return []


@dataclass
class SynFloodDetector:
    """Flag a victim receiving a burst of unanswered TCP SYNs."""

    syn_threshold: int = 30
    window_seconds: float = 3.0
    _syn_times: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _fired: Set[str] = field(default_factory=set)

    def feed(self, rec: PacketRecord) -> List[Alert]:
        if rec.protocol != "TCP" or not rec.tcp_flags:
            return []
        # SYN set but ACK not set -> half-open connection attempt.
        is_syn_only = "S" in rec.tcp_flags and "A" not in rec.tcp_flags
        if not is_syn_only:
            return []

        window = self._syn_times[rec.dst_ip]
        window.append(rec.timestamp)
        cutoff = rec.timestamp - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.syn_threshold and rec.dst_ip not in self._fired:
            self._fired.add(rec.dst_ip)
            return [Alert(
                severity="high", kind="syn_flood", source=rec.dst_ip,
                detail=(f"{len(window)} half-open SYNs to {rec.dst_ip} within "
                        f"{self.window_seconds:.0f}s (possible SYN flood)"),
                timestamp=rec.timestamp,
            )]
        return []


class DetectorPipeline:
    """Run every registered detector against each packet."""

    def __init__(self, detectors=None):
        self.detectors = detectors or [PortScanDetector(), SynFloodDetector()]
        self.alerts: List[Alert] = []

    def feed(self, rec: PacketRecord) -> List[Alert]:
        new_alerts: List[Alert] = []
        for det in self.detectors:
            new_alerts.extend(det.feed(rec))
        self.alerts.extend(new_alerts)
        return new_alerts
