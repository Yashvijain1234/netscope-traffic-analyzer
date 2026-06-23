"""Tests for the anomaly detectors and detector pipeline."""

from netscope.models import PacketRecord
from netscope.detectors import (
    PortScanDetector,
    SynFloodDetector,
    DetectorPipeline,
)


def _tcp(src, dst, dport, flags="S", ts=0.0, sport=40000):
    return PacketRecord(
        timestamp=ts, src_ip=src, dst_ip=dst, protocol="TCP", length=60,
        src_port=sport, dst_port=dport, tcp_flags=flags,
    )


class TestPortScanDetector:
    def test_fires_when_distinct_ports_exceed_threshold(self):
        det = PortScanDetector(port_threshold=10, window_seconds=5.0)
        alerts = []
        for port in range(10):
            alerts += det.feed(_tcp("1.1.1.1", "2.2.2.2", dport=port, ts=port * 0.1))
        assert len(alerts) == 1
        assert alerts[0].kind == "port_scan"
        assert alerts[0].severity == "high"
        assert alerts[0].source == "1.1.1.1"

    def test_does_not_fire_below_threshold(self):
        det = PortScanDetector(port_threshold=10)
        alerts = []
        for port in range(9):
            alerts += det.feed(_tcp("1.1.1.1", "2.2.2.2", dport=port))
        assert alerts == []

    def test_repeated_same_port_does_not_count(self):
        """Hitting the same port many times is not a scan."""
        det = PortScanDetector(port_threshold=5)
        alerts = []
        for _ in range(20):
            alerts += det.feed(_tcp("1.1.1.1", "2.2.2.2", dport=80))
        assert alerts == []

    def test_old_probes_age_out_of_window(self):
        """Ports seen outside the time window should not accumulate."""
        det = PortScanDetector(port_threshold=5, window_seconds=2.0)
        alerts = []
        # Space probes 10s apart -> only one ever in the 2s window.
        for i in range(10):
            alerts += det.feed(_tcp("1.1.1.1", "2.2.2.2", dport=i, ts=i * 10.0))
        assert alerts == []

    def test_fires_only_once_per_pair(self):
        det = PortScanDetector(port_threshold=3)
        alerts = []
        for port in range(20):
            alerts += det.feed(_tcp("1.1.1.1", "2.2.2.2", dport=port, ts=port * 0.01))
        assert len(alerts) == 1

    def test_ignores_non_tcp(self):
        det = PortScanDetector(port_threshold=2)
        udp = PacketRecord(0.0, "1.1.1.1", "2.2.2.2", "UDP", 60, 40000, 53)
        assert det.feed(udp) == []


class TestSynFloodDetector:
    def test_fires_on_syn_burst(self):
        det = SynFloodDetector(syn_threshold=20, window_seconds=3.0)
        alerts = []
        for i in range(20):
            alerts += det.feed(_tcp("attacker", "victim", dport=80, flags="S", ts=i * 0.01))
        assert len(alerts) == 1
        assert alerts[0].kind == "syn_flood"
        assert alerts[0].source == "victim"

    def test_completed_handshakes_do_not_count(self):
        """SYN-ACK packets are not half-open and must be ignored."""
        det = SynFloodDetector(syn_threshold=5)
        alerts = []
        for i in range(50):
            alerts += det.feed(_tcp("a", "victim", dport=80, flags="SA", ts=i * 0.01))
        assert alerts == []

    def test_slow_syns_age_out(self):
        det = SynFloodDetector(syn_threshold=5, window_seconds=1.0)
        alerts = []
        for i in range(20):
            alerts += det.feed(_tcp("a", "victim", dport=80, flags="S", ts=i * 5.0))
        assert alerts == []


class TestDetectorPipeline:
    def test_aggregates_alerts_from_all_detectors(self):
        pipeline = DetectorPipeline([
            PortScanDetector(port_threshold=3, window_seconds=5.0),
            SynFloodDetector(syn_threshold=3, window_seconds=5.0),
        ])
        # A single scanning source hitting many ports triggers BOTH a port scan
        # (many distinct ports) and a SYN flood (many half-open SYNs to victim).
        for port in range(10):
            pipeline.feed(_tcp("attacker", "victim", dport=port, flags="S", ts=port * 0.01))
        kinds = {a.kind for a in pipeline.alerts}
        assert "port_scan" in kinds
        assert "syn_flood" in kinds
