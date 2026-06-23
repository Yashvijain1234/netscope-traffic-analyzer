"""Tests for the streaming traffic statistics engine."""

from netscope.models import PacketRecord
from netscope.analyzer import TrafficAnalyzer


def _pkt(src, dst, proto, length, ts, sport=1000, dport=80):
    return PacketRecord(ts, src, dst, proto, length, sport, dport)


def test_basic_counts_and_bytes():
    a = TrafficAnalyzer()
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 100, ts=0.0))
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 200, ts=1.0))
    a.update(_pkt("3.3.3.3", "2.2.2.2", "UDP", 50, ts=2.0))

    assert a.total_packets == 3
    assert a.total_bytes == 350
    assert a.protocol_packets["TCP"] == 2
    assert a.protocol_packets["UDP"] == 1
    assert a.protocol_bytes["TCP"] == 300


def test_avg_packet_size():
    a = TrafficAnalyzer()
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 100, ts=0.0))
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 300, ts=1.0))
    assert a.avg_packet_size == 200


def test_top_talkers_ranks_by_bytes_sent():
    a = TrafficAnalyzer()
    a.update(_pkt("heavy", "x", "TCP", 1000, ts=0.0))
    a.update(_pkt("light", "x", "TCP", 10, ts=1.0))
    talkers = a.top_talkers()
    assert talkers[0][0] == "heavy"
    assert talkers[0][1] == 1000


def test_throughput_uses_capture_duration():
    a = TrafficAnalyzer()
    # 1000 bytes over 1 second -> 8000 bits per second.
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 500, ts=0.0))
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 500, ts=1.0))
    assert round(a.throughput_bps) == 8000


def test_flow_key_is_direction_agnostic():
    """A->B and B->A packets should map to the same conversation."""
    a = TrafficAnalyzer()
    a.update(PacketRecord(0.0, "1.1.1.1", "2.2.2.2", "TCP", 100, 1234, 80))
    a.update(PacketRecord(1.0, "2.2.2.2", "1.1.1.1", "TCP", 100, 80, 1234))
    assert len(a.bytes_by_flow) == 1


def test_summary_contains_expected_keys():
    a = TrafficAnalyzer()
    a.update(_pkt("1.1.1.1", "2.2.2.2", "TCP", 100, ts=0.0))
    summary = a.summary()
    for key in ("total_packets", "total_bytes", "throughput_bps",
                "protocol_packets", "top_talkers", "top_ports"):
        assert key in summary
