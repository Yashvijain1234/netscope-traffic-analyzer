"""Packet sources for NetScope.

Three interchangeable backends all yield :class:`PacketRecord` objects:

* ``LiveCapture``      - sniff a real interface with Scapy (needs root/admin).
* ``PcapCapture``      - replay a saved ``.pcap`` / ``.pcapng`` file.
* ``SimulatedCapture`` - generate synthetic traffic (incl. an embedded port
  scan and SYN flood) so the tool is demoable with zero setup.

Scapy is imported lazily so the simulation backend works even if Scapy or
libpcap is unavailable on the machine.
"""

from __future__ import annotations

import random
import time
from typing import Iterator, Optional

from .models import PacketRecord

# Common application-layer ports for a best-effort L7 label.
_APP_PORTS = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    123: "NTP",
}


def _classify_app(src_port: Optional[int], dst_port: Optional[int]) -> Optional[str]:
    for port in (dst_port, src_port):
        if port in _APP_PORTS:
            return _APP_PORTS[port]
    return None


def record_from_scapy(pkt) -> Optional[PacketRecord]:
    """Convert a Scapy packet into a :class:`PacketRecord` (or ``None``)."""
    # Imported here so this module loads without Scapy for simulation mode.
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP

    ts = float(getattr(pkt, "time", time.time()))
    length = len(pkt)

    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        if TCP in pkt:
            tcp = pkt[TCP]
            return PacketRecord(
                timestamp=ts, src_ip=src, dst_ip=dst, protocol="TCP", length=length,
                src_port=int(tcp.sport), dst_port=int(tcp.dport),
                tcp_flags=str(tcp.flags),
                app_protocol=_classify_app(int(tcp.sport), int(tcp.dport)),
            )
        if UDP in pkt:
            udp = pkt[UDP]
            return PacketRecord(
                timestamp=ts, src_ip=src, dst_ip=dst, protocol="UDP", length=length,
                src_port=int(udp.sport), dst_port=int(udp.dport),
                app_protocol=_classify_app(int(udp.sport), int(udp.dport)),
            )
        if ICMP in pkt:
            return PacketRecord(ts, src, dst, "ICMP", length)
        return PacketRecord(ts, src, dst, "OTHER", length)

    if ARP in pkt:
        arp = pkt[ARP]
        return PacketRecord(ts, arp.psrc, arp.pdst, "ARP", length)

    return None


class LiveCapture:
    """Sniff packets off a network interface using Scapy."""

    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter

    def stream(self, count: int = 0) -> Iterator[PacketRecord]:
        from scapy.sendrecv import sniff

        captured = []

        def _handle(pkt):
            rec = record_from_scapy(pkt)
            if rec is not None:
                captured.append(rec)

        # Scapy's sniff is blocking; we collect then yield. For long captures a
        # callback-based generator could be used, but this keeps the demo simple.
        sniff(iface=self.interface, filter=self.bpf_filter,
              prn=_handle, count=count, store=False)
        yield from captured


class PcapCapture:
    """Replay packets from a capture file."""

    def __init__(self, path: str):
        self.path = path

    def stream(self, count: int = 0) -> Iterator[PacketRecord]:
        from scapy.utils import rdpcap

        packets = rdpcap(self.path)
        for i, pkt in enumerate(packets):
            if count and i >= count:
                break
            rec = record_from_scapy(pkt)
            if rec is not None:
                yield rec


class SimulatedCapture:
    """Generate realistic synthetic traffic with embedded anomalies.

    Produces a mix of normal web/DNS traffic plus two attack patterns so the
    detectors have something to find during a demo:

    * a horizontal **port scan** from one host across many destination ports, and
    * a **SYN flood** of half-open connections toward a single victim.
    """

    NORMAL_HOSTS = [f"10.0.0.{i}" for i in range(2, 12)]
    SERVERS = ["10.0.0.1", "142.250.72.14", "151.101.1.140"]

    def __init__(self, seed: Optional[int] = 42):
        self._rng = random.Random(seed)

    def _normal_packet(self, ts: float) -> PacketRecord:
        src = self._rng.choice(self.NORMAL_HOSTS)
        dst = self._rng.choice(self.SERVERS)
        dport = self._rng.choice([80, 443, 53, 443, 443])
        proto = "UDP" if dport == 53 else "TCP"
        return PacketRecord(
            timestamp=ts, src_ip=src, dst_ip=dst, protocol=proto,
            length=self._rng.randint(60, 1500),
            src_port=self._rng.randint(20000, 65000), dst_port=dport,
            tcp_flags="PA" if proto == "TCP" else None,
            app_protocol=_APP_PORTS.get(dport),
        )

    def stream(self, count: int = 400) -> Iterator[PacketRecord]:
        ts = time.time()
        attacker = "192.168.1.66"
        victim = "10.0.0.1"
        for i in range(count):
            ts += self._rng.uniform(0.001, 0.02)
            roll = self._rng.random()
            if roll < 0.08:
                # Port scan: single source touching sequential ports, SYN only.
                yield PacketRecord(
                    timestamp=ts, src_ip=attacker, dst_ip=victim, protocol="TCP",
                    length=60, src_port=44444, dst_port=1 + (i % 1024),
                    tcp_flags="S",
                )
            elif roll < 0.14:
                # SYN flood: many spoofed-looking sources, half-open to victim:80.
                yield PacketRecord(
                    timestamp=ts,
                    src_ip=f"172.16.{self._rng.randint(0,255)}.{self._rng.randint(1,254)}",
                    dst_ip=victim, protocol="TCP", length=60,
                    src_port=self._rng.randint(1024, 65000), dst_port=80,
                    tcp_flags="S", app_protocol="HTTP",
                )
            else:
                yield self._normal_packet(ts)
