"""Console rendering and report export.

Uses ``rich`` for pretty terminal tables when available, and degrades
gracefully to plain text if it is not installed. Also exports the full analysis
to JSON or CSV for sharing / further processing.
"""

from __future__ import annotations

import csv
import json
from typing import List

from .analyzer import TrafficAnalyzer
from .detectors import Alert

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ImportError:  # pragma: no cover - optional dependency
    _RICH = False


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _human_bps(bps: float) -> str:
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbps"


def print_report(analyzer: TrafficAnalyzer, alerts: List[Alert]) -> None:
    if _RICH:
        _print_rich(analyzer, alerts)
    else:
        _print_plain(analyzer, alerts)


def _print_rich(analyzer: TrafficAnalyzer, alerts: List[Alert]) -> None:
    console = Console()
    s = analyzer.summary()

    overview = Table(title="NetScope - Capture Overview", title_style="bold cyan")
    overview.add_column("Metric", style="bold")
    overview.add_column("Value", justify="right")
    overview.add_row("Total packets", f"{s['total_packets']:,}")
    overview.add_row("Total volume", _human_bytes(s["total_bytes"]))
    overview.add_row("Duration", f"{s['duration_seconds']:.2f} s")
    overview.add_row("Avg packet size", f"{s['avg_packet_size_bytes']:.0f} B")
    overview.add_row("Avg throughput", _human_bps(s["throughput_bps"]))
    overview.add_row("Peak throughput", _human_bps(s["peak_bps"]))
    console.print(overview)

    proto = Table(title="Protocol Distribution", title_style="bold cyan")
    proto.add_column("Protocol", style="bold")
    proto.add_column("Packets", justify="right")
    proto.add_column("Bytes", justify="right")
    proto.add_column("% packets", justify="right")
    for name, pkts in analyzer.protocol_packets.most_common():
        pct = 100 * pkts / s["total_packets"] if s["total_packets"] else 0
        proto.add_row(name, f"{pkts:,}",
                      _human_bytes(analyzer.protocol_bytes[name]), f"{pct:.1f}%")
    console.print(proto)

    talkers = Table(title="Top Talkers (by bytes sent)", title_style="bold cyan")
    talkers.add_column("Source IP", style="bold")
    talkers.add_column("Bytes", justify="right")
    for ip, b in s["top_talkers"]:
        talkers.add_row(ip, _human_bytes(b))
    console.print(talkers)

    ports = Table(title="Top Destination Ports", title_style="bold cyan")
    ports.add_column("Port", style="bold")
    ports.add_column("Hits", justify="right")
    for port, hits in s["top_ports"]:
        ports.add_row(str(port), f"{hits:,}")
    console.print(ports)

    if alerts:
        alert_table = Table(title="Security Alerts", title_style="bold red")
        alert_table.add_column("Severity", style="bold")
        alert_table.add_column("Type")
        alert_table.add_column("Detail")
        sev_style = {"high": "red", "medium": "yellow", "low": "green"}
        for a in alerts:
            alert_table.add_row(
                f"[{sev_style.get(a.severity, 'white')}]{a.severity.upper()}[/]",
                a.kind, a.detail,
            )
        console.print(alert_table)
    else:
        console.print("[green]No anomalies detected.[/]")


def _print_plain(analyzer: TrafficAnalyzer, alerts: List[Alert]) -> None:
    s = analyzer.summary()
    print("\n=== NetScope - Capture Overview ===")
    print(f"Total packets : {s['total_packets']:,}")
    print(f"Total volume  : {_human_bytes(s['total_bytes'])}")
    print(f"Duration      : {s['duration_seconds']:.2f} s")
    print(f"Avg throughput: {_human_bps(s['throughput_bps'])}")
    print(f"Peak throughput: {_human_bps(s['peak_bps'])}")

    print("\n--- Protocol Distribution ---")
    for name, pkts in analyzer.protocol_packets.most_common():
        print(f"  {name:6} {pkts:>6,} packets  {_human_bytes(analyzer.protocol_bytes[name])}")

    print("\n--- Top Talkers ---")
    for ip, b in s["top_talkers"]:
        print(f"  {ip:18} {_human_bytes(b)}")

    print("\n--- Security Alerts ---")
    if alerts:
        for a in alerts:
            print(f"  [{a.severity.upper()}] {a.kind}: {a.detail}")
    else:
        print("  No anomalies detected.")


def export_json(path: str, analyzer: TrafficAnalyzer, alerts: List[Alert]) -> None:
    payload = {
        "summary": analyzer.summary(),
        "alerts": [a.to_dict() for a in alerts],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def export_csv(path: str, analyzer: TrafficAnalyzer) -> None:
    """Export the per-flow conversation table as CSV."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["endpoint_a", "endpoint_b", "protocol", "packets", "bytes"])
        for flow_key, byte_count in analyzer.bytes_by_flow.most_common():
            (a_ip, a_port), (b_ip, b_port), proto = flow_key
            writer.writerow([
                f"{a_ip}:{a_port}", f"{b_ip}:{b_port}", proto,
                analyzer.packets_by_flow[flow_key], byte_count,
            ])
