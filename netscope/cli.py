"""Command-line interface for NetScope.

Examples
--------
Run the zero-setup demo (synthetic traffic with embedded attacks)::

    python -m netscope.cli --demo

Analyze a saved capture and export a JSON report::

    python -m netscope.cli --pcap traffic.pcap --json report.json

Sniff a live interface (needs root/admin), capping at 500 packets::

    sudo python -m netscope.cli --iface en0 --count 500 --filter "tcp"
"""

from __future__ import annotations

import argparse
import sys

from .analyzer import TrafficAnalyzer
from .capture import LiveCapture, PcapCapture, SimulatedCapture
from .detectors import DetectorPipeline
from .reporter import export_csv, export_json, print_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="Capture and analyze network traffic, flag anomalies.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--demo", action="store_true",
                        help="Run on synthetic traffic (no setup or root needed).")
    source.add_argument("--iface", metavar="INTERFACE",
                        help="Sniff a live network interface (requires privileges).")
    source.add_argument("--pcap", metavar="FILE",
                        help="Analyze a saved .pcap/.pcapng capture file.")

    parser.add_argument("--count", type=int, default=0,
                        help="Max packets to process (0 = unlimited / demo default).")
    parser.add_argument("--filter", metavar="BPF",
                        help="BPF filter for live capture, e.g. 'tcp port 443'.")
    parser.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE.")
    parser.add_argument("--csv", metavar="FILE",
                        help="Write the per-flow conversation table to FILE.")
    return parser


def _make_source(args):
    if args.demo:
        return SimulatedCapture(), (args.count or 400)
    if args.pcap:
        return PcapCapture(args.pcap), args.count
    return LiveCapture(interface=args.iface, bpf_filter=args.filter), args.count


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        source, count = _make_source(args)
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2

    analyzer = TrafficAnalyzer()
    pipeline = DetectorPipeline()

    try:
        for rec in source.stream(count=count):
            analyzer.update(rec)
            pipeline.feed(rec)
    except PermissionError:
        print("error: live capture needs elevated privileges (try sudo).",
              file=sys.stderr)
        return 2
    except ImportError:
        print("error: Scapy is required for live/pcap capture. "
              "Install with 'pip install -r requirements.txt' or use --demo.",
              file=sys.stderr)
        return 2

    if analyzer.total_packets == 0:
        print("No packets captured.", file=sys.stderr)
        return 1

    print_report(analyzer, pipeline.alerts)

    if args.json:
        export_json(args.json, analyzer, pipeline.alerts)
        print(f"\nJSON report written to {args.json}")
    if args.csv:
        export_csv(args.csv, analyzer)
        print(f"Flow CSV written to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
