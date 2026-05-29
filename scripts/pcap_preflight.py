#!/usr/bin/env python3
"""
pcap_preflight.py — Quick PCAP summary for blue-team triage (Stage 1: Macro).

Tries scapy if available; falls back to a minimal pcap-header parser for the
classic libpcap format (magic 0xa1b2c3d4 / 0xd4c3b2a1). PCAPNG (0x0a0d0d0a)
is detected and the user is told to use scapy / tshark.

Usage:
    python3 pcap_preflight.py capture.pcap
    python3 pcap_preflight.py capture.pcap --json
    python3 pcap_preflight.py capture.pcap --top 5

Exit codes:
    0 success, 1 user error, 2 internal error
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAPNG_MAGIC  = 0x0a0d0d0a


def detect_format(path: Path) -> str:
    with path.open("rb") as f:
        head = f.read(4)
    if len(head) < 4:
        return "empty"
    magic = struct.unpack("<I", head)[0]
    if magic == PCAP_MAGIC_LE:
        return "pcap-le"
    if magic == PCAP_MAGIC_BE:
        return "pcap-be"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return "unknown"


def summarise_with_scapy(path: Path, top: int) -> dict:
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP  # type: ignore
    except ImportError:
        return {}

    pkts = rdpcap(str(path))
    proto = Counter()
    talkers = Counter()
    ports = Counter()
    bytes_per_pair = Counter()
    times = []

    for p in pkts:
        times.append(float(p.time))
        if IP in p:
            src, dst = p[IP].src, p[IP].dst
        elif IPv6 in p:
            src, dst = p[IPv6].src, p[IPv6].dst
        else:
            continue
        talkers[src] += 1
        talkers[dst] += 1
        pair = tuple(sorted((src, dst)))
        bytes_per_pair[pair] += len(p)
        if TCP in p:
            proto["TCP"] += 1
            ports[("tcp", int(p[TCP].dport))] += 1
        elif UDP in p:
            proto["UDP"] += 1
            ports[("udp", int(p[UDP].dport))] += 1

    return {
        "packet_count": len(pkts),
        "time_window_utc": [min(times), max(times)] if times else None,
        "top_talkers": talkers.most_common(top),
        "top_protocols": proto.most_common(),
        "top_ports": [{"proto": k[0], "port": k[1], "count": v}
                      for k, v in ports.most_common(top)],
        "top_pairs_by_bytes": [{"a": k[0], "b": k[1], "bytes": v}
                               for k, v in bytes_per_pair.most_common(top)],
        "engine": "scapy",
    }


def summarise_minimal(path: Path) -> dict:
    """Parse just the global + record headers of a libpcap file.

    Counts packets and accumulates byte totals without dissecting payloads.
    """
    with path.open("rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return {"engine": "minimal", "error": "truncated global header"}
        magic = struct.unpack("<I", global_header[:4])[0]
        endian = "<" if magic == PCAP_MAGIC_LE else ">"

        packet_count = 0
        total_bytes = 0
        first_ts = None
        last_ts = None

        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            packet_count += 1
            total_bytes += orig_len
            ts = ts_sec + ts_usec / 1_000_000.0
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            f.seek(incl_len, 1)

    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "time_window_utc": [first_ts, last_ts] if first_ts else None,
        "engine": "minimal",
        "note": "Install scapy for talker/port/protocol histograms.",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pcap", help="Path to .pcap or .pcapng file")
    p.add_argument("--json", action="store_true", help="Emit JSON")
    p.add_argument("--top", type=int, default=10, help="Top-N for histograms (scapy mode)")
    p.add_argument("--dry-run", action="store_true",
                   help="Detect format and report file size only")
    args = p.parse_args(argv)

    path = Path(args.pcap)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    fmt = detect_format(path)
    if args.dry_run:
        print(json.dumps({"path": str(path), "format": fmt,
                          "size_bytes": path.stat().st_size}, indent=2))
        return 0

    if fmt == "pcapng":
        msg = ("pcapng detected; minimal parser does not support it.\n"
               "Install scapy (`pip install scapy`) or run "
               "`capinfos`/`tshark -r ...` and feed output to log-hunter.")
        print(msg, file=sys.stderr)
        return 1
    if fmt not in {"pcap-le", "pcap-be"}:
        print(f"error: unrecognised format ({fmt}); first 4 bytes did not match.",
              file=sys.stderr)
        return 1

    summary = summarise_with_scapy(path, args.top) or summarise_minimal(path)
    summary["path"] = str(path)
    summary["format"] = fmt

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        _render_human(summary)
    return 0


def _render_human(s: dict) -> None:
    print(f"# PCAP preflight — {s.get('path')}")
    print(f"- Format: {s.get('format')}  (engine: {s.get('engine')})")
    if s.get("time_window_utc"):
        a, b = s["time_window_utc"]
        print(f"- Window: {a} → {b}  ({float(b)-float(a):.1f}s)")
    if "packet_count" in s:
        print(f"- Packets: {s['packet_count']}")
    if "total_bytes" in s:
        print(f"- Total bytes: {s['total_bytes']:,}")
    if s.get("top_talkers"):
        print("\n## Top talkers (by packet count)")
        for ip, n in s["top_talkers"]:
            print(f"- {ip}: {n}")
    if s.get("top_protocols"):
        print("\n## Protocols")
        for proto, n in s["top_protocols"]:
            print(f"- {proto}: {n}")
    if s.get("top_ports"):
        print("\n## Top destination ports")
        for row in s["top_ports"]:
            print(f"- {row['proto']}/{row['port']}: {row['count']}")
    if s.get("top_pairs_by_bytes"):
        print("\n## Heaviest conversations (bytes)")
        for row in s["top_pairs_by_bytes"]:
            print(f"- {row['a']} <-> {row['b']}: {row['bytes']:,} B")
    if s.get("note"):
        print(f"\n_{s['note']}_")


if __name__ == "__main__":
    sys.exit(main())
