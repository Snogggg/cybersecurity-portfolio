#!/usr/bin/env python3
"""PacketTrail: summarize DNS and TCP activity in .pcap/.pcapng files and flag odd behavior.

Usage:
    python packettrail.py captures
    python packettrail.py captures\\04-failed-connection.pcapng
"""
import argparse
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import DNS, IP, TCP, IPv6, rdpcap

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

NXDOMAIN_ALERT = 3   # flag a capture with this many NXDOMAIN replies or more
SCAN_PORTS = 10      # flag one host sending SYNs to this many ports on one target
MAX_LISTED = 8       # max unanswered connections printed per capture


def entropy(text):
    """Shannon entropy in bits per character. Random-looking strings score higher."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def looks_random(name):
    """Rough DGA heuristic: long first label, has a digit, high entropy."""
    label = name.rstrip(".").split(".")[0].lower()
    return len(label) >= 8 and any(ch.isdigit() for ch in label) and entropy(label) >= 3.3


def analyze_dns(packets):
    queries, responses = [], []
    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        if dns.qd is None:
            continue
        raw = dns.qd.qname
        qname = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
        qtype = QTYPES.get(dns.qd.qtype, str(dns.qd.qtype))
        if dns.qr == 0:
            queries.append((float(pkt.time), qname, qtype))
        else:
            rcode = RCODES.get(dns.rcode, str(dns.rcode))
            responses.append((float(pkt.time), qname, qtype, rcode))
    return queries, responses


def analyze_tcp(packets):
    conns = {}
    resets = []
    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        ip = pkt[IPv6] if pkt.haslayer(IPv6) else (pkt[IP] if pkt.haslayer(IP) else None)
        if ip is None:
            continue
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        syn, ack, rst = flags & 0x02, flags & 0x10, flags & 0x04
        ts = float(pkt.time)
        if syn and not ack:
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            conn = conns.setdefault(key, {"syns": 0, "synack": False, "first": ts, "delay": None})
            conn["syns"] += 1
        elif syn and ack:
            key = (ip.dst, tcp.dport, ip.src, tcp.sport)
            if key in conns and not conns[key]["synack"]:
                conns[key]["synack"] = True
                conns[key]["delay"] = ts - conns[key]["first"]
        if rst:
            resets.append((ts, ip.src, tcp.sport, ip.dst, tcp.dport))
    return conns, resets


def endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def dns_report(packets):
    queries, responses = analyze_dns(packets)
    print("\n[DNS]")
    if not queries and not responses:
        print("  no DNS traffic")
        return
    print(f"  {len(queries)} queries, {len(responses)} responses")

    counts = Counter((name, qtype) for _, name, qtype in queries)
    for (name, qtype), n in counts.most_common(10):
        print(f"  {qtype:<6} {name}  x{n}")

    rcodes = Counter(r[3] for r in responses)
    print("  response codes: " + ", ".join(f"{code} x{n}" for code, n in rcodes.items()))

    nx = rcodes.get("NXDOMAIN", 0)
    if nx >= NXDOMAIN_ALERT:
        print(f"  [!] {nx} NXDOMAIN replies: lookups for names that do not exist")
    for name in sorted({n for _, n, _ in queries if looks_random(n)}):
        print(f"  [!] random-looking name: {name} (possible DGA / generated domain)")


def tcp_report(packets):
    conns, resets = analyze_tcp(packets)
    print("\n[TCP]")
    if not conns and not resets:
        print("  no TCP connection attempts")
        return
    answered = {k: v for k, v in conns.items() if v["synack"]}
    unanswered = {k: v for k, v in conns.items() if not v["synack"]}
    print(f"  {len(conns)} connection attempts: {len(answered)} answered, "
          f"{len(unanswered)} unanswered, {len(resets)} RST")

    for (_, _, dst, dport), conn in answered.items():
        print(f"  ok   -> {endpoint(dst, dport)}  SYN-ACK after {conn['delay'] * 1000:.0f} ms")
    for (_, _, dst, dport), conn in list(unanswered.items())[:MAX_LISTED]:
        extra = f", {conn['syns'] - 1} retransmitted" if conn["syns"] > 1 else ""
        print(f"  [!]  -> {endpoint(dst, dport)}  no reply ({conn['syns']} SYNs{extra}): filtered port or host down")
    if len(unanswered) > MAX_LISTED:
        print(f"  ... and {len(unanswered) - MAX_LISTED} more unanswered")

    ports = defaultdict(set)
    for src, _, dst, dport in conns:
        ports[(src, dst)].add(dport)
    for (src, dst), seen in ports.items():
        if len(seen) >= SCAN_PORTS:
            print(f"  [!] {src} sent SYNs to {len(seen)} ports on {dst}: possible port scan")


def report(path):
    packets = rdpcap(str(path))
    print(f"\n=== {path.name} ({len(packets)} packets) ===")
    dns_report(packets)
    tcp_report(packets)


def main():
    parser = argparse.ArgumentParser(description="Summarize DNS and TCP activity in pcap files.")
    parser.add_argument("paths", nargs="+", help="capture files or folders containing them")
    args = parser.parse_args()

    files = []
    for raw in args.paths:
        path = Path(raw)
        files += sorted(path.glob("*.pcap*")) if path.is_dir() else [path]
    if not files:
        sys.exit("No capture files found.")
    for f in files:
        report(f)


if __name__ == "__main__":
    main()
