"""Reconstruct encrypted TLS record prefixes from Ethernet PCAP, without keys.

Timestamps are PCAP record-completion times, not the training socket callbacks.
Only flows with a captured initial TCP SYN/SYN-ACK can be eligible prefixes.
"""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import socket
import struct
import sys

WINDOW_US = 2_000_000
MAX_RECORDS = 64


class Stream:
    def __init__(self, base, flow, direction):
        self.base = base
        self.position = 0
        self.pending = {}
        self.buffer = bytearray()
        self.flow = flow
        self.direction = direction
        self.malformed = False
        self.records = 0
        self.retransmitted_bytes = 0

    def feed(self, seq, data, now):
        if not data or self.malformed:
            return
        offset = (seq - self.base) & 0xffffffff
        if offset > 0x7fffffff:
            return
        if offset < self.position:
            skipped = min(self.position - offset, len(data))
            self.retransmitted_bytes += skipped
            data = data[skipped:]
            offset = self.position
        if not data:
            return
        prior = self.pending.get(offset, b"")
        if len(data) > len(prior):
            self.pending[offset] = data
        while self.pending:
            first = min(self.pending)
            if first > self.position:
                return
            segment = self.pending.pop(first)[self.position - first:]
            self.position += len(segment)
            self.buffer.extend(segment)
            while len(self.buffer) >= 5:
                kind, major, minor, size = struct.unpack("!BBBH", self.buffer[:5])
                if not 20 <= kind <= 24 or major != 3 or minor > 4:
                    self.malformed = True
                    return
                if len(self.buffer) < size + 5:
                    break
                del self.buffer[:size + 5]
                self.records += 1
                if kind == 23:
                    self.flow["all_events"].append((now, self.direction, size + 5))


def utc(micros):
    return datetime.fromtimestamp(micros / 1e6, timezone.utc).isoformat()


def read(path):
    active = {}
    flows = []
    unknown = {}
    counts = Counter()
    first_packet = last_packet = None
    with path.open("rb") as f:
        h = f.read(24)
        magic = h[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            raise ValueError("unsupported PCAP format")
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        if len(h) != 24 or struct.unpack(endian + "I", h[20:24])[0] != 1:
            raise ValueError("PCAP must have complete Ethernet global header")
        while True:
            header = f.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError("truncated packet header")
            sec, fraction, caplen, original = struct.unpack(endian + "IIII", header)
            packet = f.read(caplen)
            if len(packet) != caplen:
                raise ValueError("truncated PCAP packet")
            now = sec * 1_000_000 + (fraction // 1000 if nano else fraction)
            first_packet = now if first_packet is None else first_packet
            last_packet = now
            counts["packets"] += 1
            if len(packet) < 34 or packet[12:14] != b"\x08\x00":
                counts["non_ipv4"] += 1
                continue
            ip = packet[14:]
            ihl = (ip[0] & 15) * 4
            total = struct.unpack("!H", ip[2:4])[0]
            if ip[0] >> 4 != 4 or ihl < 20 or total < ihl or total > len(ip):
                counts["invalid_or_truncated_ipv4"] += 1
                continue
            counts["ipv4"] += 1
            if struct.unpack("!H", ip[6:8])[0] & 0x3fff:
                counts["ipv4_fragment"] += 1
                continue
            if ip[9] != 6:
                counts["udp" if ip[9] == 17 else "other_ipv4"] += 1
                continue
            tcp = ip[ihl:total]
            if len(tcp) < 20:
                counts["invalid_tcp"] += 1
                continue
            sport, dport, seq = struct.unpack("!HHI", tcp[:8])
            if 443 not in (sport, dport):
                counts["other_tcp"] += 1
                continue
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            direction = 1 if dport == 443 else -1
            key = (src, sport, dst, dport) if direction == 1 else (dst, dport, src, sport)
            counts["tcp443"] += 1
            flags = tcp[13]
            off = (tcp[12] >> 4) * 4
            if off < 20 or off > len(tcp):
                counts["invalid_tcp"] += 1
                continue
            if flags & 2 and direction == 1 and not flags & 16:
                base = (seq + 1) & 0xffffffff
                if key not in active or active[key]["streams"][1].base != base:
                    flow = {"tuple": key, "syn_us": now, "first_us": now, "last_us": now, "closed_us": None, "all_events": [], "streams": {}}
                    flow["streams"][1] = Stream(base, flow, 1)
                    active[key] = flow
                    flows.append(flow)
            flow = active.get(key)
            if flow is None:
                u = unknown.setdefault(key, {"tuple": key, "first_us": now, "last_us": now, "packets": 0, "payload_bytes": 0})
                u["last_us"] = now
                u["packets"] += 1
                u["payload_bytes"] += len(tcp[off:])
                continue
            flow["last_us"] = now
            if flags & 2 and direction == -1:
                base = (seq + 1) & 0xffffffff
                if -1 not in flow["streams"]:
                    flow["streams"][-1] = Stream(base, flow, -1)
                elif flow["streams"][-1].base != base:
                    raise ValueError("conflicting SYN-ACK ISN")
            if direction in flow["streams"]:
                flow["streams"][direction].feed((seq + (1 if flags & 2 else 0)) & 0xffffffff, tcp[off:], now)
            if flags & (1 | 4) and flow["closed_us"] is None:
                flow["closed_us"] = now
    output = []
    observations = []
    for index, flow in enumerate(flows):
        # Python stable sort preserves capture ordering when timestamps tie.
        events = sorted(flow["all_events"], key=lambda e: e[0])
        started = events[0][0] if events else None
        selected = [] if started is None else [(at-started, direction, size) for at, direction, size in events if at-started < WINDOW_US][:MAX_RECORDS]
        reasons = []
        if -1 not in flow["streams"]: reasons.append("missing_syn_ack")
        if not events: reasons.append("no_complete_encrypted_records")
        if any(s.malformed for s in flow["streams"].values()): reasons.append("malformed_tls_stream")
        if any(s.pending for s in flow["streams"].values()): reasons.append("tcp_reassembly_gap")
        ending = flow["closed_us"] or last_packet
        if started is not None and len(selected) < MAX_RECORDS and ending - started < WINDOW_US: reasons.append("short_observation_window")
        sid = "%s-flow-%03d" % (path.stem, index)
        record = {"session_id": sid, "tuple": list(flow["tuple"]), "syn_utc": utc(flow["syn_us"]), "first_encrypted_utc": utc(started) if started is not None else None, "captured_end_utc": utc(flow["last_us"]), "eligible": not reasons, "exclusion_reasons": reasons, "records_in_prefix": len(selected), "all_encrypted_records": len(events), "last_prefix_micros": selected[-1][0] if selected else None, "retransmitted_bytes": sum(s.retransmitted_bytes for s in flow["streams"].values())}
        output.append(record)
        if selected:
            observations.append({"session_id": sid, "group_id": sid, "class": "belnet" if path.stem == "C-onlytls" else "unlabelled", "split": "test", "profile": "claude-archived", "events": [{"at_micros": at, "direction": direction, "bytes": size} for at, direction, size in selected]})
    for key, u in unknown.items():
        output.append({"tuple": list(key), "eligible": False, "exclusion_reasons": ["missing_initial_syn_prefix"], "packets": u["packets"], "payload_bytes": u["payload_bytes"], "first_utc": utc(u["first_us"]), "last_utc": utc(u["last_us"])})
    return {"pcap": str(path), "pcap_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "packet_counts": dict(counts), "first_utc": utc(first_packet), "last_utc": utc(last_packet), "flows": output, "observations": observations}


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: reassemble.py PCAP_DIR OUTPUT_JSON")
    files = sorted(Path(sys.argv[1]).glob("*.pcap"))
    result = {"method": "TCP reassembly from complete initial SYN/SYN-ACK; encrypted TLS outer type23 record lengths including header; timestamps at record completion in PCAP; first2seconds or64records relative to firsttype23; no decryption/model fitting", "window_micros": WINDOW_US, "max_records": MAX_RECORDS, "pcaps": [read(p) for p in files]}
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({Path(p["pcap"]).name: {"eligible": sum(x["eligible"] for x in p["flows"]), "total_flows": len(p["flows"])} for p in result["pcaps"]}))


if __name__ == "__main__":
    main()
