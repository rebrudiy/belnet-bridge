"""Regression checks for missing prefixes, retransmission, and TLS segmentation."""
import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("reassemble", Path(__file__).with_name("reassemble.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def record(kind, payload):
    return struct.pack("!BBBH", kind, 3, 3, len(payload)) + payload


def packet(src, dst, sport, dport, seq, flags, data=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + data
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(tcp), 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return bytes(12) + b"\x08\x00" + ip


def capture(items):
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(struct.pack("<IIII", 100+micros//1_000_000, micros%1_000_000, len(p), len(p))+p for micros, p in items)


class ReassemblyTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        flow={"all_events": []}
        s=r.Stream(100,flow,1)
        data=record(22,b"hello")+record(23,b"encrypted")
        s.feed(100,data[:3],1)
        s.feed(103,data[3:13],2)
        self.assertEqual(flow["all_events"],[])
        s.feed(113,data[13:],3)
        self.assertEqual(flow["all_events"],[(3,1,14)])
        self.assertFalse(s.malformed)

    def test_out_of_order_and_retransmission(self):
        flow={"all_events": []}
        s=r.Stream(100,flow,-1)
        data=record(23,b"ciphertext")
        s.feed(107,data[7:],1)
        s.feed(100,data[:7],2)
        s.feed(100,data,3)
        self.assertEqual(flow["all_events"],[(2,-1,15)])
        self.assertEqual(s.retransmitted_bytes,len(data))
        self.assertFalse(s.pending)

    def test_missing_syn_does_not_become_an_observation(self):
        p=packet("10.0.0.2","10.0.0.3",4000,443,101,0x18,record(23,b"x"))
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"C-onlytls.pcap";path.write_bytes(capture([(0,p),(3_000_000,p)]))
            output=r.read(path)
        self.assertEqual(output["observations"],[])
        self.assertEqual(output["flows"][0]["exclusion_reasons"],["missing_initial_syn_prefix"])

    def test_two_second_window_starts_at_first_encrypted_record(self):
        a,b="10.0.0.2","10.0.0.3"
        first=record(23,b"a")
        items=[(0,packet(a,b,4000,443,100,2)),(100,packet(b,a,443,4000,200,18)),
               (1000,packet(b,a,443,4000,201,24,first)),
               (2_001_000,packet(b,a,443,4000,207,24,record(23,b"b"))),
               (3_001_000,packet(a,b,4000,443,101,16))]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"C-onlytls.pcap";path.write_bytes(capture(items));output=r.read(path)
        self.assertTrue(output["flows"][0]["eligible"])
        self.assertEqual(output["observations"][0]["events"],[{"at_micros":0,"direction":-1,"bytes":6}])


if __name__=="__main__":
    unittest.main()
