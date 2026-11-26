// Read-only replay of the imported Claude classifier against packet captures.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

type mode struct {
	Name   string   `json:"name"`
	Detect []string `json:"detect"`
}
type outcome struct {
	Seen        int            `json:"seen"`
	Dropped     int            `json:"dropped"`
	DropReasons map[string]int `json:"drop_reasons"`
}
type capture struct {
	File     string              `json:"file"`
	SHA      string              `json:"sha256"`
	Packets  int                 `json:"packets"`
	IPv4     int                 `json:"ipv4"`
	TCP      int                 `json:"tcp"`
	TCP443   int                 `json:"tcp443"`
	UDP      int                 `json:"udp"`
	TCPFlows int                 `json:"tcp_four_tuples_unique"`
	UDPFlows int                 `json:"udp_four_tuples_unique"`
	NonIPv4  int                 `json:"non_ipv4"`
	LinkType uint32              `json:"link_type"`
	Verdicts map[string]*outcome `json:"verdicts"`
}
type control struct {
	Name         string            `json:"name"`
	PayloadBytes int               `json:"payload_bytes"`
	Destination  string            `json:"destination"`
	Verdicts     map[string]string `json:"verdicts"`
}

var modes = []mode{{"recorded_iplist_size_entropy", []string{"iplist", "size", "entropy"}}, {"all_plus_crypto", []string{"iplist", "size", "entropy", "crypto"}}, {"crypto_only", []string{"crypto"}}}

func die(err error) {
	if err != nil {
		panic(err)
	}
}
func fresh(m mode, keys [][]byte) *classifier {
	d := map[string]bool{}
	for _, s := range m.Detect {
		d[s] = true
	}
	return &classifier{cfg: &config{detect: d, relays: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/24")}, keys: keys}, flows: map[string]*flowState{}}
}
func ipData(packet []byte, link uint32) []byte {
	switch link {
	case 1:
		if len(packet) < 14 {
			return nil
		}
		offset := 14
		kind := binary.BigEndian.Uint16(packet[12:14])
		for kind == 0x8100 || kind == 0x88a8 {
			if len(packet) < offset+4 {
				return nil
			}
			kind = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 4
		}
		if kind != 0x0800 {
			return nil
		}
		return packet[offset:]
	case 101:
		return packet
	case 113:
		if len(packet) >= 16 && binary.BigEndian.Uint16(packet[14:16]) == 0x0800 {
			return packet[16:]
		}
	case 276:
		if len(packet) >= 20 && binary.BigEndian.Uint16(packet[:2]) == 0x0800 {
			return packet[20:]
		}
	default:
		panic(fmt.Sprintf("unsupported linktype %d", link))
	}
	return nil
}
func flowKey(ip []byte) string {
	if len(ip) < 20 {
		return ""
	}
	hlen := int(ip[0]&15) * 4
	if hlen < 20 || len(ip) < hlen+4 {
		return ""
	}
	a := fmt.Sprintf("%s:%d", netip.AddrFrom4([4]byte(ip[12:16])), binary.BigEndian.Uint16(ip[hlen:hlen+2]))
	b := fmt.Sprintf("%s:%d", netip.AddrFrom4([4]byte(ip[16:20])), binary.BigEndian.Uint16(ip[hlen+2:hlen+4]))
	if b < a {
		a, b = b, a
	}
	return a + "|" + b
}
func replay(path string, keys [][]byte) capture {
	f, err := os.Open(path)
	die(err)
	defer f.Close()
	h := sha256.New()
	r := bufio.NewReaderSize(io.TeeReader(f, h), 1<<20)
	header := make([]byte, 24)
	_, err = io.ReadFull(r, header)
	die(err)
	var order binary.ByteOrder
	switch hex.EncodeToString(header[:4]) {
	case "d4c3b2a1", "4d3cb2a1":
		order = binary.LittleEndian
	case "a1b2c3d4", "a1b23c4d":
		order = binary.BigEndian
	default:
		panic("not classic PCAP: " + path)
	}
	result := capture{File: path, LinkType: order.Uint32(header[20:24]), Verdicts: map[string]*outcome{}}
	classifiers := map[string]*classifier{}
	for _, m := range modes {
		classifiers[m.Name] = fresh(m, keys)
		result.Verdicts[m.Name] = &outcome{DropReasons: map[string]int{}}
	}
	tcpFlows := map[string]bool{}
	udpFlows := map[string]bool{}
	ph := make([]byte, 16)
	for {
		_, err = io.ReadFull(r, ph)
		if err == io.EOF {
			break
		}
		die(err)
		n := order.Uint32(ph[8:12])
		if n > 4*1024*1024 {
			panic("oversize captured packet")
		}
		packet := make([]byte, n)
		_, err = io.ReadFull(r, packet)
		die(err)
		result.Packets++
		ip := ipData(packet, result.LinkType)
		if len(ip) < 20 || ip[0]>>4 != 4 {
			result.NonIPv4++
			continue
		}
		result.IPv4++
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if total >= 20 && total <= len(ip) {
			ip = ip[:total]
		}
		switch ip[9] {
		case 6:
			result.TCP++
			tcpFlows[flowKey(ip)] = true
			hlen := int(ip[0]&15) * 4
			if len(ip) >= hlen+4 && (binary.BigEndian.Uint16(ip[hlen:hlen+2]) == 443 || binary.BigEndian.Uint16(ip[hlen+2:hlen+4]) == 443) {
				result.TCP443++
			}
		case 17:
			result.UDP++
			udpFlows[flowKey(ip)] = true
		}
		for name, c := range classifiers {
			v := result.Verdicts[name]
			v.Seen++
			if drop, why := c.classify(ip); drop {
				v.Dropped++
				v.DropReasons[why]++
			}
		}
	}
	result.SHA = hex.EncodeToString(h.Sum(nil))
	result.TCPFlows = len(tcpFlows)
	result.UDPFlows = len(udpFlows)
	return result
}
func udpPacket(payload []byte, dst netip.Addr) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 100, 0, 20})
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 42424)
	binary.BigEndian.PutUint16(p[22:24], 1090)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}
func runControls(keys [][]byte) []control {
	intro, err := os.ReadFile("internal/iwpdetector/testdata/intro.bin")
	die(err)
	var random512 []byte
	for i := 0; i < 512; i++ {
		random512 = append(random512, byte(i%256))
	}
	type item struct {
		name string
		data []byte
		dst  string
	}
	cases := []item{{"real_belnet_intro_known_relay", intro, "10.88.0.12"}, {"real_belnet_intro_outside_iplist", intro, "203.0.113.10"}, {"benign_ascii_short", []byte("ordinary UDP echo control"), "203.0.113.10"}, {"benign_ascii_224", make([]byte, 224), "203.0.113.10"}, {"non_belnet_high_entropy_512", random512, "203.0.113.10"}, {"benign_echo_to_listed_ip", []byte("ordinary UDP echo control"), "10.88.0.12"}}
	for i := range cases[3].data {
		cases[3].data[i] = 'x'
	}
	var results []control
	for _, tc := range cases {
		r := control{Name: tc.name, PayloadBytes: len(tc.data), Destination: tc.dst, Verdicts: map[string]string{}}
		p := udpPacket(tc.data, netip.MustParseAddr(tc.dst))
		for _, m := range modes {
			c := fresh(m, keys)
			drop, why := c.classify(p)
			if drop {
				r.Verdicts[m.Name] = "drop:" + why
			} else {
				r.Verdicts[m.Name] = "accept"
			}
		}
		results = append(results, r)
	}
	return results
}
func main() {
	out := flag.String("out", "out/crosscheck/rules/replay.json", "output report")
	flag.Parse()
	if len(flag.Args()) == 0 {
		panic("pass PCAP files")
	}
	keys := loadKeys("lab/results/20261119T025447Z-control/public-identities.txt")
	if len(keys) != 6 {
		panic("expected six public identities")
	}
	var captures []capture
	for _, path := range flag.Args() {
		captures = append(captures, replay(path, keys))
	}
	sort.Slice(captures, func(i, j int) bool { return captures[i].File < captures[j].File })
	metadata := map[string]any{"purpose": "Frozen imported Claude classifier on our archived wire traffic; offline verdict replay, not a live network denial experiment", "go_version": runtime.Version(), "modes": modes, "relay_prefix": "10.88.0.0/24", "known_public_keys": len(keys), "throttle": 0, "captures": captures, "controls": runControls(keys), "classifier_source": "classify.go is byte-identical to imported source", "dependency_note": "Project x/crypto v0.58.0 used in place of imported v0.59.0; BLAKE2b checked with actual captured intro", "no_training_or_threshold_changes": true}
	data, err := json.MarshalIndent(metadata, "", "  ")
	die(err)
	die(os.MkdirAll(filepath.Dir(*out), 0755))
	die(os.WriteFile(*out, append(data, '\n'), 0644))
	fmt.Printf("Replayed %d captures, three frozen configurations; report %s\n", len(captures), *out)
}
