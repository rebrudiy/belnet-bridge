package main

import "encoding/binary"

// udpPayload accepts complete, unfragmented IPv4 UDP packets. This lab tool
// deliberately does not claim to implement IP reassembly or IPv6 classification.
func udpPayload(packet []byte) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil
	}
	header := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || total > len(packet) || total < header+8 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil
	}
	udp := packet[header:total]
	size := int(binary.BigEndian.Uint16(udp[4:6]))
	if size < 8 || size != len(udp) {
		return nil
	}
	return udp[8:]
}
