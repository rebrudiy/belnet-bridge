package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// tick is diagnostic only: invalid local packets wake an idle upstream IWP loop.
// It never carries the HTTP proof and is not an approved production workaround.
func tick() {
	if len(os.Args) != 5 {
		log.Fatal("tick source-ip target-ip target-port")
	}
	src := net.ParseIP(os.Args[2]).To4()
	dst := net.ParseIP(os.Args[3]).To4()
	port, err := strconv.Atoi(os.Args[4])
	if err != nil || src == nil || dst == nil {
		log.Fatal("bad tick address")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.Close(fd)
	p := make([]byte, 29)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 29)
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[20:22], 1090)
	binary.BigEndian.PutUint16(p[22:24], uint16(port))
	binary.BigEndian.PutUint16(p[24:26], 9)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	a := &syscall.SockaddrInet4{}
	copy(a.Addr[:], dst)
	for i := 0; i < 3000; i++ {
		if err := syscall.Sendto(fd, p, 0, a); err != nil {
			log.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Println("diagnostic ticks finished")
}
