//go:build linux

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenTUN opens (or creates) a layer-3 TUN interface without packet info headers.
func OpenTUN(name string) (Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno)
	}
	return f, nil
}
