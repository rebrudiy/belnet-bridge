//go:build !linux

package main

import "errors"

func OpenTUN(name string) (Device, error) {
	return nil, errors.New("TUN devices are only supported on Linux; run the bridge in Docker or on a Linux host")
}
