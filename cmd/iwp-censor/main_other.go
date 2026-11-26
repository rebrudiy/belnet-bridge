//go:build !linux

package main

import "fmt"

func main() { fmt.Println("iwp-censor requires Linux NFQUEUE and CAP_NET_ADMIN") }
