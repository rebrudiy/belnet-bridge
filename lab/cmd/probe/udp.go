package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"os"
	"time"
)

func udpEcho() {
	conn, err := net.ListenPacket("udp4", ":1099")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = conn.WriteTo(buf[:n], peer); err != nil {
			log.Print(err)
		}
	}
}
func udpCheck() {
	if len(os.Args) != 3 {
		log.Fatal("udp-check HOST:PORT")
	}
	conn, err := net.DialTimeout("udp4", os.Args[2], 3*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		log.Fatal(err)
	}
	payload := []byte("bb-lab-benign-udp:" + hex.EncodeToString(random[:]))
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(payload)
	buf := make([]byte, 512)
	n := 0
	if err == nil {
		n, err = conn.Read(buf)
	}
	ok := err == nil && string(buf[:n]) == string(payload)
	result := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "ok": ok, "payload": string(payload), "target": os.Args[2]}
	if err != nil {
		result["error"] = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	if !ok {
		os.Exit(1)
	}
}
