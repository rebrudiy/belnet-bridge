// Lab-only UDP echo/probe and self-signed TLS decoy; not a BelNet implementation.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func fail(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	switch os.Args[1] {
	case "cert":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		fail(err)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		fail(err)
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "decoy.test"}, DNSNames: []string{"decoy.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		fail(err)
		kd, err := x509.MarshalECPrivateKey(key)
		fail(err)
		fail(os.WriteFile(os.Args[2]+"/cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		fail(os.WriteFile(os.Args[2]+"/key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0600))
	case "serve":
		cert, err := tls.LoadX509KeyPair("/work/cert.pem", "/work/key.pem")
		fail(err)
		go func() {
			l, err := tls.Listen("tcp", "127.0.0.1:18443", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"}})
			fail(err)
			fail(http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "lab decoy") })))
		}()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1090})
		fail(err)
		f, err := os.OpenFile("/work/echo.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		fail(err)
		defer f.Close()
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			fail(err)
			fail(json.NewEncoder(f).Encode(map[string]any{"time": time.Now().UTC(), "peer": peer.String(), "bytes": n}))
			_, err = conn.WriteToUDP(buf[:n], peer)
			fail(err)
		}
	case "probe":
		// One source socket per invocation. Optional source port supports reconnect checks.
		local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		if len(os.Args) > 3 {
			local.Port, _ = strconv.Atoi(os.Args[3])
		}
		dest, err := net.ResolveUDPAddr("udp4", os.Args[2])
		fail(err)
		conn, err := net.DialUDP("udp4", local, dest)
		fail(err)
		defer conn.Close()
		sizes := []int{0, 1, 128, 1200, 60000, 65507}
		if specified := os.Getenv("MATURE_PROBE_SIZES"); specified != "" {
			sizes = nil
			for _, value := range strings.Split(specified, ",") {
				n, err := strconv.Atoi(value)
				fail(err)
				if n < 0 || n > 65507 {
					panic("invalid UDP size")
				}
				sizes = append(sizes, n)
			}
		}
		results := []map[string]any{}
		for index, size := range sizes {
			p := make([]byte, size)
			for i := range p {
				p[i] = byte(i + index)
			}
			start := time.Now()
			_, err = conn.Write(p)
			fail(err)
			fail(conn.SetReadDeadline(time.Now().Add(4 * time.Second)))
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)
			row := map[string]any{"bytes": size, "received_bytes": n, "ok": err == nil && bytes.Equal(p, buf[:n]), "latency_ms": float64(time.Since(start).Microseconds()) / 1000}
			if err != nil {
				row["error"] = err.Error()
			} else if !bytes.Equal(p, buf[:n]) {
				row["error"] = "payload mismatch or truncation"
			}
			results = append(results, row)
		}
		fail(json.NewEncoder(os.Stdout).Encode(map[string]any{"source": conn.LocalAddr().String(), "destination": dest.String(), "results": results}))
	default:
		panic("use cert DIR | serve | probe HOST:PORT [SOURCEPORT]")
	}
}
