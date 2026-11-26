package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/rebrudiy/belnet-bridge/internal/iwpdetector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	queue := flag.Uint("queue", 42, "IPv4 NFQUEUE number")
	identities := flag.String("identities", "", "file: one public identity hex or .mnode per line")
	ready := flag.String("ready-file", "", "create after queue registration")
	flag.Parse()
	if *queue > 65535 || *identities == "" {
		return errors.New("require -identities and a queue number <=65535")
	}
	f, err := os.Open(*identities)
	if err != nil {
		return err
	}
	defer f.Close()
	var keys [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := iwpdetector.ParseIdentity(line)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	detector, err := iwpdetector.New(keys)
	if err != nil {
		return err
	}
	q, err := nfqueue.Open(&nfqueue.Config{NfQueue: uint16(*queue), MaxPacketLen: 65535, MaxQueueLen: 1024, Copymode: nfqueue.NfQnlCopyPacket, AfFamily: syscall.AF_INET, WriteTimeout: time.Second})
	if err != nil {
		return err
	}
	defer q.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var packets, udp, dropped atomic.Uint64
	var logMu sync.Mutex
	log := func(event map[string]any) {
		logMu.Lock()
		defer logMu.Unlock()
		event["time"] = time.Now().UTC().Format(time.RFC3339Nano)
		_ = json.NewEncoder(os.Stdout).Encode(event)
	}
	failure := make(chan error, 1)
	fail := func(err error) {
		select {
		case failure <- err:
		default:
		}
		cancel()
	}
	err = q.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			fail(errors.New("NFQUEUE packet missing ID or payload"))
			return -1
		}
		packets.Add(1)
		verdict := nfqueue.NfAccept
		var matchedIdentity string
		payload := udpPayload(*a.Payload)
		if payload != nil {
			udp.Add(1)
			if matched, identity := detector.Match(payload); matched {
				verdict = nfqueue.NfDrop
				matchedIdentity = identity
			}
		}
		if err := q.SetVerdict(*a.PacketID, verdict); err != nil {
			fail(err)
			return -1
		}
		if matchedIdentity != "" {
			dropped.Add(1)
			log(map[string]any{"event": "drop_iwp_intro", "identity": matchedIdentity, "udp_bytes": len(payload), "packet_id": *a.PacketID})
		}
		return 0
	}, func(err error) int {
		if ctx.Err() == nil {
			fail(fmt.Errorf("NFQUEUE receive: %w", err))
		}
		return -1
	})
	if err != nil {
		return err
	}
	log(map[string]any{"event": "ready", "queue": *queue, "public_identities": len(keys), "policy": "drop verified initial IWP; accept other packets"})
	if *ready != "" {
		if err := os.WriteFile(*ready, []byte("ready\n"), 0600); err != nil {
			return err
		}
		defer os.Remove(*ready)
	}
	<-ctx.Done()
	log(map[string]any{"event": "summary", "packets": packets.Load(), "udp": udp.Load(), "dropped_iwp": dropped.Load()})
	select {
	case err := <-failure:
		return err
	default:
		return nil
	}
}
