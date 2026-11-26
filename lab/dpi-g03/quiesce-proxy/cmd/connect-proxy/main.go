package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rebrudiy/belnet-bridge/g03controls/connectproxy"
	"github.com/rebrudiy/belnet-bridge/g03quiesceproxy/admin"
)

func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", "127.0.0.1:8080", "inside Docker use0.0.0.0 only with loopback-only published host port")
	config := flag.String("config", "", "frozen allowlist/mappings JSON")
	control := flag.String("control", "", "optional literal loopback admin, e.g127.0.0.1:8091")
	flag.Parse()
	if *control != "" {
		if e := admin.ValidateControlAddress(*control); e != nil {
			return e
		}
	}
	f, e := os.Open(*config)
	if e != nil {
		return e
	}
	var cfg connectproxy.Config
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	e = decoder.Decode(&cfg)
	f.Close()
	if e != nil {
		return e
	}
	q := admin.New()
	var logMu sync.Mutex
	p, e := connectproxy.New(cfg, func(event connectproxy.Event) {
		q.NoteEvent(event)
		logMu.Lock()
		defer logMu.Unlock()
		_ = json.NewEncoder(os.Stdout).Encode(event)
	})
	if e != nil {
		return e
	}
	q.Bind(p)
	proxyServer := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	proxyListener, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	var controlServer *http.Server
	var controlListener net.Listener
	if *control != "" {
		controlListener, e = net.Listen("tcp", *control)
		if e != nil {
			proxyListener.Close()
			return e
		}
		controlServer = &http.Server{Addr: *control, Handler: q, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 8 << 10}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exited := make(chan error, 2)
	serve := func(server *http.Server, listener net.Listener) {
		e := server.Serve(listener)
		if errors.Is(e, http.ErrServerClosed) {
			e = nil
		}
		exited <- e
	}
	go serve(proxyServer, proxyListener)
	servers := 1
	if controlServer != nil {
		servers++
		go serve(controlServer, controlListener)
	}
	var failure error
	exits := 0
	select {
	case <-ctx.Done():
	case failure = <-exited:
		exits++
	}
	// POST /quiesce does not reach here. Only OS shutdown/listener failure stops
	// listeners/process, after the capture's predeclared drain has completed.
	shutdown, stop := context.WithTimeout(context.Background(), admin.ShutdownTimeout)
	defer stop()
	if e := p.Shutdown(shutdown); e != nil && failure == nil {
		failure = fmt.Errorf("proxy shutdown: %w", e)
	}
	if e := proxyServer.Shutdown(shutdown); e != nil {
		_ = proxyServer.Close()
		if failure == nil {
			failure = e
		}
	}
	if controlServer != nil {
		if e := controlServer.Shutdown(shutdown); e != nil {
			_ = controlServer.Close()
			if failure == nil {
				failure = e
			}
		}
	}
	for exits < servers {
		select {
		case e := <-exited:
			exits++
			if e != nil && failure == nil {
				failure = e
			}
		case <-shutdown.Done():
			return shutdown.Err()
		}
	}
	return failure
}
