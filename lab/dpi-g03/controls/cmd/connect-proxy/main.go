package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/rebrudiy/belnet-bridge/g03controls/connectproxy"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "inside container use0.0.0.0 only with Docker publish127.0.0.1")
	config := flag.String("config", "", "frozen allowlist/mappings JSON")
	flag.Parse()
	f, err := os.Open(*config)
	if err != nil {
		log.Fatal(err)
	}
	var c connectproxy.Config
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		log.Fatal(err)
	}
	f.Close()
	var mu sync.Mutex
	proxy, err := connectproxy.New(c, func(e connectproxy.Event) { mu.Lock(); defer mu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(e) })
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: proxy, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		done, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = proxy.Shutdown(done)
		_ = server.Shutdown(done)
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-shutdownDone
}
