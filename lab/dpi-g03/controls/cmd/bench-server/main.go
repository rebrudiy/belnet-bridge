package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/rebrudiy/belnet-bridge/g03controls/bench"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:20443", "explicit lab/TUN listen address")
	cert := flag.String("cert", "", "lab cert PEM")
	key := flag.String("key", "", "lab key PEM")
	plain := flag.Bool("native-plain", false, "plain HTTP only for native.bdx application service")
	role := flag.String("role", "primary-benign", "primary-benign/native-application/diagnostic")
	flag.Parse()
	if *role != "primary-benign" && *role != "native-application" && *role != "diagnostic" {
		log.Fatal("invalid role")
	}
	if *plain && *role != "native-application" {
		log.Fatal("plain HTTP requires explicit native application role")
	}
	var mu sync.Mutex
	handler := bench.NewHandler(func(e bench.Event) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"role": *role, "workload": e})
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, IdleTimeout: 5 * time.Second, WriteTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		stop, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = handler.Shutdown(stop)
		_ = server.Shutdown(stop)
	}()
	var err error
	if *plain {
		err = server.ListenAndServe()
	} else {
		if *cert == "" || *key == "" {
			log.Fatal("TLS cert and key required")
		}
		err = server.ListenAndServeTLS(*cert, *key)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-shutdownDone
}
