// belnet-bridge carries BelNet (or any UDP-heavy) traffic inside an ordinary
// HTTPS/WebSocket connection, so DPI that fingerprints LLARP sees only TLS to a
// regular-looking website.
//
//	server: belnet-bridge server -listen :443 -cert c.pem -key k.pem -token SECRET
//	client: belnet-bridge client -url wss://bridge.example/ws -token SECRET
//
// The server needs a TUN device plus NAT (see docker/server-entrypoint.sh);
// the client brings up a TUN interface and routes BelNet through it.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: belnet-bridge server|client [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

const coverPage = `<!doctype html><html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>This is the default web page for this server.</p></body></html>`

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":443", "listen address")
	cert := fs.String("cert", "", "TLS certificate (empty = plain HTTP, for use behind a TLS proxy/CDN)")
	key := fs.String("key", "", "TLS key")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "shared secret (or $BRIDGE_TOKEN)")
	path := fs.String("path", "/ws", "secret websocket path")
	tun := fs.String("tun", "bb0", "TUN interface name")
	subnet := fs.String("subnet", "10.77.0.0/24", "tunnel subnet")
	fs.Parse(args)
	if *token == "" {
		return fmt.Errorf("-token is required")
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return err
	}
	dev, err := OpenTUN(*tun)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, coverPage)
	})
	srv := NewServer(dev, NewIPPool(prefix), *path, *token, cover)
	go func() { log.Fatal(srv.RouteFromDevice(ctx)) }()

	httpSrv := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		httpSrv.Shutdown(context.Background())
	}()
	log.Printf("bridge listening on %s, tunnel %s via %s", *listen, prefix, *tun)
	if *cert != "" {
		err = httpSrv.ListenAndServeTLS(*cert, *key)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	url := fs.String("url", "", "bridge URL, e.g. wss://bridge.example/ws")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "shared secret (or $BRIDGE_TOKEN)")
	tun := fs.String("tun", "bb0", "TUN interface name")
	insecure := fs.Bool("insecure", false, "skip TLS verification (testing with self-signed certs only)")
	addrFile := fs.String("addr-file", "", "write the assigned tunnel address here (for setup scripts)")
	fs.Parse(args)
	if *url == "" || *token == "" {
		return fmt.Errorf("-url and -token are required")
	}
	dev, err := OpenTUN(*tun)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}}}
	for backoff := time.Second; ctx.Err() == nil; backoff = min(backoff*2, time.Minute) {
		ws, addr, gw, err := Dial(ctx, *url, *token, httpClient)
		if err != nil {
			log.Printf("dial: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			continue
		}
		log.Printf("connected: tunnel address %s, gateway %s", addr, gw)
		if *addrFile != "" {
			os.WriteFile(*addrFile, []byte(fmt.Sprintf("%s %s\n", addr, gw)), 0o644)
		}
		backoff = time.Second
		err = Relay(ctx, dev, ws)
		ws.CloseNow()
		log.Printf("tunnel closed: %v", err)
	}
	return nil
}
