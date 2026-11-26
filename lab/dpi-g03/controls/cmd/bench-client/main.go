package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/rebrudiy/belnet-bridge/g03controls/bench"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	endpoint := flag.String("url", "", "explicit ws/wss URL; no default experiment")
	family := flag.String("family", "", "download/upload/rpc/push/chat/idle")
	seed := flag.Int64("seed", 0, "preregistered seed")
	duration := flag.Duration("duration", 45*time.Second, "bounded duration")
	proxy := flag.String("proxy", "", "explicit HTTP CONNECT proxy")
	pin := flag.String("spki", "", "exact lab SPKI; empty=normal public verification")
	dns := flag.String("dns", "", "native-only literal loopback DNS e.g127.3.2.1:53")
	nonce := flag.String("nonce", "", "optional fixed64hex correlation nonce; defaultfresh random")
	mode := flag.String("mode", "ordinary", "ordinary proxy WSS or native .bdx application; metadata only")
	flag.Parse()
	parsed, parseErr := url.Parse(*endpoint)
	if parseErr != nil {
		log.Fatal(parseErr)
	}
	switch *mode {
	case "ordinary":
		if parsed.Scheme != "wss" || *proxy == "" || *dns != "" {
			log.Fatal("ordinary mode requires WSS+CONNECT proxy and no native DNS")
		}
	case "native":
		if parsed.Scheme != "ws" || !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".bdx") || *proxy != "" || *dns == "" || *pin != "" {
			log.Fatal("native mode requires plain .bdx WS+loopback native DNS; no CONNECT/pin bypass")
		}
	default:
		log.Fatal("invalid mode")
	}
	plan, err := bench.NewPlan(*family, *seed, *duration, bench.DefaultBudget)
	if err != nil {
		log.Fatal(err)
	}
	result, err := bench.RunClient(context.Background(), *endpoint, plan, bench.ClientOptions{Proxy: *proxy, SPKI: *pin, DNS: *dns, Nonce: *nonce})
	output := map[string]any{"mode": *mode, "workload": result}
	if err != nil {
		output["error"] = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(output)
	if err != nil {
		os.Exit(1)
	}
}
