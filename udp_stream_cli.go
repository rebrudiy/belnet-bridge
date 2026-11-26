package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rebrudiy/belnet-bridge/internal/streamframe"
)

func runUDPStreamServer(args []string) error {
	fs := flag.NewFlagSet("udp-stream-server", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:21990", "loopback plaintext endpoint behind authenticated outer core")
	target := fs.String("target", "", "fixed first-node IWP UDP endpoint")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "shared principal token (or BRIDGE_TOKEN)")
	control := fs.String("lab-control", "", "loopback-only metadata API")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *token == "" || len(*token) > streamframe.MaxTokenLength {
		return errors.New("stream server requires fixed target and token")
	}
	if err := literalLoopback(*listen); err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var metrics *streamMetrics
	if *control != "" {
		metrics = &streamMetrics{}
		if err := startLabControl(ctx, *control, metrics.handler()); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := newStreamBridge(addr, *token, 16, metrics)
	defer bridge.close()
	return bridge.serve(ctx, listener)
}

func runUDPStreamClient(args []string) error {
	fs := flag.NewFlagSet("udp-stream-client", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:2090", "local native UDP endpoint")
	upstream := fs.String("upstream", "127.0.0.1:19090", "loopback TCP listener of authenticated outer core")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "shared principal token (or BRIDGE_TOKEN)")
	control := fs.String("lab-control", "", "loopback-only metadata API")
	maxQueueAge := fs.Duration("max-queue-age", 0, "maximum client input age at frame write-start; 0 retains queued UDP, expired datagrams are lost")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxQueueAge < 0 || *maxQueueAge > time.Minute {
		return errors.New("max-queue-age requires 0..1m")
	}
	if *token == "" || len(*token) > streamframe.MaxTokenLength {
		return errors.New("invalid stream access token length")
	}
	if err := literalLoopback(*listen); err != nil {
		return err
	}
	if err := literalLoopback(*upstream); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var metrics *streamMetrics
	if *control != "" {
		metrics = &streamMetrics{}
		if err := startLabControl(ctx, *control, metrics.handler()); err != nil {
			return err
		}
	}
	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return runUDPStreamProxyWithMaxAge(ctx, listener, *upstream, *token, metrics, *maxQueueAge)
}
