package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rangaroo/pcap-traffic-generator/internal/mutate"
	"github.com/rangaroo/pcap-traffic-generator/internal/pcapio"
	"github.com/rangaroo/pcap-traffic-generator/internal/replay"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "replay":
		runReplay(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tgen <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "  replay   replay a pcap file onto a network interface")
}

func runReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)

	var f replayFlags
	fs.StringVar(&f.pcap, "pcap", "", "input pcap file (required)")
	fs.StringVar(&f.iface, "iface", "", "output network interface (required)")
	fs.StringVar(&f.configFile, "config", "", "optional YAML config file")
	fs.StringVar(&f.mode, "mode", "burst", "replay mode: burst or timed")
	fs.IntVar(&f.repeat, "repeat", 1, "number of replay passes (default 1)")
	fs.BoolVar(&f.remutate, "remutate", false, "re-randomize mutation each repeat pass")
	fs.StringVar(&f.mutateSrcIP, "mutate-src-ip", "", "mutate src IP: CIDR or 'keep'")
	fs.StringVar(&f.mutateDstIP, "mutate-dst-ip", "", "mutate dst IP: CIDR or 'keep'")
	fs.StringVar(&f.mutateSrcPort, "mutate-src-port", "", "mutate src port: MIN-MAX or 'keep'")
	fs.StringVar(&f.mutateDstPort, "mutate-dst-port", "", "mutate dst port: MIN-MAX or 'keep'")
	fs.Int64Var(&f.seed, "seed", 0, "RNG seed for deterministic mutation (0 = use config file value)")

	fs.Parse(args) //nolint:errcheck

	if f.pcap == "" || f.iface == "" {
		fmt.Fprintln(os.Stderr, "replay: -pcap and -iface are required")
		fs.Usage()
		os.Exit(1)
	}

	var mode replay.Mode
	switch f.mode {
	case "burst":
		mode = replay.ModeBurst
	case "timed":
		mode = replay.ModeTimed
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (want burst|timed)\n", f.mode)
		os.Exit(1)
	}

	policy, err := buildPolicy(f)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}

	log.Printf("opening %s", f.pcap)
	rd, err := pcapio.Open(f.pcap)
	if err != nil {
		log.Fatalf("open pcap: %v", err)
	}
	defer rd.Close()

	log.Printf("sessionizing packets...")
	sessions, skipped, err := pcapio.Sessionize(rd)
	if err != nil {
		log.Fatalf("sessionize: %v", err)
	}
	log.Printf("loaded %d sessions (%d packets skipped)", len(sessions), skipped)

	rw := mutate.NewRewriter(policy)

	cfg := replay.Config{
		Iface:    f.iface,
		Mode:     mode,
		Repeat:   f.repeat,
		Remutate: f.remutate,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("interrupted, stopping")
		cancel()
	}()

	log.Printf("replaying on %s (mode=%s repeat=%d)", f.iface, f.mode, f.repeat)
	stats, err := replay.Run(ctx, sessions, rw, cfg)

	log.Printf("done: sent=%d errors=%d sessions=%d",
		stats.Sent, stats.Errors, stats.Sessions)

	if err != nil && ctx.Err() == nil {
		log.Fatalf("replay: %v", err)
	}
}
