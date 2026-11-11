// Command netscan is a concurrent TCP connect scanner.
//
// Usage:
//
//	netscan [flags] <target> [target...]
//
// Only scan networks and hosts you own or are explicitly authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/luca-css/network-scanner/internal/ports"
	"github.com/luca-css/network-scanner/internal/report"
	"github.com/luca-css/network-scanner/internal/scan"
	"github.com/luca-css/network-scanner/internal/target"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitInterrupted = 130 // 128 + SIGINT, shell convention
)

func main() {
	os.Exit(realMain())
}

// realMain owns every deferred cleanup, so they all run before main calls os.Exit.
func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

type options struct {
	ports       string
	concurrency int
	timeout     time.Duration
	rate        int
	banner      bool
	rdns        bool
	format      string
	outFile     string
	maxHosts    int
	quiet       bool
	targets     []string
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("netscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.ports, "p", "top100", `ports: "22,80,443", "1-1024", "top100", "critical", "all" (combinable)`)
	fs.IntVar(&o.concurrency, "c", scan.DefaultConcurrency, "max concurrent connections")
	fs.DurationVar(&o.timeout, "timeout", scan.DefaultTimeout, "per-connection timeout")
	fs.IntVar(&o.rate, "rate", 0, "max new connections per second (0 = unlimited)")
	fs.BoolVar(&o.banner, "banner", false, "grab service banners from open ports")
	fs.BoolVar(&o.rdns, "rdns", false, "reverse DNS lookup for hosts with open ports")
	fs.StringVar(&o.format, "o", "table", "output format: table, json, html")
	fs.StringVar(&o.outFile, "out", "", "write report to file instead of stdout")
	fs.IntVar(&o.maxHosts, "max-hosts", target.DefaultMaxHosts, "refuse to scan more than this many hosts")
	fs.BoolVar(&o.quiet, "q", false, "no progress messages on stderr")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, `netscan %s - concurrent TCP connect scanner

Usage: netscan [flags] <target> [target...]

Targets: 192.168.1.10 | 192.168.1.0/24 | 192.168.1.10-50 | 10.0.0.1-10.0.1.254 | host.example.com

Only scan networks you own or are explicitly authorized to test.

Flags:
`, version)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if *showVersion {
		fmt.Fprintln(stderr, "netscan", version)
		return o, flag.ErrHelp
	}
	o.targets = fs.Args()
	switch {
	case len(o.targets) == 0:
		fs.Usage()
		return o, errors.New("at least one target is required")
	case o.concurrency < 1:
		return o, errors.New("-c must be >= 1")
	case o.timeout <= 0:
		return o, errors.New("-timeout must be > 0")
	case o.rate < 0:
		return o, errors.New("-rate must be >= 0")
	}
	return o, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	format, err := report.ParseFormat(o.format)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	portList, err := ports.Parse(o.ports)
	if err != nil {
		fmt.Fprintln(stderr, "error: -p:", err)
		return exitUsage
	}

	parser := target.Parser{MaxHosts: o.maxHosts, Resolver: net.DefaultResolver}
	targets, err := parser.Parse(ctx, o.targets)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	logf := func(format string, a ...any) {
		if !o.quiet {
			fmt.Fprintf(stderr, format, a...)
		}
	}

	addrs := make([]netip.Addr, len(targets))
	for i, t := range targets {
		addrs[i] = t.Addr
	}

	b := report.NewBuilder(report.Meta{
		Version:      version,
		Targets:      o.targets,
		Ports:        o.ports,
		HostsScanned: len(addrs),
		PortsPerHost: len(portList),
		Started:      time.Now(),
	})
	for _, t := range targets {
		b.SetName(t.Addr, t.Name)
	}

	logf("[*] scanning %d host(s) x %d port(s) = %d probes (concurrency %d, timeout %s)\n",
		len(addrs), len(portList), len(addrs)*len(portList), o.concurrency, o.timeout)

	scanner := scan.New(scan.Config{
		Concurrency: o.concurrency,
		Timeout:     o.timeout,
		Rate:        o.rate,
		Banner:      o.banner,
	})
	for r := range scanner.Run(ctx, addrs, portList) {
		if r.State == scan.Open {
			logf("[+] %s open\n", netip.AddrPortFrom(r.Addr, r.Port))
		}
		b.Add(r)
	}

	interrupted := ctx.Err() != nil
	if interrupted {
		logf("[!] interrupted, writing partial results\n")
	}
	if o.rdns && !interrupted {
		resolveNames(ctx, b)
	}

	rep := b.Build(time.Now(), interrupted)
	if err := writeReport(rep, format, o.outFile, stdout); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if o.outFile != "" {
		logf("[*] report written to %s\n", o.outFile)
	}
	if interrupted {
		return exitInterrupted
	}
	return exitOK
}

// resolveNames runs reverse DNS for hosts with open ports, concurrently and
// with an overall deadline so a slow resolver cannot stall the report.
func resolveNames(ctx context.Context, b *report.Builder) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, addr := range b.OpenHosts() {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			names, err := net.DefaultResolver.LookupAddr(ctx, addr.String())
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			b.SetName(addr, strings.TrimSuffix(names[0], "."))
		})
	}
	wg.Wait()
}

func writeReport(r report.Report, f report.Format, path string, stdout io.Writer) (err error) {
	if path == "" {
		return report.Write(stdout, f, r)
	}
	// The output path is chosen by the operator running the CLI; it is only cleaned.
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()
	return report.Write(file, f, r)
}
