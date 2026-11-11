// Package scan implements a concurrent TCP connect scanner with a bounded
// worker pool, per-dial timeouts, optional rate limiting, optional passive
// banner grabbing and context-based cancellation.
//
// A TCP connect scan completes the full three-way handshake using the
// operating system's normal socket API, so it needs no special privileges
// (unlike SYN scans, which require raw sockets).
package scan

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
)

// State is the outcome of probing one port.
type State int

// Possible port states.
const (
	// Open: the TCP handshake completed.
	Open State = iota
	// Closed: the host answered with a RST (connection refused). This also
	// proves the host is up.
	Closed
	// Filtered: no answer before the timeout, or the network reported the
	// destination unreachable. Usually a firewall dropping packets or a host
	// that is down.
	Filtered
)

func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case Closed:
		return "closed"
	default:
		return "filtered"
	}
}

// MarshalText makes State serialize as its name in JSON.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Result is the outcome of a single (address, port) probe.
type Result struct {
	Addr    netip.Addr
	Port    uint16
	State   State
	Latency time.Duration // time to connect (or to fail)
	Banner  string        // sanitized first bytes sent by the service, if grabbed
}

// DialFunc matches (*net.Dialer).DialContext and allows tests to inject a
// custom dialer.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config tunes a Scanner. Zero values fall back to sensible defaults.
type Config struct {
	Concurrency   int           // max simultaneous dials (default 100)
	Timeout       time.Duration // per-dial timeout (default 1s)
	Rate          int           // max new dials per second; 0 = unlimited
	Banner        bool          // read a banner from open ports
	BannerTimeout time.Duration // how long to wait for a banner (default 1s)
	BannerMax     int           // max banner bytes (default 128)
	Dial          DialFunc      // default: (&net.Dialer{}).DialContext
}

// Default configuration values.
const (
	DefaultConcurrency   = 100
	DefaultTimeout       = time.Second
	DefaultBannerTimeout = time.Second
	DefaultBannerMax     = 128
)

// Scanner runs TCP connect scans. It is safe to reuse but each Run call is
// independent.
type Scanner struct {
	cfg Config
}

// New returns a Scanner with defaults applied to cfg.
func New(cfg Config) *Scanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.BannerTimeout <= 0 {
		cfg.BannerTimeout = DefaultBannerTimeout
	}
	if cfg.BannerMax <= 0 {
		cfg.BannerMax = DefaultBannerMax
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{}).DialContext
	}
	return &Scanner{cfg: cfg}
}

type job struct {
	addr netip.Addr
	port uint16
}

// Run probes every (address, port) pair and streams results on the returned
// channel, which is closed once all workers finish. Cancelling ctx stops
// scheduling new probes and aborts in-flight dials; probes interrupted by
// cancellation are not reported. The caller must drain the channel.
func (s *Scanner) Run(ctx context.Context, addrs []netip.Addr, ports []uint16) <-chan Result {
	jobs := make(chan job)
	results := make(chan Result, s.cfg.Concurrency)

	// Producer: feeds jobs, honouring the rate limit and cancellation.
	go func() {
		defer close(jobs)
		var tick <-chan time.Time
		if s.cfg.Rate > 0 {
			t := time.NewTicker(time.Second / time.Duration(s.cfg.Rate))
			defer t.Stop()
			tick = t.C
		}
		for _, a := range addrs {
			for _, p := range ports {
				if tick != nil {
					select {
					case <-tick:
					case <-ctx.Done():
						return
					}
				}
				select {
				case jobs <- job{a, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Fixed-size worker pool: concurrency is bounded by the number of
	// workers, not by spawning one goroutine per probe.
	workers := min(s.cfg.Concurrency, max(1, len(addrs)*len(ports)))
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				r, ok := s.probe(ctx, j.addr, j.port)
				if !ok {
					continue // cancelled mid-dial: outcome unknown, don't report
				}
				select {
				case results <- r:
				case <-ctx.Done():
				}
			}
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

// probe dials a single address/port. ok is false if the parent context was
// cancelled, in which case the result is meaningless.
func (s *Scanner) probe(ctx context.Context, addr netip.Addr, port uint16) (r Result, ok bool) {
	if ctx.Err() != nil {
		return r, false
	}
	r = Result{Addr: addr, Port: port}

	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	start := time.Now()
	conn, err := s.cfg.Dial(dialCtx, "tcp", netip.AddrPortFrom(addr, port).String())
	r.Latency = time.Since(start)
	if err != nil {
		if ctx.Err() != nil {
			return r, false
		}
		r.State = classify(err)
		return r, true
	}
	defer conn.Close()

	r.State = Open
	if s.cfg.Banner {
		r.Banner = s.grabBanner(conn)
	}
	return r, true
}

// classify maps a dial error to a port state.
func classify(err error) State {
	if isRefused(err) {
		return Closed
	}
	return Filtered
}

// grabBanner passively reads whatever the service sends first (SSH, FTP,
// SMTP, ... announce themselves). Services that wait for the client, such as
// HTTP, yield an empty banner.
func (s *Scanner) grabBanner(conn net.Conn) string {
	if err := conn.SetReadDeadline(time.Now().Add(s.cfg.BannerTimeout)); err != nil {
		return ""
	}
	buf := make([]byte, s.cfg.BannerMax)
	n, _ := conn.Read(buf)
	return sanitize(buf[:n])
}

// sanitize keeps banners printable: control characters (including ANSI escape
// sequences that could mess with a terminal) become spaces and runs of
// whitespace collapse. Output encoders handle the remaining escaping.
func sanitize(b []byte) string {
	s := strings.ToValidUTF8(string(b), "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
