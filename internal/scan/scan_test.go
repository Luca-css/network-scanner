package scan

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var localhost = netip.MustParseAddr("127.0.0.1")

// listen starts a TCP listener on 127.0.0.1 that accepts connections and
// optionally writes a banner. It returns the listening port.
func listen(t *testing.T, banner string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				c.Write([]byte(banner))
			}
			c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// closedPort returns a port on 127.0.0.1 that nothing listens on.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port
}

func collect(ch <-chan Result) map[uint16]Result {
	out := make(map[uint16]Result)
	for r := range ch {
		out[r.Port] = r
	}
	return out
}

func TestRunOpenAndClosed(t *testing.T) {
	open := listen(t, "")
	closed := closedPort(t)

	// Windows retries a SYN that gets RST'd for a while before reporting
	// "refused", so give closed ports a generous timeout.
	s := New(Config{Timeout: 5 * time.Second})
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{open, closed}))

	if len(got) != 2 {
		t.Fatalf("got %d results, want 2: %v", len(got), got)
	}
	if st := got[open].State; st != Open {
		t.Errorf("port %d state = %s, want open", open, st)
	}
	if st := got[closed].State; st != Closed {
		t.Errorf("port %d state = %s, want closed", closed, st)
	}
	if got[open].Addr != localhost {
		t.Errorf("addr = %s, want %s", got[open].Addr, localhost)
	}
}

func TestBannerGrab(t *testing.T) {
	port := listen(t, "SSH-2.0-OpenSSH_9.6\r\n\x1b[31mjunk\x00")
	s := New(Config{Banner: true, BannerTimeout: 2 * time.Second})
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{port}))

	r := got[port]
	if r.State != Open {
		t.Fatalf("state = %s, want open", r.State)
	}
	if want := "SSH-2.0-OpenSSH_9.6 [31mjunk"; r.Banner != want {
		t.Errorf("banner = %q, want %q", r.Banner, want)
	}
}

func TestBannerSilentService(t *testing.T) {
	// A listener that accepts but never writes (like HTTP) must not hang the
	// scan: the banner read is bounded by BannerTimeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }() // hold the connection open, silently
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	s := New(Config{Banner: true, BannerTimeout: 100 * time.Millisecond})
	start := time.Now()
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{port}))
	if got[port].State != Open || got[port].Banner != "" {
		t.Errorf("got %+v, want open with empty banner", got[port])
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("silent service took %s, banner timeout not honoured", el)
	}
}

// blockingDial simulates a filtered port: it never answers until the context
// is done.
func blockingDial(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
}

func TestTimeoutIsFiltered(t *testing.T) {
	s := New(Config{Timeout: 50 * time.Millisecond, Dial: blockingDial})
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{9}))

	r, ok := got[9]
	if !ok {
		t.Fatal("expected a result for a timed-out probe")
	}
	if r.State != Filtered {
		t.Errorf("state = %s, want filtered", r.State)
	}
	if r.Latency < 50*time.Millisecond {
		t.Errorf("latency = %s, expected at least the timeout", r.Latency)
	}
}

func TestRefusedIsClosed(t *testing.T) {
	refuse := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	s := New(Config{Dial: refuse})
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{1}))
	if got[1].State != Closed {
		t.Errorf("state = %s, want closed", got[1].State)
	}
}

func TestContextCancelStopsScan(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := New(Config{Concurrency: 4, Timeout: time.Minute, Dial: blockingDial})

	ports := make([]uint16, 1000)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	ch := s.Run(ctx, []netip.Addr{localhost}, ports)

	time.AfterFunc(50*time.Millisecond, cancel)
	done := make(chan map[uint16]Result)
	go func() { done <- collect(ch) }()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("cancelled probes must not be reported, got %d results", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("result channel not closed after cancellation")
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	const limit = 5
	var inFlight, peak atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return nil, os.NewSyscallError("connect", syscall.ECONNREFUSED)
	}

	s := New(Config{Concurrency: limit, Dial: dial})
	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, ports))

	if len(got) != len(ports) {
		t.Errorf("got %d results, want %d", len(got), len(ports))
	}
	if p := peak.Load(); p > limit {
		t.Errorf("peak concurrency = %d, want <= %d", p, limit)
	}
}

func TestRateLimit(t *testing.T) {
	refuse := func(context.Context, string, string) (net.Conn, error) {
		return nil, os.NewSyscallError("connect", syscall.ECONNREFUSED)
	}
	// 10 probes at 50/s need at least ~9 ticks of 20ms each.
	s := New(Config{Rate: 50, Dial: refuse})
	start := time.Now()
	got := collect(s.Run(t.Context(), []netip.Addr{localhost}, []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
	el := time.Since(start)

	if len(got) != 10 {
		t.Fatalf("got %d results, want 10", len(got))
	}
	if el < 150*time.Millisecond {
		t.Errorf("10 probes at 50/s finished in %s; rate limit not applied", el)
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"SSH-2.0-OpenSSH\r\n", "SSH-2.0-OpenSSH"},
		{"220  mail  ready\r\n", "220 mail ready"},
		{"a\x00b\x07c", "a b c"},
		{"\xff\xfebad utf8", "?bad utf8"},
		{"<script>alert(1)</script>", "<script>alert(1)</script>"}, // escaping is the report's job
		{"", ""},
	}
	for _, tt := range tests {
		if got := sanitize([]byte(tt.in)); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStateString(t *testing.T) {
	for st, want := range map[State]string{Open: "open", Closed: "closed", Filtered: "filtered"} {
		if st.String() != want {
			t.Errorf("%d.String() = %q, want %q", st, st.String(), want)
		}
	}
}
