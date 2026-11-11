package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luca-css/network-scanner/internal/ports"
	"github.com/luca-css/network-scanner/internal/scan"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

var started = time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

func sampleReport(t *testing.T) Report {
	t.Helper()
	b := NewBuilder(Meta{
		Version:      "test",
		Targets:      []string{"10.0.0.0/30", "web.lan"},
		Ports:        "22,80,445,3389,8081",
		HostsScanned: 3,
		PortsPerHost: 5,
		Started:      started,
	})
	a1 := netip.MustParseAddr("10.0.0.1")
	a2 := netip.MustParseAddr("10.0.0.2")
	a3 := netip.MustParseAddr("10.0.0.10")
	// Deliberately out of order: Build must sort hosts and ports.
	b.Add(scan.Result{Addr: a3, Port: 80, State: scan.Open, Latency: 2 * time.Millisecond})
	b.Add(scan.Result{Addr: a1, Port: 3389, State: scan.Open, Latency: 1500 * time.Microsecond})
	b.Add(scan.Result{Addr: a1, Port: 22, State: scan.Open, Latency: time.Millisecond, Banner: "SSH-2.0-OpenSSH_9.6"})
	b.Add(scan.Result{Addr: a1, Port: 8081, State: scan.Open, Latency: time.Millisecond})
	b.Add(scan.Result{Addr: a1, Port: 445, State: scan.Closed})
	b.Add(scan.Result{Addr: a2, Port: 22, State: scan.Closed})
	b.Add(scan.Result{Addr: a2, Port: 80, State: scan.Filtered})
	b.Add(scan.Result{Addr: a3, Port: 22, State: scan.Filtered})
	b.SetName(a3, "web.lan")
	return b.Build(started.Add(1500*time.Millisecond), false)
}

func TestBuild(t *testing.T) {
	r := sampleReport(t)

	want := Stats{Probes: 8, Open: 4, Closed: 2, Filtered: 2, HostsUp: 3, HighRisk: 1, OpenHosts: 2}
	if r.Stats != want {
		t.Errorf("stats = %+v, want %+v", r.Stats, want)
	}
	if r.DurationSec != 1.5 {
		t.Errorf("duration = %v, want 1.5", r.DurationSec)
	}
	if len(r.Hosts) != 2 || r.Hosts[0].Addr != "10.0.0.1" || r.Hosts[1].Addr != "10.0.0.10" {
		t.Fatalf("hosts not sorted by address: %+v", r.Hosts)
	}
	var got []uint16
	for _, p := range r.Hosts[0].Ports {
		got = append(got, p.Port)
	}
	if want := []uint16{22, 3389, 8081}; !equal(got, want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
	if p := r.Hosts[0].Ports[1]; p.Service != "rdp" || p.Risk != ports.RiskCritical || !p.HighRisk() {
		t.Errorf("3389 not enriched from catalog: %+v", p)
	}
	if p := r.Hosts[0].Ports[2]; p.Service != "" || p.Risk != ports.RiskInfo {
		t.Errorf("unknown port should have no service: %+v", p)
	}
	if r.Hosts[1].Hostname != "web.lan" {
		t.Errorf("hostname = %q, want web.lan", r.Hosts[1].Hostname)
	}
}

func TestEmptyReport(t *testing.T) {
	r := NewBuilder(Meta{Started: started}).Build(started, true)
	if r.Hosts == nil {
		t.Error("Hosts should be an empty slice so JSON renders [] not null")
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no open ports") || !strings.Contains(buf.String(), "INTERRUPTED") {
		t.Errorf("unexpected table output:\n%s", buf.String())
	}
}

func TestGolden(t *testing.T) {
	r := sampleReport(t)
	for _, f := range []Format{FormatTable, FormatJSON, FormatHTML} {
		t.Run(string(f), func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, f, r); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "report."+string(f)+".golden")
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run `go test ./internal/report -update` to create it)", err)
			}
			// Normalize line endings in case git checked the file out with CRLF.
			if got, w := buf.String(), strings.ReplaceAll(string(want), "\r\n", "\n"); got != w {
				t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, w)
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	hosts := decoded["hosts"].([]any)
	firstPort := hosts[0].(map[string]any)["ports"].([]any)[0].(map[string]any)
	if firstPort["risk"] != "medium" || firstPort["service"] != "ssh" {
		t.Errorf("risk/service should serialize as names, got %v", firstPort)
	}
}

func TestHTMLEscapesUntrustedInput(t *testing.T) {
	// Banners and hostnames come from the network: treat them as hostile.
	b := NewBuilder(Meta{Started: started, Targets: []string{`"><img src=x onerror=alert(1)>`}})
	addr := netip.MustParseAddr("192.0.2.1")
	b.Add(scan.Result{Addr: addr, Port: 80, State: scan.Open, Banner: `<script>alert("xss")</script>`})
	b.SetName(addr, `evil<b>.example`)

	var buf bytes.Buffer
	if err := WriteHTML(&buf, b.Build(started, false)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, raw := range []string{"<script>alert", "<img src=x", "evil<b>"} {
		if strings.Contains(out, raw) {
			t.Errorf("unescaped %q found in HTML output", raw)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;", "evil&lt;b&gt;.example"} {
		if !strings.Contains(out, escaped) {
			t.Errorf("expected escaped %q in HTML output", escaped)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"table", "json", "html"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q): %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml) should fail")
	}
}

func equal(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
