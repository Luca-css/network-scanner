// Package report aggregates scan results and renders them as a terminal
// table, JSON or a self-contained HTML page.
package report

import (
	"cmp"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/luca-css/network-scanner/internal/ports"
	"github.com/luca-css/network-scanner/internal/scan"
)

// Meta describes the scan that produced a report.
type Meta struct {
	Version      string    `json:"version"`
	Targets      []string  `json:"targets"`
	Ports        string    `json:"ports"`
	HostsScanned int       `json:"hosts_scanned"`
	PortsPerHost int       `json:"ports_per_host"`
	Started      time.Time `json:"started"`
}

// Report is the serializable result of a scan. Only hosts with at least one
// open port are listed; closed/filtered ports are summarized in Stats.
type Report struct {
	Meta
	Finished    time.Time `json:"finished"`
	DurationSec float64   `json:"duration_sec"`
	Interrupted bool      `json:"interrupted"`
	Stats       Stats     `json:"stats"`
	Hosts       []Host    `json:"hosts"`
}

// Stats counts probe outcomes.
type Stats struct {
	Probes    int `json:"probes"`
	Open      int `json:"open"`
	Closed    int `json:"closed"`
	Filtered  int `json:"filtered"`
	HostsUp   int `json:"hosts_up"`  // answered on any port (open or RST)
	HighRisk  int `json:"high_risk"` // open ports rated high or critical
	OpenHosts int `json:"open_hosts"`
}

// Host is a host with at least one open port.
type Host struct {
	Addr     string `json:"addr"`
	Hostname string `json:"hostname,omitempty"`
	Ports    []Port `json:"ports"`
}

// Port is an open port, enriched with catalog data.
type Port struct {
	Port      uint16     `json:"port"`
	Service   string     `json:"service,omitempty"`
	Risk      ports.Risk `json:"risk"`
	Note      string     `json:"note,omitempty"`
	Banner    string     `json:"banner,omitempty"`
	LatencyMS float64    `json:"latency_ms"`
}

// HighRisk reports whether the port is rated high or critical.
func (p Port) HighRisk() bool { return p.Risk >= ports.RiskHigh }

// Builder accumulates streamed scan results without keeping every probe in
// memory: only open ports are stored, everything else is counted.
type Builder struct {
	meta  Meta
	stats Stats
	open  map[netip.Addr][]Port
	up    map[netip.Addr]struct{}
	names map[netip.Addr]string
}

// NewBuilder starts a report for the given scan metadata.
func NewBuilder(meta Meta) *Builder {
	return &Builder{
		meta:  meta,
		open:  make(map[netip.Addr][]Port),
		up:    make(map[netip.Addr]struct{}),
		names: make(map[netip.Addr]string),
	}
}

// Add records one probe result.
func (b *Builder) Add(r scan.Result) {
	b.stats.Probes++
	switch r.State {
	case scan.Open:
		b.stats.Open++
		b.up[r.Addr] = struct{}{}
		p := Port{
			Port:      r.Port,
			Banner:    r.Banner,
			LatencyMS: float64(r.Latency.Microseconds()) / 1000,
		}
		if svc, ok := ports.Lookup(r.Port); ok {
			p.Service, p.Risk, p.Note = svc.Name, svc.Risk, svc.Note
		}
		if p.HighRisk() {
			b.stats.HighRisk++
		}
		b.open[r.Addr] = append(b.open[r.Addr], p)
	case scan.Closed:
		b.stats.Closed++
		b.up[r.Addr] = struct{}{}
	default:
		b.stats.Filtered++
	}
}

// SetName attaches a hostname (from the target spec or reverse DNS). The
// first name set for an address wins, so user-supplied names are kept.
func (b *Builder) SetName(addr netip.Addr, name string) {
	if _, exists := b.names[addr]; name != "" && !exists {
		b.names[addr] = name
	}
}

// OpenHosts returns the addresses with at least one open port, sorted.
func (b *Builder) OpenHosts() []netip.Addr {
	out := make([]netip.Addr, 0, len(b.open))
	for a := range b.open {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// Build finalizes the report. Hosts are sorted by address, ports ascending.
func (b *Builder) Build(finished time.Time, interrupted bool) Report {
	r := Report{
		Meta:        b.meta,
		Finished:    finished,
		DurationSec: finished.Sub(b.meta.Started).Seconds(),
		Interrupted: interrupted,
		Stats:       b.stats,
		Hosts:       []Host{},
	}
	r.Stats.HostsUp = len(b.up)
	r.Stats.OpenHosts = len(b.open)
	for _, a := range b.OpenHosts() {
		ps := slices.Clone(b.open[a])
		slices.SortFunc(ps, func(x, y Port) int { return cmp.Compare(x.Port, y.Port) })
		r.Hosts = append(r.Hosts, Host{Addr: a.String(), Hostname: b.names[a], Ports: ps})
	}
	return r
}

// Format is an output format.
type Format string

// Supported formats.
const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatHTML  Format = "html"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatTable, FormatJSON, FormatHTML:
		return f, nil
	}
	return "", fmt.Errorf("unknown format %q (want table, json or html)", s)
}

// Write renders r in the given format.
func Write(w io.Writer, f Format, r Report) error {
	switch f {
	case FormatJSON:
		return WriteJSON(w, r)
	case FormatHTML:
		return WriteHTML(w, r)
	default:
		return WriteTable(w, r)
	}
}
