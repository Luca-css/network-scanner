package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable writes a human-readable table, one row per open port.
func WriteTable(w io.Writer, r Report) error {
	if len(r.Hosts) == 0 {
		fmt.Fprintln(w, "(no open ports found)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "HOST\tPORT\tSERVICE\tRISK\tLATENCY\tBANNER")
		for _, h := range r.Hosts {
			host := h.Addr
			if h.Hostname != "" {
				host += " (" + h.Hostname + ")"
			}
			for _, p := range h.Ports {
				fmt.Fprintf(tw, "%s\t%d/tcp\t%s\t%s\t%.1fms\t%s\n",
					host, p.Port, orDash(p.Service), p.Risk, p.LatencyMS, orDash(truncate(p.Banner, 50)))
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	s := r.Stats
	_, err := fmt.Fprintf(w, "\n%d host(s) scanned, %d up, %d with open ports | probes: %d open, %d closed, %d filtered | high/critical: %d | %.2fs%s\n",
		r.HostsScanned, s.HostsUp, s.OpenHosts, s.Open, s.Closed, s.Filtered, s.HighRisk, r.DurationSec, interruptedNote(r))
	return err
}

func interruptedNote(r Report) string {
	if r.Interrupted {
		return " (INTERRUPTED: partial results)"
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

//go:embed template.html
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"ts":   func(t time.Time) string { return t.Format("2006-01-02 15:04:05 MST") },
	"join": strings.Join,
}).Parse(htmlSource))

// WriteHTML writes a self-contained HTML page. html/template escapes every
// value contextually, so banners or hostnames containing markup are rendered
// as text, never executed.
func WriteHTML(w io.Writer, r Report) error {
	return htmlTemplate.Execute(w, r)
}
