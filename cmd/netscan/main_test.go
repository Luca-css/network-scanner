package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luca-css/network-scanner/internal/report"
)

func TestRunEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("220 test ftp ready\r\n"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	var stdout, stderr bytes.Buffer
	args := []string{"-p", fmt.Sprint(port), "-banner", "-o", "json", "-q", "127.0.0.1"}
	if code := run(t.Context(), args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if len(r.Hosts) != 1 || len(r.Hosts[0].Ports) != 1 {
		t.Fatalf("expected one open port, got %+v", r.Hosts)
	}
	if p := r.Hosts[0].Ports[0]; int(p.Port) != port || p.Banner != "220 test ftp ready" {
		t.Errorf("unexpected port result %+v", p)
	}
	if stderr.Len() != 0 {
		t.Errorf("-q should silence stderr, got %q", stderr.String())
	}
}

func TestRunWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.html")
	var stdout, stderr bytes.Buffer
	// Port 1 on localhost is almost certainly closed; content doesn't matter here.
	code := run(t.Context(), []string{"-p", "1", "-o", "html", "-out", out, "127.0.0.1"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!DOCTYPE html>") {
		t.Errorf("file does not look like HTML: %.60q", data)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty when -out is set")
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no targets", []string{}},
		{"bad port", []string{"-p", "70000", "127.0.0.1"}},
		{"bad format", []string{"-o", "xml", "127.0.0.1"}},
		{"bad concurrency", []string{"-c", "0", "127.0.0.1"}},
		{"too many hosts", []string{"10.0.0.0/8"}},
		{"unknown flag", []string{"-nope", "127.0.0.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitUsage, stderr.String())
			}
		})
	}
}

func TestRunInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled: nothing is probed, partial report still written
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"-p", "1-100", "127.0.0.1"}, &stdout, &stderr)
	if code != exitInterrupted {
		t.Errorf("exit code = %d, want %d", code, exitInterrupted)
	}
	if !strings.Contains(stdout.String(), "INTERRUPTED") {
		t.Errorf("table should flag partial results, got:\n%s", stdout.String())
	}
}
