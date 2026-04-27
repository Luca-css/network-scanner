package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type Host struct {
	IP        string
	Hostname  string
	Status    string
	OpenPorts []int
	ScanTime  float64
}

// ── Network helpers ───────────────────────────────────────────────────────────

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil // skip network and broadcast
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isUp(ip string) bool {
	ports := []string{"80", "443", "22", "445", "135"}
	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", ip+":"+p, 400*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func scanPorts(ip string) []int {
	ports := []int{21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5985, 8080}
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// ── Scanner ───────────────────────────────────────────────────────────────────

func scanHost(ip string) Host {
	start := time.Now()
	h := Host{IP: ip, Status: "down"}

	if isUp(ip) {
		h.Status = "up"
		h.Hostname = reverseLookup(ip)
		h.OpenPorts = scanPorts(ip)
	}

	h.ScanTime = time.Since(start).Seconds()
	return h
}

func scan(cidr string) []Host {
	ips, err := expandCIDR(cidr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CIDR inválido:", err)
		os.Exit(1)
	}

	fmt.Printf("\n  Scanning %s (%d hosts)...\n\n", cidr, len(ips))

	results := make([]Host, len(ips))
	jobs := make(chan int, len(ips))
	var wg sync.WaitGroup
	workers := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = scanHost(ips[i])
				if results[i].Status == "up" {
					color := "\033[32m" // green
					fmt.Printf("  %s[UP]\033[0m  %-16s  %-30s  ports: %v\n",
						color, results[i].IP, results[i].Hostname, results[i].OpenPorts)
				}
			}
		}()
	}

	for i := range ips {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// ── Report ────────────────────────────────────────────────────────────────────

const htmlTpl = `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Network Scan — {{.CIDR}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#020c1b;color:#c9d1d9}
header{background:#0a1628;border-bottom:1px solid #00d4ff22;padding:18px 32px}
header h1{font-size:1.2rem;color:#00d4ff}
header p{color:#484f58;font-size:.82rem;margin-top:4px}
.container{max-width:1200px;margin:0 auto;padding:24px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{background:#0a1628;border:1px solid #ffffff08;border-radius:8px;padding:14px;text-align:center}
.stat-num{font-size:1.8rem;font-weight:700;color:#00d4ff}
.stat-num.red{color:#ef4444}
.stat-label{font-size:.68rem;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.card{background:#0a1628;border:1px solid #ffffff08;border-radius:10px;padding:20px;margin-bottom:14px}
.card-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:#00d4ff;margin-bottom:14px}
.alert-box{background:#7f1d1d;border:1px solid #ef444444;border-radius:8px;padding:12px 16px;
  margin-bottom:14px;font-size:.82rem;color:#fca5a5}
table{width:100%;border-collapse:collapse;font-size:.76rem}
th{text-align:left;padding:8px 10px;color:#484f58;font-weight:500;border-bottom:1px solid #ffffff08}
td{padding:7px 10px;border-bottom:1px solid #ffffff05;font-family:monospace}
tr:hover td{background:#0d1f35}tr:last-child td{border:none}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-up{background:#4ade80}.dot-down{background:#ef4444}
.port{display:inline-block;background:#0d1f35;border:1px solid #00d4ff22;color:#00d4ff;
  padding:1px 7px;border-radius:4px;font-size:.68rem;margin:1px}
.port.danger{background:#2a0a0a;border-color:#ef444444;color:#ef4444}
footer{text-align:center;padding:16px;color:#484f58;font-size:.72rem}
</style></head><body>
<header>
  <h1>Network Scanner</h1>
  <p>Range: <strong>{{.CIDR}}</strong> &nbsp;·&nbsp; Scan: {{.ScannedAt}} &nbsp;·&nbsp; Duração: {{.Duration}}s</p>
</header>
<div class="container">
{{if .Alerts}}<div class="alert-box">⚠ {{.Alerts}}</div>{{end}}
<div class="stats">
  <div class="stat"><div class="stat-num">{{.Total}}</div><div class="stat-label">Total Hosts</div></div>
  <div class="stat"><div class="stat-num">{{.Up}}</div><div class="stat-label">Online</div></div>
  <div class="stat"><div class="stat-num red">{{.Down}}</div><div class="stat-label">Offline</div></div>
  <div class="stat"><div class="stat-num">{{.TotalPorts}}</div><div class="stat-label">Portas Abertas</div></div>
</div>
<div class="card">
  <div class="card-title">Hosts Descobertos</div>
  <table><thead><tr><th>Status</th><th>IP</th><th>Hostname</th><th>Portas Abertas</th><th>Scan (s)</th></tr></thead>
  <tbody>
  {{range .Hosts}}
  <tr>
    <td><span class="dot dot-{{.Status}}"></span>{{.Status}}</td>
    <td>{{.IP}}</td>
    <td>{{if .Hostname}}{{.Hostname}}{{else}}-{{end}}</td>
    <td>{{range .OpenPorts}}<span class="port{{if isDanger .}} danger{{end}}">{{.}}</span>{{end}}</td>
    <td>{{printf "%.2f" .ScanTime}}</td>
  </tr>
  {{end}}
  </tbody></table>
</div>
</div>
<footer>Network Scanner · Go · github.com/Luca-css/network-scanner · {{.ScannedAt}}</footer>
</body></html>`

func isDanger(port int) bool {
	danger := map[int]bool{23: true, 21: true, 139: true, 5985: true}
	return danger[port]
}

func generateReport(hosts []Host, cidr string, duration float64) {
	up, down, totalPorts := 0, 0, 0
	var alerts []string
	for _, h := range hosts {
		if h.Status == "up" {
			up++
			totalPorts += len(h.OpenPorts)
			for _, p := range h.OpenPorts {
				switch p {
				case 23:
					alerts = append(alerts, fmt.Sprintf("%s: Telnet (porta 23) exposto", h.IP))
				case 3389:
					alerts = append(alerts, fmt.Sprintf("%s: RDP (porta 3389) exposto", h.IP))
				case 445:
					alerts = append(alerts, fmt.Sprintf("%s: SMB (porta 445) exposto", h.IP))
				}
			}
		} else {
			down++
		}
	}

	funcMap := template.FuncMap{"isDanger": isDanger}
	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTpl))

	data := map[string]interface{}{
		"CIDR":       cidr,
		"ScannedAt":  time.Now().Format("02/01/2006 15:04:05"),
		"Duration":   fmt.Sprintf("%.1f", duration),
		"Total":      len(hosts),
		"Up":         up,
		"Down":       down,
		"TotalPorts": totalPorts,
		"Hosts":      hosts,
		"Alerts":     strings.Join(alerts, " | "),
	}

	fname := fmt.Sprintf("scan_%s.html", time.Now().Format("20060102_150405"))
	f, _ := os.Create(fname)
	defer f.Close()
	tmpl.Execute(f, data)

	// Also save JSON
	jname := strings.Replace(fname, ".html", ".json", 1)
	jf, _ := os.Create(jname)
	enc := json.NewEncoder(jf)
	enc.SetIndent("", "  ")
	enc.Encode(hosts)
	jf.Close()

	fmt.Printf("\n  Hosts online:  %d / %d\n", up, len(hosts))
	fmt.Printf("  Portas abertas: %d\n", totalPorts)
	fmt.Printf("  HTML: %s\n", fname)
	fmt.Printf("  JSON: %s\n\n", jname)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	cidr := "192.168.1.0/24"
	if len(os.Args) > 1 {
		cidr = os.Args[1]
	}

	start := time.Now()
	hosts := scan(cidr)
	duration := time.Since(start).Seconds()
	generateReport(hosts, cidr, duration)
}
