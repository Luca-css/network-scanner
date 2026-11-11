// Package ports holds the port catalog (well-known services and their risk
// notes) and the parser for port specifications such as "22,80,443",
// "1-1024", "top100" or "critical".
package ports

import (
	"fmt"
	"slices"
)

// Risk classifies how sensitive an exposed service usually is. It is a
// heuristic for triage, not a vulnerability verdict.
type Risk int

// Risk levels, ordered from least to most severe.
const (
	RiskInfo Risk = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// String returns the lower-case name of the risk level.
func (r Risk) String() string {
	switch r {
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "info"
	}
}

// MarshalText makes Risk serialize as its name in JSON.
func (r Risk) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText parses a risk name, so JSON reports can be read back.
func (r *Risk) UnmarshalText(b []byte) error {
	for _, c := range []Risk{RiskInfo, RiskMedium, RiskHigh, RiskCritical} {
		if string(b) == c.String() {
			*r = c
			return nil
		}
	}
	return fmt.Errorf("unknown risk %q", b)
}

// Service describes a well-known TCP service.
type Service struct {
	Port uint16
	Name string
	Risk Risk
	Note string // short, actionable reason why exposure matters
}

// catalog is the list of services the scanner knows how to label. Entries with
// Risk >= RiskHigh form the "critical" port set.
var catalog = []Service{
	{21, "ftp", RiskHigh, "Cleartext credentials; check for anonymous login"},
	{22, "ssh", RiskMedium, "Remote shell; enforce key auth and restrict source IPs"},
	{23, "telnet", RiskCritical, "Cleartext remote shell; should be disabled"},
	{25, "smtp", RiskMedium, "Check for open relay and STARTTLS"},
	{53, "dns", RiskMedium, "Check for open resolver / zone transfer (AXFR)"},
	{80, "http", RiskInfo, "Web service; prefer HTTPS"},
	{110, "pop3", RiskMedium, "Often cleartext credentials"},
	{111, "rpcbind", RiskHigh, "Exposes RPC services (NFS etc.)"},
	{135, "msrpc", RiskHigh, "Windows RPC endpoint mapper; should not face untrusted networks"},
	{139, "netbios-ssn", RiskHigh, "Legacy SMB over NetBIOS"},
	{143, "imap", RiskMedium, "Often cleartext credentials"},
	{161, "snmp", RiskHigh, "UDP normally; TCP exposure is unusual"},
	{389, "ldap", RiskHigh, "Directory service; check anonymous bind"},
	{443, "https", RiskInfo, "Web service over TLS"},
	{445, "microsoft-ds", RiskCritical, "SMB; frequent wormable-vulnerability target"},
	{636, "ldaps", RiskMedium, "Directory service over TLS"},
	{873, "rsync", RiskHigh, "Check for unauthenticated modules"},
	{1433, "mssql", RiskHigh, "Database exposed to network"},
	{1521, "oracle", RiskHigh, "Database exposed to network"},
	{2049, "nfs", RiskHigh, "Check export permissions"},
	{2375, "docker", RiskCritical, "Unauthenticated Docker API means root on host"},
	{3306, "mysql", RiskHigh, "Database exposed to network"},
	{3389, "rdp", RiskCritical, "Remote desktop; brute-force and RCE target, put behind VPN"},
	{5432, "postgresql", RiskHigh, "Database exposed to network"},
	{5900, "vnc", RiskCritical, "Remote desktop, often weak or no auth"},
	{5985, "winrm", RiskHigh, "Windows remote management over HTTP"},
	{5986, "winrm-https", RiskHigh, "Windows remote management over HTTPS"},
	{6379, "redis", RiskCritical, "Often deployed without authentication"},
	{8080, "http-alt", RiskInfo, "Alternate web service / proxy"},
	{8443, "https-alt", RiskInfo, "Alternate web service over TLS"},
	{9200, "elasticsearch", RiskCritical, "Often deployed without authentication"},
	{11211, "memcached", RiskHigh, "No authentication by default"},
	{27017, "mongodb", RiskCritical, "Often deployed without authentication"},
}

var byPort = func() map[uint16]Service {
	m := make(map[uint16]Service, len(catalog))
	for _, s := range catalog {
		m[s.Port] = s
	}
	return m
}()

// Lookup returns the catalog entry for port, if known.
func Lookup(port uint16) (Service, bool) {
	s, ok := byPort[port]
	return s, ok
}

// Catalog returns a copy of every known service, sorted by port.
func Catalog() []Service {
	return slices.Clone(catalog)
}

// Critical returns the ports whose risk is high or critical, sorted.
func Critical() []uint16 {
	var out []uint16
	for _, s := range catalog {
		if s.Risk >= RiskHigh {
			out = append(out, s.Port)
		}
	}
	return out
}

// top100 is the list of the 100 most common TCP ports, based on the
// frequency data shipped with nmap (nmap-services), sorted ascending.
var top100 = []uint16{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
	119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
	515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
	1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
	2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
	5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
	8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
	49153, 49154, 49155, 49156, 49157,
}

// Top100 returns a copy of the top-100 TCP port list.
func Top100() []uint16 {
	return slices.Clone(top100)
}
