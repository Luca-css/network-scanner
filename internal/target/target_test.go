package target

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addrs, ok := f[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func addrs(ts []Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Addr.String()
	}
	return out
}

func TestParse(t *testing.T) {
	resolver := fakeResolver{
		"router.lan":   {netip.MustParseAddr("192.168.1.1")},
		"dual-stack":   {netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("10.0.0.7")},
		"empty.lan":    {},
		"ipv6-only.ex": {netip.MustParseAddr("2001:db8::5")},
	}

	tests := []struct {
		name     string
		specs    []string
		maxHosts int
		want     []string
		wantLen  int
		wantErr  error // nil = any error when wantFail is set
		wantFail bool
	}{
		{name: "single ipv4", specs: []string{"10.0.0.1"}, want: []string{"10.0.0.1"}},
		{name: "single ipv6", specs: []string{"2001:db8::1"}, want: []string{"2001:db8::1"}},
		{name: "ipv4-mapped ipv6 is unmapped", specs: []string{"::ffff:10.0.0.1"}, want: []string{"10.0.0.1"}},
		{name: "cidr /30 skips network and broadcast", specs: []string{"10.0.0.0/30"}, want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "cidr /31 keeps both", specs: []string{"10.0.0.0/31"}, want: []string{"10.0.0.0", "10.0.0.1"}},
		{name: "cidr /32", specs: []string{"10.0.0.9/32"}, want: []string{"10.0.0.9"}},
		{name: "cidr host bits are masked", specs: []string{"10.0.0.6/30"}, want: []string{"10.0.0.5", "10.0.0.6"}},
		{name: "cidr /24", specs: []string{"192.168.1.0/24"}, wantLen: 254},
		{name: "ipv6 /126 keeps all", specs: []string{"2001:db8::/126"}, wantLen: 4},
		{name: "full range", specs: []string{"10.0.0.250-10.0.1.2"}, want: []string{"10.0.0.250", "10.0.0.251", "10.0.0.252", "10.0.0.253", "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1", "10.0.1.2"}},
		{name: "last octet shorthand", specs: []string{"10.0.0.1-3"}, want: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{name: "duplicates removed, order kept", specs: []string{"10.0.0.2", "10.0.0.1-3", "10.0.0.2"}, want: []string{"10.0.0.2", "10.0.0.1", "10.0.0.3"}},
		{name: "whitespace and empty specs ignored", specs: []string{" 10.0.0.1 ", ""}, want: []string{"10.0.0.1"}},
		{name: "hostname", specs: []string{"router.lan"}, want: []string{"192.168.1.1"}},
		{name: "hyphenated hostname prefers ipv4", specs: []string{"dual-stack"}, want: []string{"10.0.0.7"}},
		{name: "ipv6-only hostname", specs: []string{"ipv6-only.ex"}, want: []string{"2001:db8::5"}},
		{name: "limit exactly reached", specs: []string{"10.0.0.0/29"}, maxHosts: 6, wantLen: 6},

		{name: "huge ipv4 cidr rejected", specs: []string{"10.0.0.0/8"}, wantFail: true, wantErr: ErrTooManyHosts},
		{name: "huge ipv6 cidr rejected", specs: []string{"2001:db8::/64"}, wantFail: true, wantErr: ErrTooManyHosts},
		{name: "limit exceeded across specs", specs: []string{"10.0.0.0/29", "10.0.1.1"}, maxHosts: 6, wantFail: true, wantErr: ErrTooManyHosts},
		{name: "range larger than limit", specs: []string{"10.0.0.1-10.0.0.20"}, maxHosts: 10, wantFail: true, wantErr: ErrTooManyHosts},
		{name: "reversed range", specs: []string{"10.0.0.9-10.0.0.1"}, wantFail: true},
		{name: "reversed shorthand", specs: []string{"10.0.0.9-1"}, wantFail: true},
		{name: "shorthand out of byte", specs: []string{"10.0.0.1-300"}, wantFail: true},
		{name: "ipv6 range unsupported", specs: []string{"2001:db8::1-2001:db8::5"}, wantFail: true},
		{name: "bad cidr", specs: []string{"10.0.0.0/33"}, wantFail: true},
		{name: "unknown hostname", specs: []string{"nope.lan"}, wantFail: true},
		{name: "hostname with no addresses", specs: []string{"empty.lan"}, wantFail: true},
		{name: "invalid ip goes to resolver and fails", specs: []string{"999.1.1.1"}, wantFail: true},
		{name: "no targets", specs: []string{""}, wantFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Parser{MaxHosts: tt.maxHosts, Resolver: resolver}
			got, err := p.Parse(t.Context(), tt.specs)
			if tt.wantFail {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want error", tt.specs, addrs(got))
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("Parse(%q) error = %v, want %v", tt.specs, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.specs, err)
			}
			if tt.want != nil && !slices.Equal(addrs(got), tt.want) {
				t.Errorf("Parse(%q) = %v, want %v", tt.specs, addrs(got), tt.want)
			}
			if tt.wantLen != 0 && len(got) != tt.wantLen {
				t.Errorf("Parse(%q) returned %d targets, want %d", tt.specs, len(got), tt.wantLen)
			}
		})
	}
}

func TestParseKeepsHostnameAndDisabledResolver(t *testing.T) {
	p := Parser{Resolver: fakeResolver{"router.lan": {netip.MustParseAddr("192.168.1.1")}}}
	got, err := p.Parse(t.Context(), []string{"router.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "router.lan" || got[0].String() != "router.lan (192.168.1.1)" {
		t.Errorf("unexpected target %+v", got[0])
	}

	if _, err := (Parser{}).Parse(t.Context(), []string{"router.lan"}); err == nil {
		t.Error("hostname should fail when no resolver is configured")
	}
}
