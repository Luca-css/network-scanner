// Package target parses scan target specifications (single IPs, CIDR blocks,
// IPv4 ranges and hostnames) and expands them into a de-duplicated list of
// addresses, refusing to expand ranges larger than a configured limit.
package target

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultMaxHosts is the default upper bound on the number of addresses a
// single Parse call may produce (a /16).
const DefaultMaxHosts = 1 << 16

// ErrTooManyHosts is returned when the expanded target list would exceed the
// configured limit.
var ErrTooManyHosts = errors.New("too many hosts")

// Target is a single address to scan. Name is set when the target was given
// as a hostname.
type Target struct {
	Addr netip.Addr
	Name string
}

func (t Target) String() string {
	if t.Name != "" {
		return t.Name + " (" + t.Addr.String() + ")"
	}
	return t.Addr.String()
}

// Resolver resolves hostnames. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Parser expands target specifications.
type Parser struct {
	// MaxHosts caps the total number of addresses. Zero means DefaultMaxHosts.
	MaxHosts int
	// Resolver is used for hostname targets. Nil disables hostname support.
	Resolver Resolver
}

// Parse expands every spec and returns the targets in input order, with
// duplicates removed. Supported forms:
//
//	192.168.1.10              single IPv4/IPv6 address
//	192.168.1.0/24            CIDR (network/broadcast skipped for IPv4 prefixes <= /30)
//	192.168.1.10-192.168.1.20 inclusive IPv4 range
//	192.168.1.10-20           shorthand: last octet range
//	scanme.example.com        hostname (first resolved address)
func (p Parser) Parse(ctx context.Context, specs []string) ([]Target, error) {
	limit := p.MaxHosts
	if limit <= 0 {
		limit = DefaultMaxHosts
	}

	var out []Target
	seen := make(map[netip.Addr]struct{})
	add := func(t Target) error {
		if _, dup := seen[t.Addr]; dup {
			return nil
		}
		if len(out) >= limit {
			return fmt.Errorf("%w: limit is %d", ErrTooManyHosts, limit)
		}
		seen[t.Addr] = struct{}{}
		out = append(out, t)
		return nil
	}

	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		if err := p.expand(ctx, spec, limit, add); err != nil {
			return nil, fmt.Errorf("target %q: %w", spec, err)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no targets")
	}
	return out, nil
}

func (p Parser) expand(ctx context.Context, spec string, limit int, add func(Target) error) error {
	switch {
	case strings.Contains(spec, "/"):
		prefix, err := netip.ParsePrefix(spec)
		if err != nil {
			return err
		}
		first, last := prefixBounds(prefix.Masked())
		return addRange(first, last, limit, add)

	case strings.Contains(spec, "-"):
		if first, last, ok, err := parseRange(spec); ok {
			if err != nil {
				return err
			}
			return addRange(first, last, limit, add)
		}
		// Not an IP range: hostnames may legitimately contain '-'.

	default:
		if addr, err := netip.ParseAddr(spec); err == nil {
			return add(Target{Addr: addr.Unmap()})
		}
	}
	return p.resolve(ctx, spec, add)
}

func (p Parser) resolve(ctx context.Context, host string, add func(Target) error) error {
	if p.Resolver == nil {
		return errors.New("not an IP address, CIDR or range (hostname resolution disabled)")
	}
	addrs, err := p.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("hostname resolved to no addresses")
	}
	// Prefer IPv4 to keep results predictable on dual-stack hosts.
	chosen := addrs[0]
	for _, a := range addrs {
		if a.Unmap().Is4() {
			chosen = a
			break
		}
	}
	return add(Target{Addr: chosen.Unmap(), Name: host})
}

// prefixBounds returns the usable first/last addresses of a masked prefix.
// For IPv4 prefixes of /30 or shorter the network and broadcast addresses are
// skipped, matching how hosts are actually addressed.
func prefixBounds(prefix netip.Prefix) (first, last netip.Addr) {
	first = prefix.Addr()
	last = lastAddr(prefix)
	if first.Is4() && prefix.Bits() <= 30 {
		first, last = first.Next(), last.Prev()
	}
	return first, last
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Addr().AsSlice()
	hostBits := len(bytes)*8 - prefix.Bits()
	for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
		n := min(hostBits, 8)
		bytes[i] |= byte(1<<n - 1)
		hostBits -= n
	}
	addr, _ := netip.AddrFromSlice(bytes)
	return addr
}

// parseRange handles "a.b.c.d-e.f.g.h" and "a.b.c.d-N". ok is false when the
// spec does not look like an IP range at all (e.g. a hyphenated hostname).
func parseRange(spec string) (first, last netip.Addr, ok bool, err error) {
	lo, hi, _ := strings.Cut(spec, "-")
	first, perr := netip.ParseAddr(strings.TrimSpace(lo))
	if perr != nil {
		return first, last, false, nil
	}
	hi = strings.TrimSpace(hi)
	if !first.Is4() {
		return first, last, true, errors.New("ranges are only supported for IPv4; use CIDR for IPv6")
	}

	if n, convErr := strconv.ParseUint(hi, 10, 8); convErr == nil {
		b := first.As4()
		b[3] = byte(n)
		last = netip.AddrFrom4(b)
	} else if last, perr = netip.ParseAddr(hi); perr != nil || !last.Is4() {
		return first, last, true, fmt.Errorf("invalid range end %q", hi)
	}

	if last.Less(first) {
		return first, last, true, errors.New("range start is greater than range end")
	}
	return first, last, true, nil
}

// addRange adds every address in [first, last], failing fast (before any
// allocation) if the range alone exceeds the limit.
func addRange(first, last netip.Addr, limit int, add func(Target) error) error {
	if !first.IsValid() || !last.IsValid() || last.Less(first) {
		return nil // e.g. a /31-style empty usable range never happens, but stay safe
	}
	size := new(big.Int).Sub(addrInt(last), addrInt(first))
	size.Add(size, big.NewInt(1))
	if size.Cmp(big.NewInt(int64(limit))) > 0 {
		return fmt.Errorf("%w: range has %s addresses, limit is %d", ErrTooManyHosts, size, limit)
	}
	for a := first; a.IsValid(); a = a.Next() {
		if err := add(Target{Addr: a}); err != nil {
			return err
		}
		if a == last {
			break
		}
	}
	return nil
}

func addrInt(a netip.Addr) *big.Int {
	return new(big.Int).SetBytes(a.AsSlice())
}
