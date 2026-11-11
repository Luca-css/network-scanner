package ports

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ErrEmpty is returned when a specification yields no ports.
var ErrEmpty = errors.New("empty port specification")

// Parse converts a comma-separated port specification into a sorted,
// de-duplicated list. Each element may be:
//
//	443        a single port
//	1-1024     an inclusive range
//	top100     the 100 most common TCP ports
//	critical   the high/critical-risk ports from the catalog
//	all        1-65535
//
// Whitespace around elements is ignored; keywords are case-insensitive.
func Parse(spec string) ([]uint16, error) {
	seen := make(map[uint16]struct{})
	add := func(ps ...uint16) {
		for _, p := range ps {
			seen[p] = struct{}{}
		}
	}

	for raw := range strings.SplitSeq(spec, ",") {
		item := strings.ToLower(strings.TrimSpace(raw))
		switch item {
		case "":
			continue
		case "top100":
			add(top100...)
			continue
		case "critical":
			add(Critical()...)
			continue
		case "all":
			item = "1-65535"
		}

		if lo, hi, isRange := strings.Cut(item, "-"); isRange {
			start, err := parsePort(lo)
			if err != nil {
				return nil, fmt.Errorf("range %q: %w", item, err)
			}
			end, err := parsePort(hi)
			if err != nil {
				return nil, fmt.Errorf("range %q: %w", item, err)
			}
			if start > end {
				return nil, fmt.Errorf("range %q: start is greater than end", item)
			}
			for p := int(start); p <= int(end); p++ {
				add(uint16(p))
			}
			continue
		}

		p, err := parsePort(item)
		if err != nil {
			return nil, err
		}
		add(p)
	}

	if len(seen) == 0 {
		return nil, ErrEmpty
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q (want 1-65535)", s)
	}
	return uint16(n), nil
}
