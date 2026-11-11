package ports

import (
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []uint16
		wantLen int // used instead of want for large results
		wantErr bool
	}{
		{name: "single", spec: "22", want: []uint16{22}},
		{name: "list sorted and deduplicated", spec: "443, 22,80,22", want: []uint16{22, 80, 443}},
		{name: "range", spec: "20-23", want: []uint16{20, 21, 22, 23}},
		{name: "range and single overlap", spec: "1-3,2,5", want: []uint16{1, 2, 3, 5}},
		{name: "range of one", spec: "8080-8080", want: []uint16{8080}},
		{name: "max port", spec: "65535", want: []uint16{65535}},
		{name: "top100", spec: "top100", wantLen: 100},
		{name: "keyword case insensitive", spec: "TOP100", wantLen: 100},
		{name: "critical", spec: "critical", want: Critical()},
		{name: "all", spec: "all", wantLen: 65535},
		{name: "trailing comma ignored", spec: "22,", want: []uint16{22}},
		{name: "zero", spec: "0", wantErr: true},
		{name: "too big", spec: "65536", wantErr: true},
		{name: "negative", spec: "-1", wantErr: true},
		{name: "not a number", spec: "ssh", wantErr: true},
		{name: "reversed range", spec: "100-1", wantErr: true},
		{name: "open range", spec: "100-", wantErr: true},
		{name: "empty", spec: "", wantErr: true},
		{name: "only commas", spec: ", ,", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.spec, err)
			}
			if tt.want != nil && !slices.Equal(got, tt.want) {
				t.Errorf("Parse(%q) = %v, want %v", tt.spec, got, tt.want)
			}
			if tt.wantLen != 0 && len(got) != tt.wantLen {
				t.Errorf("Parse(%q) returned %d ports, want %d", tt.spec, len(got), tt.wantLen)
			}
			if !slices.IsSorted(got) {
				t.Errorf("Parse(%q) result is not sorted", tt.spec)
			}
		})
	}
}

func TestTop100IsSortedAndUnique(t *testing.T) {
	top := Top100()
	if len(top) != 100 {
		t.Fatalf("len(Top100()) = %d, want 100", len(top))
	}
	if !slices.IsSorted(top) || len(slices.Compact(slices.Clone(top))) != 100 {
		t.Error("Top100 must be sorted and unique")
	}
}

func TestCatalogConsistency(t *testing.T) {
	cat := Catalog()
	if !slices.IsSortedFunc(cat, func(a, b Service) int { return int(a.Port) - int(b.Port) }) {
		t.Error("catalog must be sorted by port")
	}
	for _, s := range cat {
		if s.Name == "" || s.Note == "" {
			t.Errorf("port %d: name and note are required", s.Port)
		}
		got, ok := Lookup(s.Port)
		if !ok || got != s {
			t.Errorf("Lookup(%d) = %v, %v", s.Port, got, ok)
		}
	}
	if _, ok := Lookup(1); ok {
		t.Error("Lookup(1) should be unknown")
	}
	for _, p := range Critical() {
		if s, _ := Lookup(p); s.Risk < RiskHigh {
			t.Errorf("port %d in Critical() has risk %s", p, s.Risk)
		}
	}
}

func TestRiskTextRoundTrip(t *testing.T) {
	for _, r := range []Risk{RiskInfo, RiskMedium, RiskHigh, RiskCritical} {
		b, _ := r.MarshalText()
		var got Risk
		if err := got.UnmarshalText(b); err != nil || got != r {
			t.Errorf("round trip %s: got %s, err %v", r, got, err)
		}
	}
	var r Risk
	if err := r.UnmarshalText([]byte("bogus")); err == nil {
		t.Error("expected error for unknown risk")
	}
}
