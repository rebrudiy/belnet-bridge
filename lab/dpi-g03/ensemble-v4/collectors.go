package main

import (
	"fmt"
	"path/filepath"
	"time"
)

// A union policy may reuse earlier development captures, while every report
// remains bound to the exact collector that existed before that capture.
type CollectorBinding struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}

type collectorManifest struct {
	Schema   string       `json:"schema"`
	Stage    string       `json:"stage"`
	Frozen   time.Time    `json:"frozen_at"`
	Groups   []Assignment `json:"groups"`
	Measured int          `json:"measured_seconds"`
	Capture  int          `json:"capture_seconds"`
	Grace    int          `json:"prefix_grace_seconds"`
	Offsets  []int        `json:"window_offsets_seconds"`
	Cap      int64        `json:"pcap_cap_bytes"`
}

type captureOrigin struct {
	SHA    string
	Frozen time.Time
}

func captureOrigins(f Freeze, projectionDirectory string) (map[string]captureOrigin, error) {
	origins := map[string]captureOrigin{}
	if len(f.Collectors) == 0 {
		for _, a := range f.Groups {
			if a.CollectorSHA != "" {
				return nil, fmt.Errorf("assignment collector requires explicit verified collector bindings")
			}
			origins[a.GroupID] = captureOrigin{f.CollectorSHA, f.Frozen}
		}
		return origins, nil
	}
	if f.Stage != "B1" {
		return nil, fmt.Errorf("development collector union is B1 only; sealed test has one fresh collector")
	}
	expected := map[string]Assignment{}
	for _, a := range f.Groups {
		if !hexSHA(a.CollectorSHA) {
			return nil, fmt.Errorf("group %s missing exact collector SHA", a.GroupID)
		}
		expected[a.GroupID] = a
	}
	seen := map[string]bool{}
	for _, binding := range f.Collectors {
		if !hexSHA(binding.SHA) || seen[binding.SHA] || binding.Path == "" {
			return nil, fmt.Errorf("invalid/repeated collector binding")
		}
		seen[binding.SHA] = true
		p := binding.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(projectionDirectory, p)
		}
		var c collectorManifest
		actual, err := read(p, &c)
		if err != nil || actual != binding.SHA {
			return nil, fmt.Errorf("collector bytes do not match binding %s", binding.SHA)
		}
		if c.Schema != "belnet-g03-collector/v4" || c.Stage != "B1" || c.Frozen.IsZero() || c.Frozen.After(f.Frozen) || c.Measured != f.MeasuredSeconds || c.Capture != f.CaptureSeconds || c.Grace != f.PrefixGrace || c.Cap != f.CaptureCap || !sameInts(c.Offsets, f.WindowOffsets) {
			return nil, fmt.Errorf("collector must be same-contract earlier B1 development freeze")
		}
		local := map[string]bool{}
		for _, a := range c.Groups {
			if local[a.GroupID] || a.Scope != "primary" || (a.Split != "train" && a.Split != "validation") {
				return nil, fmt.Errorf("collector contains repeated/nondevelopment group")
			}
			local[a.GroupID] = true
			want, ok := expected[a.GroupID]
			if !ok || want.CollectorSHA != binding.SHA || !sameCore(want, a) || !compatibleOptional(want, a) {
				return nil, fmt.Errorf("collector has undeclared or mismatched group %s", a.GroupID)
			}
			if _, exists := origins[a.GroupID]; exists {
				return nil, fmt.Errorf("group belongs to multiple collectors")
			}
			origins[a.GroupID] = captureOrigin{binding.SHA, c.Frozen}
		}
	}
	if len(origins) != len(expected) {
		return nil, fmt.Errorf("collector union does not cover every declared group")
	}
	if !seen[f.CollectorSHA] {
		return nil, fmt.Errorf("original collector missing from union")
	}
	return origins, nil
}
