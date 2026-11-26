package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReporterDevelopmentIsDiagnosticAndUnknownSplitStillRejected(t *testing.T) {
	m := metadata()
	m.Split = "development"
	m.MeasurementStartMicros = epochNS / 1000
	m.MeasuredSeconds = 80
	m.PrefixGraceSeconds = 2
	m.CaptureEnded = utc(epochNS + int64(82*time.Second))
	m.WindowOffsetsSeconds = []int64{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(21)))
	path := filepath.Join(t.TempDir(), "synthetic-Q.pcap")
	if err := os.WriteFile(path, f.buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := extract(path, m)
	if err != nil || report.Metadata.Split != "development" || !report.CoverageComplete {
		t.Fatal("diagnostic reporter cannot retain development split", err)
	}
	m.Split = "unknown"
	if _, err = newParser(m); err == nil {
		t.Fatal("unknown split accepted")
	}
}
