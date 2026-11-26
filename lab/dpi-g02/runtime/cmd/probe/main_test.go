package main

import (
	"testing"
	"time"
)

func TestClockSnapshotMatchesVMPrecision(t *testing.T) {
	now := time.Unix(1795100000, 123456789)
	sample := clockSnapshot(now)
	if sample["unix_micros"] != now.UnixMicro() || sample["utc"] != now.UTC().Format(time.RFC3339Nano) {
		t.Fatal("VM sample clock fields differ")
	}
}
