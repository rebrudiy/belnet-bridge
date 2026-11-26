package main

import (
	"encoding/json"
	"testing"
)

func TestRealMetricsBooleanSchema(t *testing.T) {
	for _, fixture := range []struct {
		wire      string
		truncated bool
	}{
		{`{"connections":[{"id":1,"session_hash":"sid-hash","udp_tuple":"127.0.0.1:12000","connected":true}],"metadata_truncated":false}`, false},
		{`{"connections":[],"metadata_truncated":true}`, true},
	} {
		var got state
		if err := json.Unmarshal([]byte(fixture.wire), &got); err != nil {
			t.Fatalf("real state boolean rejected: %v", err)
		}
		if got.Truncated != fixture.truncated {
			t.Fatal("truncation flag lost")
		}
	}
}
