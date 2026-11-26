// Package traffic classifies observable encrypted TLS record metadata. It never
// receives TLS keys, decrypted messages, IP addresses, ports or certificates.
package traffic

import (
	"fmt"
	"time"
)

const (
	SchemaVersion   = 1
	Window          = 2 * time.Second
	MaxRecords      = 64
	ClassBelNet     = "belnet"
	ClassBenign     = "benign"
	SplitTrain      = "train"
	SplitValidation = "validation"
	SplitTest       = "test"
)

// Event is one complete TLS outer application-data record. Bytes includes its
// five-byte header. TLS 1.3 encrypted handshake records also use outer type 23.
type Event struct {
	AtMicros  int64 `json:"at_micros"`
	Direction int   `json:"direction"` // +1 client to server; -1 server to client
	Bytes     int   `json:"bytes"`
}

// Observation metadata is retained only for provenance and split checks. Only
// Events enter Features and Model.Score. GroupID binds both entry connections
// and all variants from one source workload to the same split.
type Observation struct {
	SessionID string  `json:"session_id"`
	GroupID   string  `json:"group_id"`
	Split     string  `json:"split"`
	Class     string  `json:"class"`
	Profile   string  `json:"profile"`
	Events    []Event `json:"events"`
}

func (o Observation) group() string {
	if o.GroupID != "" {
		return o.GroupID
	}
	return o.SessionID
}

func (o Observation) validate() error {
	if o.SessionID == "" || o.group() == "" {
		return fmt.Errorf("observation needs a session/group ID")
	}
	if o.Class != ClassBelNet && o.Class != ClassBenign {
		return fmt.Errorf("unknown class %q", o.Class)
	}
	if len(o.Events) == 0 {
		return fmt.Errorf("observation %q has no TLS application records", o.SessionID)
	}
	var previous int64
	for i, e := range o.Events {
		if e.AtMicros < 0 || (i > 0 && e.AtMicros < previous) || (e.Direction != -1 && e.Direction != 1) || e.Bytes < 5 || e.Bytes > 65540 {
			return fmt.Errorf("observation %q contains invalid event %d", o.SessionID, i)
		}
		previous = e.AtMicros
	}
	return nil
}

func observedEvents(events []Event) []Event {
	end := len(events)
	if end > MaxRecords {
		end = MaxRecords
	}
	for i := 0; i < end; i++ {
		if events[i].AtMicros >= Window.Microseconds() {
			return events[:i]
		}
	}
	return events[:end]
}
