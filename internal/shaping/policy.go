// Package shaping frames datagrams and changes the size and timing of writes.
// It does not change TLS, authenticate peers, or make traffic indistinguishable.
package shaping

import "fmt"

const (
	MaxDatagram        = 65507
	MaxFrame           = 128 * 1024
	MaxBatch           = 16
	MaxQueue           = 64
	MaxQueueBytes      = 1024 * 1024
	MaxDelayMS         = 100
	InitialDummyCredit = 64 * 1024
)

// Policy uses milliseconds and bytes so the JSON is directly reviewable.
// Zero values mean one datagram per frame, with no intentional padding or delay.
type Policy struct {
	PadTo           int `json:"pad_to"`
	PadJitter       int `json:"pad_jitter"`
	BatchMax        int `json:"batch_max"`
	BatchDelayMS    int `json:"batch_delay_ms"`
	PaceMinMS       int `json:"pace_min_ms"`
	PaceJitterMS    int `json:"pace_jitter_ms"`
	DummyIntervalMS int `json:"dummy_interval_ms"`
	DummyBytes      int `json:"dummy_bytes"`
	WarmupFrames    int `json:"warmup_frames"`
}

type Profile struct {
	Name string `json:"name"`
	Up   Policy `json:"up"`
	Down Policy `json:"down"`
}

func (p Profile) Validate() error {
	if len(p.Name) > 128 {
		return fmt.Errorf("profile name exceeds 128 bytes")
	}
	if err := p.Up.Validate(); err != nil {
		return fmt.Errorf("up policy: %w", err)
	}
	if err := p.Down.Validate(); err != nil {
		return fmt.Errorf("down policy: %w", err)
	}
	return nil
}

func (p Policy) Validate() error {
	if p.PadTo < 0 || p.PadTo > 4096 || p.PadJitter < 0 || p.PadJitter > 4096 {
		return fmt.Errorf("padding values must be between 0 and 4096 bytes")
	}
	if p.BatchMax < 0 || p.BatchMax > MaxBatch {
		return fmt.Errorf("batch_max must be between 0 and %d", MaxBatch)
	}
	if p.BatchDelayMS < 0 || p.BatchDelayMS > MaxDelayMS {
		return fmt.Errorf("batch_delay_ms must be between 0 and %d", MaxDelayMS)
	}
	if p.PaceMinMS < 0 || p.PaceJitterMS < 0 || p.PaceMinMS > MaxDelayMS || p.PaceJitterMS > MaxDelayMS-p.PaceMinMS {
		return fmt.Errorf("maximum pacing interval must be between 0 and %d ms", MaxDelayMS)
	}
	if p.DummyIntervalMS != 0 && (p.DummyIntervalMS < 10 || p.DummyIntervalMS > 60000) {
		return fmt.Errorf("dummy_interval_ms must be 0 or between 10 and 60000")
	}
	if p.DummyBytes < 0 || p.DummyBytes > 4096 || p.WarmupFrames < 0 || p.WarmupFrames > 8 {
		return fmt.Errorf("dummy_bytes must be 0..4096 and warmup_frames 0..8")
	}
	return nil
}

func (p Policy) batchMax() int {
	if p.BatchMax == 0 {
		return 1
	}
	return p.BatchMax
}
