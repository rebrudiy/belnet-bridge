package main

import (
	"net/http"
	"sync"
	"time"
)

// This metadata is opt-in and exposed only through the loopback lab API. It
// stores no token/SID/payload. A bounded history reports truncation explicitly.
type streamPacketEvent struct {
	AtUnixMicros           int64  `json:"at_unix_micros"`
	Connection             uint64 `json:"connection"`
	SessionHash            string `json:"session_hash"`
	Direction              int    `json:"direction"`
	Bytes                  int    `json:"bytes"`
	UDPTuple               string `json:"udp_tuple"`
	InputUnixMicros        int64  `json:"input_unix_micros,omitempty"`
	QueueWaitMicros        int64  `json:"queue_wait_micros,omitempty"`
	WriteStartedUnixMicros int64  `json:"write_started_unix_micros,omitempty"`
	BlockedWriteMicros     int64  `json:"blocked_write_micros,omitempty"`
}
type streamConnectionState struct {
	ID                    uint64 `json:"id"`
	SessionHash           string `json:"session_hash"`
	OpenedUnixMicros      int64  `json:"opened_unix_micros"`
	ClosedUnixMicros      int64  `json:"closed_unix_micros,omitempty"`
	Connected             bool   `json:"connected"`
	UDPTuple              string `json:"udp_tuple"`
	StreamTuple           string `json:"stream_tuple"`
	UpBytes               uint64 `json:"up_bytes"`
	DownBytes             uint64 `json:"down_bytes"`
	UpDatagrams           uint64 `json:"up_datagrams"`
	DownDatagrams         uint64 `json:"down_datagrams"`
	MaxQueueWaitMicros    int64  `json:"max_queue_wait_micros"`
	LocalQueueDropped     uint64 `json:"local_queue_dropped"`
	MaxBlockedWriteMicros int64  `json:"max_blocked_write_micros"`
	FailedWriteDatagrams  uint64 `json:"failed_write_datagrams"`
	FailedWriteBytes      uint64 `json:"failed_write_bytes"`
	ReceiverQueueDropped  uint64 `json:"receiver_queue_dropped"`
	MaxQueueAgeMicros     int64  `json:"max_queue_age_micros"`
	ExpiredDatagrams      uint64 `json:"expired_datagrams"`
	ExpiredBytes          uint64 `json:"expired_bytes"`
	MaxExpiredAgeMicros   int64  `json:"max_expired_age_micros"`
	MaxAllInputAgeMicros  int64  `json:"max_all_input_age_micros"`
}
type streamExpiredEvent struct {
	AtUnixMicros      int64  `json:"at_unix_micros"`
	InputUnixMicros   int64  `json:"input_unix_micros"`
	Connection        uint64 `json:"connection"`
	SessionHash       string `json:"session_hash"`
	Bytes             int    `json:"bytes"`
	AgeMicros         int64  `json:"age_micros"`
	MaxQueueAgeMicros int64  `json:"max_queue_age_micros"`
	Reason            string `json:"reason"`
}
type streamInputEvent struct {
	AtUnixMicros int64  `json:"at_unix_micros"`
	SessionHash  string `json:"session_hash"`
	Bytes        int    `json:"bytes"`
	Accepted     bool   `json:"accepted"`
}
type streamMetrics struct {
	mu            sync.Mutex
	next          uint64
	connections   []*streamConnectionState
	events        []streamPacketEvent
	truncated     uint64
	disconnects   []map[string]any
	inputs        []streamInputEvent
	expiredEvents []streamExpiredEvent
}

func (m *streamMetrics) open(session, udpTuple, streamTuple string) uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	m.connections = append(m.connections, &streamConnectionState{ID: m.next, SessionHash: session, OpenedUnixMicros: time.Now().UnixMicro(), Connected: true, UDPTuple: udpTuple, StreamTuple: streamTuple})
	if len(m.connections) > 4096 {
		m.connections = m.connections[2048:]
		m.truncated++
	}
	return m.next
}
func (m *streamMetrics) closed(id uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			c.Connected = false
			c.ClosedUnixMicros = time.Now().UnixMicro()
			return
		}
	}
}
func (m *streamMetrics) packet(id uint64, direction, bytes int, tuple string) {
	m.packetQueued(id, direction, bytes, tuple, time.Time{}, time.Time{}, 0)
}

func (m *streamMetrics) packetQueued(id uint64, direction, bytes int, tuple string, input, writeStarted time.Time, dropped uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			if direction > 0 {
				c.UpBytes += uint64(bytes)
				c.UpDatagrams++
			} else {
				c.DownBytes += uint64(bytes)
				c.DownDatagrams++
			}
			now := time.Now()
			var queueWait, inputMicros, writeStartMicros, blockedMicros int64
			if !input.IsZero() {
				inputMicros = input.UnixMicro()
				queueWait = max(0, writeStarted.Sub(input).Microseconds())
				c.MaxQueueWaitMicros = max(c.MaxQueueWaitMicros, queueWait)
				c.MaxAllInputAgeMicros = max(c.MaxAllInputAgeMicros, queueWait)
			}
			if !writeStarted.IsZero() {
				writeStartMicros = writeStarted.UnixMicro()
				blockedMicros = max(0, now.Sub(writeStarted).Microseconds())
				c.MaxBlockedWriteMicros = max(c.MaxBlockedWriteMicros, blockedMicros)
			}
			c.LocalQueueDropped = max(c.LocalQueueDropped, dropped)
			m.events = append(m.events, streamPacketEvent{AtUnixMicros: now.UnixMicro(), Connection: id, SessionHash: c.SessionHash, Direction: direction, Bytes: bytes, UDPTuple: tuple, InputUnixMicros: inputMicros, QueueWaitMicros: queueWait, WriteStartedUnixMicros: writeStartMicros, BlockedWriteMicros: blockedMicros})
			if len(m.events) > 100000 {
				m.events = m.events[50000:]
				m.truncated++
			}
			return
		}
	}
}

func (m *streamMetrics) input(hash string, size int, at time.Time, accepted bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputs = append(m.inputs, streamInputEvent{at.UnixMicro(), hash, size, accepted})
	if len(m.inputs) > 100000 {
		m.inputs = m.inputs[50000:]
		m.truncated++
	}
}

func (m *streamMetrics) failedWrite(id uint64, size int, input, started time.Time, dropped uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			c.FailedWriteDatagrams++
			c.FailedWriteBytes += uint64(size)
			c.LocalQueueDropped = max(c.LocalQueueDropped, dropped)
			c.MaxQueueWaitMicros = max(c.MaxQueueWaitMicros, max(0, started.Sub(input).Microseconds()))
			c.MaxAllInputAgeMicros = max(c.MaxAllInputAgeMicros, max(0, started.Sub(input).Microseconds()))
			c.MaxBlockedWriteMicros = max(c.MaxBlockedWriteMicros, time.Since(started).Microseconds())
			return
		}
	}
}

func (m *streamMetrics) policy(id uint64, maxAge time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			c.MaxQueueAgeMicros = maxAge.Microseconds()
			return
		}
	}
}

func (m *streamMetrics) expired(id uint64, size int, input, at time.Time, limit time.Duration, dropped uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			age := int64(-1)
			inputMicros := int64(0)
			reason := "missing_input_timestamp"
			if !input.IsZero() {
				age = max(0, at.Sub(input).Microseconds())
				inputMicros = input.UnixMicro()
				reason = "max_forward_age"
				c.MaxExpiredAgeMicros = max(c.MaxExpiredAgeMicros, age)
				c.MaxAllInputAgeMicros = max(c.MaxAllInputAgeMicros, age)
			}
			c.ExpiredDatagrams++
			c.ExpiredBytes += uint64(size)
			c.LocalQueueDropped = max(c.LocalQueueDropped, dropped)
			m.expiredEvents = append(m.expiredEvents, streamExpiredEvent{at.UnixMicro(), inputMicros, id, c.SessionHash, size, age, limit.Microseconds(), reason})
			if len(m.expiredEvents) > 100000 {
				m.expiredEvents = m.expiredEvents[50000:]
				m.truncated++
			}
			return
		}
	}
}

func (m *streamMetrics) receiverDropped(id, dropped uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.connections {
		if c.ID == id {
			c.ReceiverQueueDropped = max(c.ReceiverQueueDropped, dropped)
			return
		}
	}
}
func (m *streamMetrics) disconnected(session, reason string, dropped uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnects = append(m.disconnects, map[string]any{"at_unix_micros": time.Now().UnixMicro(), "session_hash": session, "error_type": reason, "local_queue_dropped": dropped})
	if len(m.disconnects) > 4096 {
		m.disconnects = m.disconnects[2048:]
		m.truncated++
	}
}
func (m *streamMetrics) state() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	connections := make([]streamConnectionState, 0, len(m.connections))
	for _, c := range m.connections {
		connections = append(connections, *c)
	}
	return map[string]any{"connections": connections, "packet_events": append([]streamPacketEvent{}, m.events...), "udp_inputs": append([]streamInputEvent{}, m.inputs...), "expired_events": append([]streamExpiredEvent{}, m.expiredEvents...), "disconnects": append([]map[string]any{}, m.disconnects...), "metadata_truncated": m.truncated > 0, "truncated_batches": m.truncated, "snapshot_unix_micros": time.Now().UnixMicro()}
}
func (m *streamMetrics) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, m.state()) })
	return mux
}
