package traffic

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Recorder reconstructs TLS record boundaries from partial encrypted reads and
// writes. It stores no record payload. A shared recorder merges both directions.
type Recorder struct {
	mu        sync.Mutex
	parsers   [2]recordParser
	started   time.Time
	events    []Event
	clock     func() time.Time
	malformed bool
	bytesOut  uint64
	bytesIn   uint64
	window    time.Duration
	limit     int
}

type recordParser struct {
	header      [5]byte
	headerRead  int
	remaining   int
	bytes       int
	application bool
}

func NewRecorder() *Recorder { return &Recorder{clock: time.Now, window: Window, limit: MaxRecords} }

// NewCaptureRecorder keeps a longer lab trace for predeclared later-window
// evaluation. It is not an alternative model schema: callers must extract the
// normal Window/MaxRecords prefix from each selected starting point.
func NewCaptureRecorder() *Recorder {
	return &Recorder{clock: time.Now, window: 12 * time.Second, limit: 2048}
}

// ObserveConn must wrap the raw connection before tls.Client/tls.Server. It
// observes only successfully read/written ciphertext, never TLS plaintext.
func ObserveConn(conn net.Conn, clientSide bool, recorder *Recorder) net.Conn {
	return &observedConn{Conn: conn, recorder: recorder, clientSide: clientSide}
}

type observedConn struct {
	net.Conn
	recorder   *Recorder
	clientSide bool
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	direction := 1
	if c.clientSide {
		direction = -1
	}
	c.recorder.observe(direction, p[:n])
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	direction := -1
	if c.clientSide {
		direction = 1
	}
	c.recorder.observe(direction, p[:n])
	return n, err
}

func (r *Recorder) observe(direction int, data []byte) {
	if len(data) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if direction > 0 {
		r.bytesOut += uint64(len(data))
	} else {
		r.bytesIn += uint64(len(data))
	}
	if r.malformed || len(r.events) >= r.limit {
		return
	}
	observedAt := r.clock()
	index := 0
	if direction < 0 {
		index = 1
	}
	p := &r.parsers[index]
	for len(data) > 0 {
		if p.headerRead < 5 {
			n := copy(p.header[p.headerRead:], data)
			p.headerRead += n
			data = data[n:]
			if p.headerRead < 5 {
				return
			}
			if p.header[0] < 20 || p.header[0] > 24 || p.header[1] != 3 || p.header[2] > 4 {
				r.malformed = true
				return
			}
			p.remaining = int(binary.BigEndian.Uint16(p.header[3:5]))
			p.bytes = p.remaining + 5
			p.application = p.header[0] == 23
		}
		n := min(p.remaining, len(data))
		p.remaining -= n
		data = data[n:]
		if p.remaining > 0 {
			return
		}
		if p.application {
			if r.started.IsZero() {
				r.started = observedAt
			}
			delta := observedAt.Sub(r.started).Microseconds()
			if delta < 0 {
				delta = 0
			}
			if len(r.events) > 0 && delta < r.events[len(r.events)-1].AtMicros {
				delta = r.events[len(r.events)-1].AtMicros
			}
			if delta >= r.window.Microseconds() {
				return
			}
			r.events = append(r.events, Event{delta, direction, p.bytes})
			if len(r.events) >= r.limit {
				return
			}
		}
		*p = recordParser{}
	}
}

func (r *Recorder) EventsSnapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func (r *Recorder) StartedAt() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started, !r.started.IsZero()
}

func (r *Recorder) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events) >= r.limit || (!r.started.IsZero() && r.clock().Sub(r.started) >= r.window)
}

// Malformed reports an invalid outer TLS header, so callers can exclude corrupt
// observations rather than treating parser failure as a traffic class.
func (r *Recorder) Malformed() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.malformed }

// WireBytes counts all observed raw connection bytes, including TLS handshakes
// and traffic after the feature window. This is measurement metadata, never a
// classifier feature. TCP/IP headers and retransmissions are not counted here.
func (r *Recorder) WireBytes() (clientToServer, serverToClient uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytesOut, r.bytesIn
}
