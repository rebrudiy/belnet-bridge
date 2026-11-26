// Package streamframe encodes bounded UDP datagrams on an existing byte stream.
// It does not authenticate a peer, encrypt data, select a target, retain sessions,
// retry writes, or make stream delivery equivalent to reliable UDP delivery.
// Callers own deadlines and must serialize each stream's readers and writers.
package streamframe

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MaxDatagram    = 65507
	MaxTokenLength = 1024
)

var (
	ErrBadMagic           = errors.New("streamframe: invalid handshake magic")
	ErrInvalidSession     = errors.New("streamframe: session ID must be nonzero")
	ErrInvalidTokenLength = errors.New("streamframe: token must contain 1..1024 bytes")
	ErrBadAcceptance      = errors.New("streamframe: invalid acceptance marker")
	ErrFrameTooLarge      = errors.New("streamframe: datagram exceeds 65507 bytes")
)

// WriteHandshake writes BDG1, the opaque 32-byte session ID, a uint16 token byte
// length, and the token. Validation occurs before writing any bytes. The caller
// must protect the stream and authorize the token before accepting the session.
func WriteHandshake(w io.Writer, sid [32]byte, token string) error {
	if sid == ([32]byte{}) {
		return ErrInvalidSession
	}
	if len(token) == 0 || len(token) > MaxTokenLength {
		return ErrInvalidTokenLength
	}
	var header [38]byte
	copy(header[:4], "BDG1")
	copy(header[4:36], sid[:])
	binary.BigEndian.PutUint16(header[36:], uint16(len(token)))
	if err := writeAll(w, header[:], "write handshake"); err != nil {
		return err
	}
	return writeAll(w, []byte(token), "write handshake")
}

// ReadHandshake parses a handshake without authenticating it. A non-nil error
// always returns a zero ID and empty token. Token allocation is bounded before
// reading its bytes. Error strings never include token or underlying I/O text.
func ReadHandshake(r io.Reader) ([32]byte, string, error) {
	var header [38]byte
	if err := readExact(r, header[:4], false, "read handshake"); err != nil {
		return [32]byte{}, "", err
	}
	if string(header[:4]) != "BDG1" {
		return [32]byte{}, "", ErrBadMagic
	}
	if err := readExact(r, header[4:], true, "read handshake"); err != nil {
		return [32]byte{}, "", err
	}
	var sid [32]byte
	copy(sid[:], header[4:36])
	if sid == ([32]byte{}) {
		return [32]byte{}, "", ErrInvalidSession
	}
	size := int(binary.BigEndian.Uint16(header[36:]))
	if size == 0 || size > MaxTokenLength {
		return [32]byte{}, "", ErrInvalidTokenLength
	}
	token := make([]byte, size)
	if err := readExact(r, token, true, "read handshake"); err != nil {
		return [32]byte{}, "", err
	}
	return sid, string(token), nil
}

// WriteAccepted writes BDGA. It must only be called after external authorization
// and session attachment succeed; this codec makes no authorization decision.
func WriteAccepted(w io.Writer) error { return writeAll(w, []byte("BDGA"), "write acceptance") }

// ReadAccepted requires the exact BDGA marker. Bytes following it remain unread.
func ReadAccepted(r io.Reader) error {
	var marker [4]byte
	if err := readExact(r, marker[:], false, "read acceptance"); err != nil {
		return err
	}
	if string(marker[:]) != "BDGA" {
		return ErrBadAcceptance
	}
	return nil
}

// Write emits a uint32 big-endian length followed by one complete UDP payload.
// Empty payloads are real datagrams. Oversized payloads write nothing. A failed
// write may already have emitted a prefix: discard the stream rather than retry
// the datagram on that stream. There is no per-datagram delivery acknowledgement.
func Write(w io.Writer, packet []byte) error {
	if len(packet) > MaxDatagram {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(packet)))
	if err := writeAll(w, header[:], "write frame"); err != nil {
		return err
	}
	return writeAll(w, packet, "write frame")
}

// Read returns one owned complete datagram, validating the length before payload
// allocation. An empty datagram is a non-nil empty slice with nil error. EOF
// before a header is io.EOF; any truncated header or payload is unexpected EOF.
// Discard the stream after an error: this API does not resynchronize framing.
func Read(r io.Reader) ([]byte, error) {
	var header [4]byte
	if err := readExact(r, header[:], false, "read frame"); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxDatagram {
		return nil, ErrFrameTooLarge
	}
	packet := make([]byte, int(size))
	if err := readExact(r, packet, true, "read frame"); err != nil {
		return nil, err
	}
	return packet, nil
}

func readExact(r io.Reader, b []byte, started bool, operation string) error {
	_, err := io.ReadFull(r, b)
	if started && errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return safeIOError(operation, err)
}

func writeAll(w io.Writer, b []byte, operation string) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return safeIOError(operation, err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Preserve errors.Is/errors.As without copying arbitrary I/O error text into
// logs. An I/O implementation could otherwise put handshake bytes in its error.
type streamIOError struct {
	operation string
	cause     error
}

func (e *streamIOError) Error() string { return "streamframe: " + e.operation + " failed" }
func (e *streamIOError) Unwrap() error { return e.cause }
func safeIOError(operation string, err error) error {
	if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF || err == io.ErrShortWrite {
		return err
	}
	return &streamIOError{operation: operation, cause: err}
}
