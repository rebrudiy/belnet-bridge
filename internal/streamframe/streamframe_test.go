package streamframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func validSID() [32]byte {
	var sid [32]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	return sid
}

type partialWriter struct {
	dst   bytes.Buffer
	limit int
}

func (w *partialWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.dst.Write(p)
}

type noProgressWriter struct{}

func (noProgressWriter) Write([]byte) (int, error) { return 0, nil }

type invalidCountWriter int

func (w invalidCountWriter) Write([]byte) (int, error) { return int(w), nil }

type forbiddenWriter struct{ t *testing.T }

func (w forbiddenWriter) Write([]byte) (int, error) {
	w.t.Fatal("invalid input wrote bytes")
	return 0, io.ErrShortWrite
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

type failReader struct{ err error }

func (r failReader) Read([]byte) (int, error) { return 0, r.err }

type headerOnlyReader struct {
	header []byte
	calls  int
}

func (r *headerOnlyReader) Read(p []byte) (int, error) {
	r.calls++
	if len(r.header) == 0 {
		panic("oversized length requested body")
	}
	n := copy(p, r.header)
	r.header = r.header[n:]
	return n, nil
}

func TestFrameRoundTripsAndEOF(t *testing.T) {
	var wire bytes.Buffer
	sizes := []int{0, 1, 1200, 60000, MaxDatagram}
	for _, n := range sizes {
		packet := bytes.Repeat([]byte{byte(n % 251)}, n)
		if err := Write(&wire, packet); err != nil {
			t.Fatal(err)
		}
	}
	reader := iotest.OneByteReader(&wire)
	for _, n := range sizes {
		packet, err := Read(reader)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if packet == nil || !bytes.Equal(packet, bytes.Repeat([]byte{byte(n % 251)}, n)) {
			t.Fatalf("size %d corrupted or empty nil", n)
		}
	}
	if packet, err := Read(reader); packet != nil || err != io.EOF {
		t.Fatalf("after all frames: %v, %v", packet, err)
	}
}

func TestHandshakeAndAcceptanceFragmentation(t *testing.T) {
	for _, token := range []string{"x", strings.Repeat("t", MaxTokenLength), strings.Repeat("ж", MaxTokenLength/2)} {
		writer := &partialWriter{limit: 1}
		sid := validSID()
		if err := WriteHandshake(writer, sid, token); err != nil {
			t.Fatal(err)
		}
		if err := WriteAccepted(writer); err != nil {
			t.Fatal(err)
		}
		if err := Write(writer, []byte("next frame")); err != nil {
			t.Fatal(err)
		}
		reader := iotest.OneByteReader(&writer.dst)
		gotSID, gotToken, err := ReadHandshake(reader)
		if err != nil || gotSID != sid || gotToken != token {
			t.Fatalf("handshake mismatch, err=%v", err)
		}
		if err := ReadAccepted(reader); err != nil {
			t.Fatal(err)
		}
		packet, err := Read(reader)
		if err != nil || string(packet) != "next frame" {
			t.Fatal("acceptance consumed next frame")
		}
	}
}

func TestWriteValidatesBeforeWriting(t *testing.T) {
	if err := Write(forbiddenWriter{t}, make([]byte, MaxDatagram+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	for _, token := range []string{"", strings.Repeat("secret", MaxTokenLength)} {
		if err := WriteHandshake(forbiddenWriter{t}, validSID(), token); !errors.Is(err, ErrInvalidTokenLength) {
			t.Fatal(err)
		}
	}
	if err := WriteHandshake(forbiddenWriter{t}, [32]byte{}, "secret"); !errors.Is(err, ErrInvalidSession) {
		t.Fatal(err)
	}
}

func TestReadRejectsLengthBeforeBody(t *testing.T) {
	for _, size := range []uint32{MaxDatagram + 1, 1 << 31, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		reader := &headerOnlyReader{header: header[:]}
		packet, err := Read(reader)
		if !errors.Is(err, ErrFrameTooLarge) || packet != nil || reader.calls != 1 {
			t.Fatalf("length %d was not rejected at header: %v", size, err)
		}
	}
	for _, size := range []uint16{0, MaxTokenLength + 1, ^uint16(0)} {
		header := handshakeBytes(validSID(), size, nil)
		reader := &headerOnlyReader{header: header}
		sid, token, err := ReadHandshake(reader)
		if !errors.Is(err, ErrInvalidTokenLength) || sid != ([32]byte{}) || token != "" {
			t.Fatalf("token length %d: %v", size, err)
		}
	}
}

func TestFrameShortWrites(t *testing.T) {
	writer := &partialWriter{limit: 7}
	want := bytes.Repeat([]byte{0xa7}, 1200)
	if err := Write(writer, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&writer.dst)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("short writes corrupted frame: %v", err)
	}
	for _, writer := range []io.Writer{noProgressWriter{}, invalidCountWriter(-1), invalidCountWriter(10000)} {
		if err := Write(writer, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("bad writer: %v", err)
		}
	}
	if err := WriteHandshake(noProgressWriter{}, validSID(), "secret"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := WriteAccepted(noProgressWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

func TestTruncatedFramesAndHandshake(t *testing.T) {
	for _, wire := range [][]byte{{0}, {0, 0}, {0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 3, 1, 2}} {
		if packet, err := Read(bytes.NewReader(wire)); packet != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated frame %x: %v", wire, err)
		}
	}
	full := handshakeBytes(validSID(), 3, []byte("abc"))
	for end := range len(full) {
		sid, token, err := ReadHandshake(bytes.NewReader(full[:end]))
		want := io.ErrUnexpectedEOF
		if end == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) || sid != ([32]byte{}) || token != "" {
			t.Fatalf("handshake truncated at %d: %v", end, err)
		}
	}
	for end := range 4 {
		err := ReadAccepted(bytes.NewReader([]byte("BDGA")[:end]))
		want := io.ErrUnexpectedEOF
		if end == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("acceptance truncated at %d: %v", end, err)
		}
	}
}

func TestRejectsWrongMagicAndZeroSession(t *testing.T) {
	sid, token, err := ReadHandshake(bytes.NewReader([]byte("NOPE")))
	if !errors.Is(err, ErrBadMagic) || sid != ([32]byte{}) || token != "" {
		t.Fatalf("wrong magic: %v", err)
	}
	if _, _, err := ReadHandshake(bytes.NewReader(handshakeBytes([32]byte{}, 1, []byte{1}))); !errors.Is(err, ErrInvalidSession) {
		t.Fatal(err)
	}
	if err := ReadAccepted(strings.NewReader("BDG1")); !errors.Is(err, ErrBadAcceptance) {
		t.Fatal(err)
	}
}

func TestErrorsDoNotPrintTokenAndPreserveCause(t *testing.T) {
	const secret = "must-never-appear-in-log-token"
	cause := errors.New("underlying transport exposed " + secret)
	tests := []func() error{
		func() error { return WriteHandshake(failWriter{cause}, validSID(), secret) },
		func() error { _, _, err := ReadHandshake(failReader{cause}); return err },
		func() error { return Write(failWriter{cause}, []byte(secret)) },
		func() error { _, err := Read(failReader{cause}); return err },
		func() error { return WriteAccepted(failWriter{cause}) },
		func() error { return ReadAccepted(failReader{cause}) },
	}
	for _, run := range tests {
		err := run()
		if err == nil || strings.Contains(fmt.Sprint(err), secret) || !errors.Is(err, cause) {
			t.Fatalf("I/O error leaked content or lost cause")
		}
	}
	// Failure while reading the token body must not return an unauthenticated SID/token.
	reader := io.MultiReader(bytes.NewReader(handshakeBytes(validSID(), uint16(len(secret)), nil)), failReader{cause})
	sid, token, err := ReadHandshake(reader)
	if sid != ([32]byte{}) || token != "" || strings.Contains(err.Error(), secret) || !errors.Is(err, cause) {
		t.Fatal("token-body failure leaked content")
	}
}

func handshakeBytes(sid [32]byte, size uint16, token []byte) []byte {
	wire := make([]byte, 38)
	copy(wire, "BDG1")
	copy(wire[4:36], sid[:])
	binary.BigEndian.PutUint16(wire[36:], size)
	return append(wire, token...)
}

func FuzzReadFrameLength(f *testing.F) {
	for _, size := range []uint32{0, 1, 1200, 60000, MaxDatagram, MaxDatagram + 1, 1 << 31, ^uint32(0)} {
		f.Add(size, uint16(17))
	}
	f.Fuzz(func(t *testing.T, size uint32, available uint16) {
		body := bytes.Repeat([]byte{0x3c}, int(available)%2048)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		wire := append(header[:], body...)
		packet, err := Read(iotest.OneByteReader(bytes.NewReader(wire)))
		switch {
		case size > MaxDatagram:
			if !errors.Is(err, ErrFrameTooLarge) || packet != nil {
				t.Fatal("oversized length accepted")
			}
		case int(size) > len(body):
			if !errors.Is(err, io.ErrUnexpectedEOF) || packet != nil {
				t.Fatal("truncated payload accepted")
			}
		default:
			if err != nil || packet == nil || !bytes.Equal(packet, body[:int(size)]) {
				t.Fatal("valid bounded frame corrupted")
			}
		}
	})
}
