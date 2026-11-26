package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// integrityVerifier validates what was actually received. Upload ACKs cover a
// prefix only; they do not imply every sent byte was accepted by the backend.
// One caller owns the verifier; RunClient uses it only in its reader goroutine.
type integrityVerifier struct {
	plan           Plan
	downloadIndex  int
	uploadPrefixes map[int64]string
	lastAck        int64
}

func newIntegrityVerifier(p Plan) *integrityVerifier {
	v := &integrityVerifier{plan: p, uploadPrefixes: map[int64]string{}}
	if p.Family == "upload" {
		h := sha256.New()
		var n int64
		v.uploadPrefixes[0] = hex.EncodeToString(h.Sum(nil))
		for _, a := range p.Up {
			payload, _ := Payload(a.Kind, a.Seq, a.Bytes, p.Seed, nil)
			h.Write(payload)
			n += int64(len(payload))
			v.uploadPrefixes[n] = hex.EncodeToString(h.Sum(nil))
		}
	}
	return v
}
func (v *integrityVerifier) download(data []byte) bool {
	if v.downloadIndex >= len(v.plan.Down) {
		return false
	}
	a := v.plan.Down[v.downloadIndex]
	v.downloadIndex++
	expected, e := Payload(a.Kind, a.Seq, a.Bytes, v.plan.Seed+7, nil)
	return e == nil && bytes.Equal(data, expected)
}
func (v *integrityVerifier) uploadACK(data []byte) (int64, bool) {
	var ack struct {
		Kind  string `json:"kind"`
		Seq   int    `json:"seq"`
		Bytes int64  `json:"accepted_bytes"`
		SHA   string `json:"sha256"`
	}
	if json.Unmarshal(data, &ack) != nil || ack.Kind != "upload-ack" || ack.Bytes < v.lastAck {
		return 0, false
	}
	want, ok := v.uploadPrefixes[ack.Bytes]
	if !ok || ack.SHA != want {
		return 0, false
	}
	v.lastAck = ack.Bytes
	return ack.Bytes, true
}
