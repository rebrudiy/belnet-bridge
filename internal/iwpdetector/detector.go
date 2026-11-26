// Package iwpdetector recognizes initial BelNet IWP introductions using known
// public relay identities. It does not recognize established encrypted sessions.
package iwpdetector

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	identitySize = 32
	tagSize      = 32
	introSize    = 224
)

var zbase32 = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769").WithPadding(base32.NoPadding)

type relay struct {
	key      [32]byte
	identity string
}

// Detector holds immutable, public information and is safe for concurrent use.
type Detector struct {
	relays []relay
}

// New prepares a detector for at least one 32-byte public identity (RC field k).
// These identities are not the transport public keys from RC address records.
func New(identities [][]byte) (*Detector, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one public relay identity is required")
	}
	d := &Detector{relays: make([]relay, 0, len(identities))}
	for i, identity := range identities {
		if len(identity) != identitySize {
			return nil, fmt.Errorf("identity %d: got %d bytes, want %d", i, len(identity), identitySize)
		}
		d.relays = append(d.relays, relay{
			key:      blake2b.Sum256(identity),
			identity: hex.EncodeToString(identity),
		})
	}
	return d, nil
}

// Match checks a complete, reassembled UDP payload for the 224-byte initial IWP
// introduction. It returns the matching recipient's lowercase identity hex.
// A match is a protocol test with public inputs, not proof of sender identity.
func (d *Detector) Match(payload []byte) (matched bool, identity string) {
	if len(payload) != introSize {
		return false, ""
	}
	for _, r := range d.relays {
		// New enforces the fixed 32-byte key; New256 cannot fail for this size.
		h, _ := blake2b.New256(r.key[:])
		_, _ = h.Write(payload[tagSize:])
		tag := h.Sum(nil)
		if subtle.ConstantTimeCompare(tag, payload[:tagSize]) == 1 {
			return true, r.identity
		}
	}
	return false, ""
}

// ParseIdentity accepts a 32-byte hexadecimal identity or a z-base-32 .mnode
// address. Whitespace and letter case are normalized; malformed inputs fail.
func ParseIdentity(value string) ([]byte, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 2*identitySize {
		identity, err := hex.DecodeString(value)
		if err == nil {
			return identity, nil
		}
	}
	if strings.HasSuffix(value, ".mnode") {
		encoded := strings.TrimSuffix(value, ".mnode")
		identity, err := zbase32.DecodeString(encoded)
		if err == nil && len(identity) == identitySize && zbase32.EncodeToString(identity) == encoded {
			return identity, nil
		}
	}
	return nil, fmt.Errorf("invalid public relay identity: expected 64 hex characters or z-base-32 .mnode address")
}
