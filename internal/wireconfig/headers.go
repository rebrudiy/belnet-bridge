// Package wireconfig defines the authenticated v2 transport request.
package wireconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rebrudiy/belnet-bridge/internal/shaping"
)

const (
	VersionHeader = "X-Bridge-Version"
	SessionHeader = "X-Bridge-Session"
	ProfileHeader = "X-Bridge-Profile"
	TraceHeader   = "X-Bridge-Trace"
)

// Headers is shared by the tunnel and the matched benign lab client. Constant
// request length prevents the experiment's control metadata becoming a label.
func Headers(token, session string, profile shaping.Profile, path string) (http.Header, error) {
	if _, err := ParseSession(session); err != nil {
		return nil, err
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	h.Set(VersionHeader, "2")
	h.Set(SessionHeader, session)
	h.Set(ProfileHeader, base64.RawURLEncoding.EncodeToString(data))
	size := len(path)
	for key, values := range h {
		for _, value := range values {
			size += len(key) + len(value) + 4
		}
	}
	if size > 2000 {
		return nil, fmt.Errorf("transport request metadata is too large")
	}
	h.Set("X-Client-Padding", strings.Repeat("a", 2048-size))
	return h, nil
}

func ParseSession(session string) ([]byte, error) {
	if len(session) != 64 {
		return nil, fmt.Errorf("session ID must contain 32 random bytes in hex")
	}
	data, err := hex.DecodeString(session)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID")
	}
	return data, nil
}

func ParseProfile(value string) (shaping.Profile, error) {
	var profile shaping.Profile
	if len(value) > 4096 {
		return profile, fmt.Errorf("profile header is too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return profile, err
	}
	return DecodeProfile(bytes.NewReader(data))
}

// DecodeProfile applies the same strict JSON and policy validation to profile
// files and transport headers. Readers must enforce their input size limit.
func DecodeProfile(reader io.Reader) (shaping.Profile, error) {
	var profile shaping.Profile
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return profile, fmt.Errorf("trailing profile data")
	}
	return profile, profile.Validate()
}
