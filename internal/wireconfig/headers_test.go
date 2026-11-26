package wireconfig

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rebrudiy/belnet-bridge/internal/shaping"
)

func TestMatchedRequestLengthAndProfileRoundTrip(t *testing.T) {
	var sizes []int
	for _, path := range []string{"/ws", "/lab/ws"} {
		p := shaping.Profile{Name: strings.Repeat("x", len(path)), Up: shaping.Policy{PadTo: 256}}
		h, err := Headers("secret", strings.Repeat("a", 64), p, path)
		if err != nil {
			t.Fatal(err)
		}
		size := len(path)
		for k, values := range h {
			for _, value := range values {
				size += len(k) + len(value) + 4
			}
		}
		sizes = append(sizes, size)
		got, err := ParseProfile(h.Get(ProfileHeader))
		if err != nil || got != p {
			t.Fatal("profile did not round trip")
		}
	}
	if sizes[0] != sizes[1] {
		t.Fatal("encrypted request size reveals class or profile name")
	}
}

func TestProfileSourcesRejectUnknownAndTrailingJSON(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		valid bool
	}{
		{"valid", `{"name":"selected","up":{"pad_to":256}}`, true},
		{"whitespace", "{\"name\":\"selected\"}\n\t", true},
		{"unknown field", `{"name":"selected","typo":true}`, false},
		{"unknown policy", `{"up":{"typo":true}}`, false},
		{"second value", `{"name":"selected"} {}`, false},
		{"trailing garbage", `{"name":"selected"} extra`, false},
		{"invalid policy", `{"up":{"pad_to":-1}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, fileErr := DecodeProfile(strings.NewReader(test.input))
			_, headerErr := ParseProfile(base64.RawURLEncoding.EncodeToString([]byte(test.input)))
			if (fileErr == nil) != test.valid || (headerErr == nil) != test.valid {
				t.Fatalf("file error = %v, header error = %v, want valid = %v", fileErr, headerErr, test.valid)
			}
		})
	}
}
