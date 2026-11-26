package bench

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func validNonce(n string) bool {
	if len(n) != 64 || n != strings.ToLower(n) {
		return false
	}
	b, e := hex.DecodeString(n)
	return e == nil && len(b) == 32
}
func NewNonce() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func fixedSeed(text string) (int64, error) {
	if len(text) != 16 || text != strings.ToLower(text) {
		return 0, errors.New("seed must be16 lowercase hex characters")
	}
	value, e := strconv.ParseInt(text, 16, 64)
	if e != nil || value < 1 || value > 1<<48-1 {
		return 0, errors.New("bounded positive seed required")
	}
	return value, nil
}
func validateKeys(q url.Values) error {
	for key := range q {
		if key != "family" && key != "seed" && key != "duration_ms" && key != "nonce" {
			return errors.New("only fixed workload parameters allowed on wire")
		}
		if len(q[key]) != 1 {
			return errors.New("duplicate workload parameter")
		}
	}
	return nil
}

// WorkloadURL excludes corpus/group/class/split identifiers from wire parameters.
func WorkloadURL(endpoint string, p Plan, nonce string) (string, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("plain endpoint URL required")
	}
	q := u.Query()
	if e := validateKeys(q); e != nil {
		return "", e
	}
	if !validNonce(nonce) {
		return "", errors.New("nonce must be64 lowercase hex characters")
	}
	q.Set("family", p.Family)
	q.Set("seed", fmt.Sprintf("%016x", p.Seed))
	q.Set("duration_ms", strconv.FormatInt(p.DurationMS, 10))
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func parseWorkload(q url.Values, budget int) (Plan, error) {
	if e := validateKeys(q); e != nil {
		return Plan{}, e
	}
	seed, e := fixedSeed(q.Get("seed"))
	if e != nil {
		return Plan{}, e
	}
	if !validNonce(q.Get("nonce")) {
		return Plan{}, errors.New("fixed nonce required")
	}
	duration, e := strconv.ParseInt(q.Get("duration_ms"), 10, 64)
	if e != nil || duration < 1000 || duration > 80000 {
		return Plan{}, errors.New("duration must be1000..80000ms")
	}
	return NewPlan(q.Get("family"), seed, time.Duration(duration)*time.Millisecond, budget)
}
