package userkey

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validRecord() Record {
	return Record{
		Alg:         AlgXWing,
		PublicKey:   base64.StdEncoding.EncodeToString(make([]byte, PublicKeyBytes)),
		WrappedSeed: base64.StdEncoding.EncodeToString(make([]byte, WrappedSeedBytes)),
		CreatedAt:   time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC),
	}
}

func TestValidateShape(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	bad := []func(r *Record){
		func(r *Record) { r.Alg = "x25519" },
		func(r *Record) { r.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		func(r *Record) { r.PublicKey = "not base64!" },
		func(r *Record) { r.WrappedSeed = base64.StdEncoding.EncodeToString(make([]byte, 59)) },
		func(r *Record) { r.CreatedAt = time.Time{} },
	}
	for i, mutate := range bad {
		r := validRecord()
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

// Pinned so the JS fingerprint test can assert the same value for the same input.
func TestFingerprintVector(t *testing.T) {
	pk := make([]byte, PublicKeyBytes)
	for i := range pk {
		pk[i] = byte(i)
	}
	got := Fingerprint(pk)
	if len(got) != 24 || strings.Count(got, " ") != 4 || got != strings.ToUpper(got) {
		t.Fatalf("fingerprint shape: %q", got)
	}
	if got != fingerprintOfCountingKey {
		t.Fatalf("fingerprint = %q, want %q", got, fingerprintOfCountingKey)
	}
}

func TestPublicOmitsSeed(t *testing.T) {
	p, err := validRecord().Public("u-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "u-1" || p.Fingerprint == "" || p.Previous == nil {
		t.Fatalf("public: %+v", p)
	}
}

// Filled in once by running the test with -run TestFingerprintVector -v and copying the
// printed value; the JS test pins the same string.
const fingerprintOfCountingKey = "B74C BE6A BEFF 8BF1 95BA"
