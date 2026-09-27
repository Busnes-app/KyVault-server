// Package userkey holds the shape of a user's published X-Wing key record. The server
// stores it opaquely; only lengths, the algorithm name and the fingerprint are computed here.
package userkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AlgXWing         = "xwing"
	PublicKeyBytes   = 1216 // ML-KEM-768 encapsulation key + X25519 point
	WrappedSeedBytes = 12 + 32 + 16
	MaxPrevious      = 5
)

var ErrShape = errors.New("userkey: invalid record")

type Previous struct {
	PublicKey  string    `json:"publicKey"`
	ReplacedAt time.Time `json:"replacedAt"`
}

// Record is what the owner writes and reads. WrappedSeed is AES-256-GCM under the raw
// vault key with AAD "kyvault-user-key:<userId>"; the server never opens it.
type Record struct {
	Alg         string     `json:"alg"`
	PublicKey   string     `json:"publicKey"`
	WrappedSeed string     `json:"wrappedSeed"`
	CreatedAt   time.Time  `json:"createdAt"`
	Previous    []Previous `json:"previous,omitempty"`
}

// Public is what other users see. No seed, never.
type Public struct {
	UserID      string     `json:"userId"`
	Alg         string     `json:"alg"`
	PublicKey   string     `json:"publicKey"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"createdAt"`
	Previous    []Previous `json:"previous"`
}

func decodeLen(s string, want int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != want {
		return nil, fmt.Errorf("%w: want %d bytes", ErrShape, want)
	}
	return b, nil
}

func (r Record) Validate() error {
	if r.Alg != AlgXWing || r.CreatedAt.IsZero() {
		return ErrShape
	}
	if _, err := decodeLen(r.PublicKey, PublicKeyBytes); err != nil {
		return err
	}
	if _, err := decodeLen(r.WrappedSeed, WrappedSeedBytes); err != nil {
		return err
	}
	return nil
}

// Fingerprint is SHA-256 of the public key, first 20 hex digits, upper case, in fours.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))[:20]
	parts := make([]string, 0, 5)
	for i := 0; i < 20; i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, " ")
}

func (r Record) Fingerprint() (string, error) {
	pk, err := decodeLen(r.PublicKey, PublicKeyBytes)
	if err != nil {
		return "", err
	}
	return Fingerprint(pk), nil
}

func (r Record) Public(userID string) (Public, error) {
	fp, err := r.Fingerprint()
	if err != nil {
		return Public{}, err
	}
	prev := r.Previous
	if prev == nil {
		prev = []Previous{}
	}
	return Public{UserID: userID, Alg: r.Alg, PublicKey: r.PublicKey, Fingerprint: fp, CreatedAt: r.CreatedAt, Previous: prev}, nil
}
