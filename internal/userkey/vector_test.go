package userkey

import (
	"bytes"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the HPKE interop fixture")

const vectorPath = "../../frontend/src/lib/testdata/hpke-xwing-vector.json"

type vector struct {
	Seed      string `json:"seed"`
	PublicKey string `json:"publicKey"`
	Info      string `json:"info"`
	Plaintext string `json:"plaintext"`
	GoSealed  string `json:"goSealed"`
	JSSealed  string `json:"jsSealed,omitempty"`
}

func fixedSeed() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestInteropVector writes the fixture with -update and otherwise proves that what the JS
// side sealed (if present) opens here. The JS test proves the reverse.
func TestInteropVector(t *testing.T) {
	kem := hpke.MLKEM768X25519()
	sk, err := kem.NewPrivateKey(fixedSeed())
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	info := []byte("kyvault/test/1")
	if *update {
		sealed, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, []byte("hello from go"))
		if err != nil {
			t.Fatal(err)
		}
		v := vector{Seed: b64(fixedSeed()), PublicKey: b64(pk.Bytes()), Info: string(info), Plaintext: "hello from go", GoSealed: b64(sealed)}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("fixture missing; run: go test ./internal/userkey -run TestInteropVector -update: %v", err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unb64(t, v.PublicKey), pk.Bytes()) {
		t.Fatal("fixture public key does not match the seed")
	}
	if v.JSSealed == "" {
		t.Skip("jsSealed not present yet; the JS test writes it with UPDATE_VECTOR=1")
	}
	pt, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(v.Info), unb64(t, v.JSSealed))
	if err != nil {
		t.Fatalf("open jsSealed: %v", err)
	}
	if string(pt) != "hello from js" {
		t.Fatalf("jsSealed opened to %q", pt)
	}
}
