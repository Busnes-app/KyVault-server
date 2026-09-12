package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A pairing that fails on the wire must carry why it failed. The handler answers the operator
// with a fixed sentence either way, so this detail only ever reaches the audit record — which
// is the one place an operator can look to tell an expired PIN from an unreachable KyRecovery.
func TestClaimKeepsTheRemoteCause(t *testing.T) {
	// .invalid never resolves, so the claim fails after ValidateURL has passed.
	const server = "https://kyrecovery.invalid"

	_, err := NewClient(false).Claim(context.Background(), server, "123456")
	if err == nil {
		t.Fatal("claim against an unresolvable host succeeded")
	}
	if !errors.Is(err, ErrRemote) {
		t.Fatalf("error is not ErrRemote: %v", err)
	}
	if !strings.Contains(err.Error(), "kyrecovery.invalid") {
		t.Fatalf("claim error dropped the cause, leaving nothing to diagnose: %v", err)
	}
}
