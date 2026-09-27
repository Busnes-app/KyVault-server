package api

import "testing"

func TestVaultTargetAuditAction(t *testing.T) {
	cases := []struct {
		name     string
		target   vaultTarget
		personal string
		want     string
	}{
		{"personal passthrough", vaultTarget{shared: false}, "vault.saved", "vault.saved"},
		{"shared restore special-cased", vaultTarget{shared: true}, "vault.restored_snapshot", "shared.rolled_back"},
		{"shared conflict download special-cased", vaultTarget{shared: true}, "vault.conflict_download", "shared.conflict_downloaded"},
		{"shared download uses shared.downloaded", vaultTarget{shared: true}, "vault.download", "shared.downloaded"},
		{"shared default prefix", vaultTarget{shared: true}, "vault.saved", "shared.saved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.target.auditAction(tc.personal); got != tc.want {
				t.Errorf("auditAction(%q) = %q, want %q", tc.personal, got, tc.want)
			}
		})
	}
}
