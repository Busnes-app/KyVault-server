package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyvault-server/internal/audit"
	"github.com/Busnes-app/kyvault-server/internal/devices"
	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/sso"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

func generatedKey(t *testing.T) (recoverykey.PrivateKey, RecoveryKey) {
	t.Helper()
	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return private, RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}
}

func TestPairingSealsTokenAndPinsKey(t *testing.T) {
	dir := t.TempDir()
	store := NewStateStore(dir)
	_, key := generatedKey(t)
	const token = "do-not-store-this-token-in-cleartext"
	if err := store.StorePairing("https://recovery.example", token, key); err != nil {
		t.Fatal(err)
	}
	if serviceName, err := store.ServiceName(); err != nil || serviceName != ServiceName {
		t.Fatalf("new pairing service name = %q, %v", serviceName, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(token)) {
		t.Fatal("pairing state contains the plaintext token")
	}
	pairing, err := store.LoadPairing()
	if err != nil || pairing.Token != token || pairing.Key.Public.ID() != key.Public.ID() {
		t.Fatalf("LoadPairing = %+v, %v", pairing, err)
	}
	_, other := generatedKey(t)
	if err := store.StorePairing("https://recovery.example", "other", other); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("different key pairing error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPairing(); !errors.Is(err, ErrKeyPinMissing) {
		t.Fatalf("missing recovery.pub error = %v", err)
	}
}

func TestStatusMigratesLegacyLocalCopiesForNewPairing(t *testing.T) {
	configDir, backupDir := t.TempDir(), t.TempDir()
	store := NewStateStore(configDir)
	_, key := generatedKey(t)
	if err := store.StorePairing("https://recovery.example", "token", key); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(backupDir, recoveryclient.LocalPrefix(LegacyServiceName)+"old.kycap")
	if err := os.WriteFile(legacy, []byte("capsule"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := (&Service{State: store, Config: Config{Directory: backupDir}}).Status()
	if err != nil || len(status.LocalCopies) != 1 || status.LocalCopies[0].Name != recoveryclient.LocalPrefix(ServiceName)+"old.kycap" {
		t.Fatalf("migrated local copies = %+v, %v", status.LocalCopies, err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy copy still exists: %v", err)
	}
}

func testCollector(t *testing.T) Collector {
	t.Helper()
	root := t.TempDir()
	configDir, dataDir := filepath.Join(root, "config"), filepath.Join(root, "data")
	u, err := users.NewStore(configDir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := devices.NewStore(configDir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewStore(filepath.Join(dataDir, "vaults"), 90)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.NewStore(filepath.Join(dataDir, "audit"), configDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Log(t.Context(), "test", "user", "", "", "seed"); err != nil {
		t.Fatal(err)
	}
	user, err := u.CreateSSOUser("alice", users.RoleAdmin, "sub-alice", "alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.SaveVault(user.ID, 0, []byte("encrypted-kdbx"), "sealed-envelope", "", "test"); err != nil {
		t.Fatal(err)
	}
	ssoStore := sso.NewStore(configDir)
	if err := ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://signon.example", ClientID: "kyvault", ClientSecret: "sealed-inside-capsule"}); err != nil {
		t.Fatal(err)
	}
	sh, err := shared.NewStore(filepath.Join(dataDir, "shared"), 90)
	if err != nil {
		t.Fatal(err)
	}
	return Collector{Vault: v, Audit: a, Users: u, Devices: d, SSO: ssoStore, Shared: sh,
		State: NewStateStore(configDir), DataDir: dataDir, PairingSecret: "replication-secret", RetentionDays: 90, AppVersion: "test"}
}

type openingDepositor struct {
	t       *testing.T
	private recoverykey.PrivateKey
	opened  *[]capsule.File
}

func (d openingDepositor) Deposit(_ context.Context, _, _ string, raw []byte) (Receipt, error) {
	d.t.Helper()
	manifest, files, err := capsule.Open(raw, d.private, "")
	if err != nil {
		d.t.Fatalf("test-held private key did not open deposit: %v", err)
	}
	if len(files) < 9 {
		d.t.Fatalf("capsule has only %d files", len(files))
	}
	if d.opened != nil {
		*d.opened = files
	}
	sum := sha256.Sum256(raw)
	return Receipt{CapsuleID: manifest.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)), DepositedAt: time.Now()}, nil
}

func TestDepositAndRestoreDrillRoundTrip(t *testing.T) {
	collector := testCollector(t)
	sv, err := collector.Shared.Create("Finance", "u-1", base64.StdEncoding.EncodeToString(make([]byte, shared.SealedKeyBytes)), "FP", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sharedVaultBytes := []byte("shared-vault-ciphertext")
	if _, err := collector.Vault.SaveVault(shared.StoreKey(sv.ID), 0, sharedVaultBytes, "", "", ""); err != nil {
		t.Fatal(err)
	}
	sharedRecordBytes, err := os.ReadFile(filepath.Join(collector.DataDir, "shared", sv.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}

	private, key := generatedKey(t)
	if err := collector.State.StorePairing("https://recovery.example", "secret-token", key); err != nil {
		t.Fatal(err)
	}
	var opened []capsule.File
	service := Service{State: collector.State, Collector: collector, Client: openingDepositor{t: t, private: private, opened: &opened}}
	result, err := service.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.CapsuleID != result.Manifest.CapsuleID {
		t.Fatal("receipt and manifest capsule IDs differ")
	}

	byPath := make(map[string][]byte, len(opened))
	for _, f := range opened {
		byPath[f.Path] = f.Content
	}
	if !bytes.Equal(byPath["data/shared/"+sv.ID+".json"], sharedRecordBytes) {
		t.Fatalf("restored data/shared/%s.json bytes differ", sv.ID)
	}
	if !bytes.Equal(byPath["data/vaults/shared/"+sv.ID+"/vault.kdbx"], sharedVaultBytes) {
		t.Fatalf("restored data/vaults/shared/%s/vault.kdbx bytes differ", sv.ID)
	}

	drill, err := RunDrill(t.Context(), collector)
	if err != nil || !drill.Passed {
		t.Fatalf("RunDrill = %+v, %v", drill, err)
	}
	found := false
	for _, c := range drill.Checks {
		if c.Name == "shared vault records" {
			found = true
			if !c.Passed {
				t.Fatalf("shared vault records check failed: %s", c.Message)
			}
		}
	}
	if !found {
		t.Fatal("drill did not run the shared vault records check")
	}
}

func TestRecoveryURLPolicy(t *testing.T) {
	for _, value := range []string{
		"http://recovery.example", "https://user@recovery.example", "https://recovery.example?q=x",
		"https://recovery.example/#fragment", "https://127.0.0.1", "https://100.64.0.1",
		"https://[64:ff9b::a00:1]",
	} {
		if err := ValidateURL(value, false); err == nil {
			t.Errorf("endpoint accepted %q", value)
		}
	}
	if err := ValidateURL("https://recovery.example", false); err != nil {
		t.Fatalf("public HTTPS origin rejected: %v", err)
	}
}

type mismatchedDepositor struct{}

func (mismatchedDepositor) Deposit(context.Context, string, string, []byte) (Receipt, error) {
	return Receipt{CapsuleID: "wrong", Digest: "wrong", SizeBytes: 1}, nil
}

func TestDepositRejectsMismatchedReceiptCapsule(t *testing.T) {
	collector := testCollector(t)
	_, key := generatedKey(t)
	if err := collector.State.StorePairing("https://recovery.example", "token", key); err != nil {
		t.Fatal(err)
	}
	service := Service{State: collector.State, Collector: collector, Client: mismatchedDepositor{}}
	if _, err := service.Run(t.Context()); !errors.Is(err, ErrRemote) {
		t.Fatalf("mismatched receipt error = %v", err)
	}
}

func TestDecryptGuard(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	guardtest.NoDecryptOutside(t, root, map[string][]string{"cmd/server/backup.go": {"runRestore"}})
}

func TestSCIMTokenIncludedInRecoveryCapsule(t *testing.T) {
	collector := testCollector(t)
	collector.SCIMToken = "synthetic-scim-token-with-at-least-32-characters"
	files, _, _, err := collector.Collect()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.Path == "config/scim.token" {
			found = true
			if string(file.Content) != collector.SCIMToken || file.Mode != 0600 {
				t.Fatal("wrong SCIM token snapshot")
			}
		}
	}
	if !found {
		t.Fatal("SCIM token missing from sealed payload inputs")
	}
	result, err := RunDrill(context.Background(), collector)
	if err != nil || !result.Passed {
		t.Fatalf("SCIM-aware restore drill: %+v %v", result, err)
	}
}

func TestCapsuleIncludesSharedVaults(t *testing.T) {
	c := testCollector(t)
	sv, err := c.Shared.Create("Finance", "u-1", base64.StdEncoding.EncodeToString(make([]byte, shared.SealedKeyBytes)), "FP", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Vault.SaveVault(shared.StoreKey(sv.ID), 0, []byte("shared-ct"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	files, _, _, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"data/shared/" + sv.ID + ".json": false, "data/vaults/shared/" + sv.ID + "/vault.kdbx": false, "data/vaults/shared/" + sv.ID + "/metadata.json": false}
	for _, f := range files {
		if _, ok := want[f.Path]; ok {
			want[f.Path] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Fatalf("capsule lacks %s", p)
		}
	}
}

func TestCollectFailsWithoutSharedStore(t *testing.T) {
	c := testCollector(t)
	c.Shared = nil
	if _, _, _, err := c.Collect(); err == nil {
		t.Fatal("expected Collect to fail with no Shared store")
	}
}

func TestSharedSettingsIncludedWhenPresent(t *testing.T) {
	c := testCollector(t)
	configDir := filepath.Dir(c.State.dir)
	c.SharedSettingsPath = filepath.Join(configDir, "shared.json")
	settingsBytes := []byte(`{"createRestrictedToAdmins":true}`)
	if err := os.WriteFile(c.SharedSettingsPath, settingsBytes, 0600); err != nil {
		t.Fatal(err)
	}
	files, _, _, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range files {
		if f.Path == "config/shared.json" {
			found = true
			if !bytes.Equal(f.Content, settingsBytes) || f.Mode != 0600 {
				t.Fatal("wrong config/shared.json snapshot")
			}
		}
	}
	if !found {
		t.Fatal("config/shared.json missing from sealed payload inputs")
	}
}

func TestSharedSettingsOmittedWhenAbsent(t *testing.T) {
	c := testCollector(t)
	c.SharedSettingsPath = filepath.Join(filepath.Dir(c.State.dir), "shared.json")
	files, _, _, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "config/shared.json" {
			t.Fatal("config/shared.json present without a settings file")
		}
	}
}

func TestDrillChecksDeletedSharedVaultRecords(t *testing.T) {
	c := testCollector(t)
	sv, err := c.Shared.Create("Finance", "u-1", base64.StdEncoding.EncodeToString(make([]byte, shared.SealedKeyBytes)), "FP", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Vault.SaveVault(shared.StoreKey(sv.ID), 0, []byte("shared-ct"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	err = c.Shared.Delete(sv.ID, "u-1", func(dst string) error {
		return c.Vault.MoveOut(shared.StoreKey(sv.ID), dst)
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, "shared", "deleted", sv.ID, "record.json")); err != nil {
		t.Fatal(err)
	}
	drill, err := RunDrill(t.Context(), c)
	if err != nil || !drill.Passed {
		t.Fatalf("RunDrill = %+v, %v", drill, err)
	}
	found := false
	for _, chk := range drill.Checks {
		if chk.Name == "shared vault records" {
			found = true
			if !chk.Passed {
				t.Fatalf("shared vault records check failed on deleted vault: %s", chk.Message)
			}
		}
	}
	if !found {
		t.Fatal("drill did not run the shared vault records check")
	}
}
