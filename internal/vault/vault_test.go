package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/userkey"
)

func TestVaultStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 90)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	userID := "user_test_123"

	// 1. Initial vault save (v1)
	v1Data := []byte("KDBX-V4-ENCRYPTED-PAYLOAD-V1")
	meta1, err := store.SaveVault(userID, 0, v1Data, "enc_pw_env_1", "enc_rec_env_1", "desktop-chrome")
	if err != nil {
		t.Fatalf("SaveVault v1 failed: %v", err)
	}
	if meta1.Version != 1 || meta1.SizeBytes != int64(len(v1Data)) {
		t.Errorf("unexpected meta1: %+v", meta1)
	}

	// 2. Open vault and verify content
	rc, readMeta, err := store.OpenVault(userID)
	if err != nil {
		t.Fatalf("OpenVault failed: %v", err)
	}
	defer rc.Close()
	readBytes, _ := io.ReadAll(rc)
	if !bytes.Equal(readBytes, v1Data) || readMeta.Version != 1 {
		t.Errorf("read bytes mismatch: got %s", string(readBytes))
	}

	// 3. Save v2 with expectedVersion = 1
	v2Data := []byte("KDBX-V4-ENCRYPTED-PAYLOAD-V2")
	meta2, err := store.SaveVault(userID, 1, v2Data, "enc_pw_env_2", "", "mobile-android")
	if err != nil {
		t.Fatalf("SaveVault v2 failed: %v", err)
	}
	if meta2.Version != 2 {
		t.Errorf("expected version 2, got %d", meta2.Version)
	}

	// 4. Test Conflict Handling: Attempt save with stale version (expectedVersion = 1 instead of 2)
	vConflictData := []byte("KDBX-V4-CONFLICT-DATA")
	_, err = store.SaveVault(userID, 1, vConflictData, "", "", "laptop-firefox")
	if err == nil {
		t.Fatalf("expected conflict error, got nil")
	}
	confErr, ok := err.(*ConflictError)
	if !ok {
		t.Fatalf("expected *ConflictError, got %T: %v", err, err)
	}
	if confErr.CurrentVersion != 2 || confErr.ExpectedVersion != 1 {
		t.Errorf("unexpected ConflictError fields: %+v", confErr)
	}

	// Check conflicts list
	conflicts, err := store.ListConflicts(userID)
	if err != nil || len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict entry, got %d (err: %v)", len(conflicts), err)
	}

	// 5. Test History List and Rollback
	history, err := store.ListHistory(userID)
	if err != nil || len(history) != 1 {
		t.Fatalf("expected 1 history entry, got %d (err: %v)", len(history), err)
	}

	meta3, err := store.RestoreHistory(userID, history[0].ID)
	if err != nil {
		t.Fatalf("RestoreHistory failed: %v", err)
	}
	if meta3.Version != 3 {
		t.Errorf("expected rollback version 3, got %d", meta3.Version)
	}

	// 6. Device Envelope management
	err = store.SetDeviceEnvelope(userID, DeviceEnvelope{
		DeviceID: "device_abc",
		Name:     "Pixel 8",
		Envelope: "dev_envelope_blob_xyz",
	})
	if err != nil {
		t.Fatalf("SetDeviceEnvelope failed: %v", err)
	}

	m, _ := store.GetMetadata(userID)
	if _, ok := m.DeviceEnvelopes["device_abc"]; !ok {
		t.Fatalf("expected device_abc in DeviceEnvelopes")
	}

	err = store.RemoveDeviceEnvelope(userID, "device_abc")
	if err != nil {
		t.Fatalf("RemoveDeviceEnvelope failed: %v", err)
	}
	m, _ = store.GetMetadata(userID)
	if _, ok := m.DeviceEnvelopes["device_abc"]; ok {
		t.Fatalf("expected device_abc removed")
	}
}

func TestHistoryCountBoundOnSaveAndRollback(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 100
	for version := int64(0); version < limit+5; version++ {
		if _, err := store.SaveVault("user", version, []byte("encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	history, err := store.ListHistory("user")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != limit {
		t.Fatalf("history count = %d, want %d", len(history), limit)
	}
	var oldest, newest bool
	for _, entry := range history {
		oldest = oldest || entry.Version == 1
		newest = newest || entry.Version == limit+4
	}
	if !oldest || !newest {
		t.Fatal("count pruning must retain the oldest and newest snapshots")
	}
	if _, err := store.RestoreHistory("user", history[0].ID); err != nil {
		t.Fatal(err)
	}
	history, err = store.ListHistory("user")
	if err != nil || len(history) != limit {
		t.Fatalf("rollback history count = %d, err = %v", len(history), err)
	}
}

func TestHistoryAgeRetention(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	for version := int64(0); version < 2; version++ {
		if _, err := store.SaveVault("user", version, []byte("encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	history, err := store.ListHistory("user")
	if err != nil || len(history) != 1 {
		t.Fatalf("history = %v, err = %v", history, err)
	}
	old := filepath.Join(store.historyDir("user"), history[0].ID+".kdbx")
	expired := time.Now().AddDate(0, 0, -91)
	if err := os.Chtimes(old, expired, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("user", 2, []byte("new encrypted"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired snapshot still exists: %v", err)
	}
	history, err = store.ListHistory("user")
	if err != nil || len(history) != 1 || history[0].Version != 2 {
		t.Fatalf("recent history = %v, err = %v", history, err)
	}
}

func TestHistoryCapPreservesTimeCoverage(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("user", 0, []byte("encrypted"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 150; i++ {
		path := filepath.Join(store.historyDir("user"), fmt.Sprintf("seed_%03d.kdbx", i))
		if err := os.WriteFile(path, []byte("old encrypted"), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-time.Duration(i+1) * 60 * 24 * time.Hour / 150)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	// A burst of writes must not displace the pre-session recovery window.
	for version := int64(1); version <= 150; version++ {
		if _, err := store.SaveVault("user", version, []byte("session encrypted"), "", "", ""); err != nil {
			t.Fatal(err)
		}
		history, err := store.ListHistory("user")
		if err != nil {
			t.Fatal(err)
		}
		if len(history) > 100 || len(history) == 0 {
			t.Fatalf("history count = %d", len(history))
		}
		if !history[len(history)-1].Timestamp.Before(now.AddDate(0, 0, -30)) {
			t.Fatalf("write %d erased old history", version)
		}
		// Require more than one token old snapshot: maintain coverage in each 15-day band.
		var bands [4]bool
		for _, h := range history {
			band := int(now.Sub(h.Timestamp) / (15 * 24 * time.Hour))
			if band >= 0 && band < len(bands) {
				bands[band] = true
			}
		}
		for band, covered := range bands {
			if !covered {
				t.Fatalf("write %d erased time band %d", version, band)
			}
		}
	}
}

// A stale upload's rejected bytes are named after the saving device. The id is
// server-minted hex, but the filename must stay inside the conflicts directory no
// matter what reaches this call.
func TestConflictFilenameCannotEscape(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v1"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	evil := "../../../../" + t.Name() + "-escaped"
	_, err = store.SaveVault("u1", 0, []byte("stale"), "", "", evil)
	var conf *ConflictError
	if !errors.As(err, &conf) {
		t.Fatalf("stale save = %v, want ConflictError", err)
	}
	if strings.Contains(conf.ConflictID, "/") || strings.Contains(conf.ConflictID, "..") {
		t.Fatalf("conflict id carries path syntax: %q", conf.ConflictID)
	}
	var escaped []string
	_ = filepath.WalkDir(filepath.Dir(dir), func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.Contains(p, "-escaped") {
			escaped = append(escaped, p)
		}
		return nil
	})
	if len(escaped) != 0 {
		t.Fatalf("conflict written outside the store: %v", escaped)
	}
	if got, want := fileToken("0123abcd-_"), "0123abcd-_"; got != want {
		t.Fatalf("fileToken(%q) = %q", want, got)
	}
	if got := fileToken(""); got != "web" {
		t.Fatalf("fileToken(\"\") = %q, want web", got)
	}
}

func testUserKey(pk byte) userkey.Record {
	pub := make([]byte, userkey.PublicKeyBytes)
	for i := range pub {
		pub[i] = pk
	}
	return userkey.Record{
		Alg:         userkey.AlgXWing,
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		WrappedSeed: base64.StdEncoding.EncodeToString(make([]byte, userkey.WrappedSeedBytes)),
		CreatedAt:   time.Now().UTC(),
	}
}

func TestSaveUserKeyAppendsPreviousAndCaps(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	created, err := store.SaveUserKey("u1", 1, testUserKey(1), false)
	if err != nil || !created {
		t.Fatalf("first save: created=%v err=%v", created, err)
	}
	if _, err := store.SaveUserKey("u1", 0, testUserKey(2), false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	for i := byte(2); i <= 8; i++ {
		created, err := store.SaveUserKey("u1", 1, testUserKey(i), false)
		if err != nil || created {
			t.Fatalf("replace %d: created=%v err=%v", i, created, err)
		}
	}
	meta, _ := store.GetMetadata("u1")
	if meta.UserKey == nil || len(meta.UserKey.Previous) != userkey.MaxPrevious {
		t.Fatalf("previous: %+v", meta.UserKey)
	}
	// Oldest dropped: previous[0] is key 3 (keys 1 and 2 fell off), newest last.
	if got := meta.UserKey.Previous[0].PublicKey; got != testUserKey(3).PublicKey {
		t.Fatalf("previous[0] is not key 3")
	}
	if meta.Version != 1 {
		t.Fatalf("user key write bumped version to %d", meta.Version)
	}
	// Re-saving the same public key is idempotent: no previous entry.
	before := len(meta.UserKey.Previous)
	if _, err := store.SaveUserKey("u1", 1, testUserKey(8), false); err != nil {
		t.Fatal(err)
	}
	meta, _ = store.GetMetadata("u1")
	if len(meta.UserKey.Previous) != before {
		t.Fatal("same-key save appended previous")
	}
}

func TestRotateVaultCarriesUserKey(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	// rotation without a record needs no header
	if _, err := store.RotateVault("u1", 1, []byte("v2"), "pw2", "rec2", "", nil); err != nil {
		t.Fatalf("rotation with no user key: %v", err)
	}
	if _, err := store.SaveUserKey("u1", 2, testUserKey(1), false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateVault("u1", 2, []byte("v3"), "pw3", "rec3", "", nil); !errors.Is(err, ErrRotationUserKey) {
		t.Fatalf("rotation dropping the user key: %v", err)
	}
	rewrapped := testUserKey(1)
	rewrapped.WrappedSeed = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, userkey.WrappedSeedBytes))
	meta, err := store.RotateVault("u1", 2, []byte("v3"), "pw3", "rec3", "", &rewrapped)
	if err != nil {
		t.Fatal(err)
	}
	if meta.UserKey == nil || meta.UserKey.WrappedSeed != rewrapped.WrappedSeed || meta.UserKey.PublicKey != testUserKey(1).PublicKey {
		t.Fatalf("rotated user key: %+v", meta.UserKey)
	}
	// A rotation may not change the public key: that is Replace, a separate action.
	other := testUserKey(2)
	if _, err := store.RotateVault("u1", 3, []byte("v4"), "pw4", "rec4", "", &other); !errors.Is(err, ErrRotationUserKey) {
		t.Fatalf("rotation swapping the public key: %v", err)
	}
	// Ordinary saves carry the record through untouched.
	meta, err = store.SaveVault("u1", 3, []byte("v4"), "", "", "")
	if err != nil || meta.UserKey == nil {
		t.Fatalf("save dropped user key: %+v %v", meta.UserKey, err)
	}
}

// metadata without userKey decodes
func TestMetadataWithoutUserKeyDecodes(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir, 90)
	if _, err := store.SaveVault("u1", 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(store.metaPath("u1"))
	if bytes.Contains(raw, []byte("userKey")) {
		t.Fatal("empty user key serialised")
	}
	meta, err := store.GetMetadata("u1")
	if err != nil || meta.UserKey != nil {
		t.Fatalf("decode: %+v %v", meta.UserKey, err)
	}
}

func TestRestoreHistoryKeepsUserKey(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v1"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	key := testUserKey(1)
	if _, err := store.SaveUserKey("u1", 1, key, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 1, []byte("v2"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	history, err := store.ListHistory("u1")
	if err != nil || len(history) == 0 {
		t.Fatalf("history: %v %v", history, err)
	}
	meta, err := store.RestoreHistory("u1", history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if meta.UserKey == nil || meta.UserKey.PublicKey != key.PublicKey || meta.UserKey.WrappedSeed != key.WrappedSeed {
		t.Fatalf("rollback lost the user key: %+v", meta.UserKey)
	}
	if len(meta.UserKey.Previous) != len(key.Previous) {
		t.Fatalf("rollback changed previous: %+v", meta.UserKey.Previous)
	}
}

func TestRotateVaultRefusesPublishingNewUserKey(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	// No published key yet: a rotation carrying X-User-Key must not publish one.
	fresh := testUserKey(1)
	if _, err := store.RotateVault("u1", 1, []byte("v2"), "pw2", "rec2", "", &fresh); !errors.Is(err, ErrRotationUserKey) {
		t.Fatalf("rotation publishing a new key: %v", err)
	}
	meta, _ := store.GetMetadata("u1")
	if meta.UserKey != nil {
		t.Fatalf("rotation published a user key: %+v", meta.UserKey)
	}
}

func TestSaveUserKeyRefusesZeroVersion(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveUserKey("u1", 0, testUserKey(1), false); !errors.Is(err, ErrConflict) {
		t.Fatalf("save against version 0: %v", err)
	}
	meta, _ := store.GetMetadata("u1")
	if meta.UserKey != nil {
		t.Fatal("save against version 0 stored a key")
	}
}

// Two tabs racing to publish the first key: createOnly refuses the second so it cannot
// silently replace the first.
func TestSaveUserKeyCreateOnlyRefusesExisting(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault("u1", 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveUserKey("u1", 1, testUserKey(1), true); err != nil {
		t.Fatalf("first create-only save: %v", err)
	}
	if _, err := store.SaveUserKey("u1", 1, testUserKey(2), true); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create-only save: %v", err)
	}
	meta, _ := store.GetMetadata("u1")
	if meta.UserKey == nil || meta.UserKey.PublicKey != testUserKey(1).PublicKey {
		t.Fatalf("create-only conflict changed the record: %+v", meta.UserKey)
	}
	// createOnly does not block an ordinary replace.
	if _, err := store.SaveUserKey("u1", 1, testUserKey(2), false); err != nil {
		t.Fatalf("ordinary replace after create-only conflict: %v", err)
	}
}

// MoveOut takes a vault directory away under the store lock and retires the key: no
// later write, at any version, recreates the directory.
func TestMoveOutMovesDirectoryAndSaveDoesNotResurrect(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	key := "shared/sv_aaaaaaaaaaaaaaaaaaaaaa"
	if _, err := store.SaveVault(key, 0, []byte("v1"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	// A failed move (missing destination parent) is an error and retires nothing.
	if err := store.MoveOut(key, filepath.Join(t.TempDir(), "absent", "vault")); err == nil {
		t.Fatal("MoveOut into a missing parent succeeded")
	}
	if _, err := store.SaveVault(key, 1, []byte("v2"), "", "", ""); err != nil {
		t.Fatalf("save after failed MoveOut: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := store.MoveOut(key, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "vault.kdbx")); err != nil || string(got) != "v2" {
		t.Fatalf("moved kdbx = %q, %v", got, err)
	}
	gone := func(what string) {
		t.Helper()
		if _, err := os.Stat(store.userVaultDir(key)); !os.IsNotExist(err) {
			t.Fatalf("%s: vault directory exists: %v", what, err)
		}
	}
	gone("after MoveOut")
	if _, err := store.SaveVault(key, 2, []byte("stale"), "", "", ""); !errors.Is(err, ErrRetired) || !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale save after MoveOut = %v", err)
	}
	gone("after stale save")
	if _, err := store.SaveVault(key, 0, []byte("fresh"), "", "", ""); !errors.Is(err, ErrRetired) {
		t.Fatalf("version-0 save after MoveOut = %v", err)
	}
	gone("after version-0 save")
	if _, err := store.RestoreHistory(key, "1_v1"); !errors.Is(err, ErrRetired) {
		t.Fatalf("restore after MoveOut = %v", err)
	}
	if err := store.DiscardConflict(key, "1_web_exp0"); !errors.Is(err, ErrRetired) {
		t.Fatalf("discard after MoveOut = %v", err)
	}
	if err := store.SaveEnvelopes(key, 0, "pw", "rec", nil); !errors.Is(err, ErrRetired) {
		t.Fatalf("envelopes after MoveOut = %v", err)
	}
	gone("after every write")
	// A missing directory is not an error, and the key is retired all the same.
	other := "shared/sv_bbbbbbbbbbbbbbbbbbbbbb"
	if err := store.MoveOut(other, filepath.Join(t.TempDir(), "x")); err != nil {
		t.Fatalf("MoveOut missing = %v", err)
	}
	if _, err := store.SaveVault(other, 0, []byte("v"), "", "", ""); !errors.Is(err, ErrRetired) {
		t.Fatalf("save to a retired never-written key = %v", err)
	}
}

func TestClearHistoryRemovesSnapshotsAndConflicts(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	key := "shared/sv_abcdefghijklmnopqrstuv"
	meta, err := store.SaveVault(key, 0, []byte("one"), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault(key, meta.Version, []byte("two"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	// A rejected upload leaves a conflict behind.
	if _, err := store.SaveVault(key, 1, []byte("stale"), "", "", ""); err == nil {
		t.Fatal("expected a conflict")
	}
	hist, err := store.ListHistory(key)
	if err != nil {
		t.Fatal(err)
	}
	confs, err := store.ListConflicts(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) == 0 || len(confs) == 0 {
		t.Fatalf("fixture: %d snapshots, %d conflicts", len(hist), len(confs))
	}
	if err := store.ClearHistory(key); err != nil {
		t.Fatal(err)
	}
	if hist, err = store.ListHistory(key); err != nil || len(hist) != 0 {
		t.Fatalf("history after clear: %d %v", len(hist), err)
	}
	if confs, err = store.ListConflicts(key); err != nil || len(confs) != 0 {
		t.Fatalf("conflicts after clear: %d %v", len(confs), err)
	}
	// The current vault is untouched.
	rc, cur, err := store.OpenVault(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if string(data) != "two" || cur.Version != 2 {
		t.Fatalf("current vault = %q v%d", data, cur.Version)
	}
	// Idempotent, and a key that never existed is not an error.
	if err := store.ClearHistory(key); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearHistory("shared/sv_zzzzzzzzzzzzzzzzzzzzzz"); err != nil {
		t.Fatal(err)
	}
	// A retired key is refused, like every other writer.
	if err := store.MoveOut(key, filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearHistory(key); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired = %v", err)
	}
}

// SaveRotated is the shared-vault rotation write: it starts a new key epoch, so every
// snapshot taken under the retired key is flagged and refused for rollback even if the
// caller never manages to delete those snapshots.
func TestSaveRotatedStartsANewKeyEpoch(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	key := "shared/sv_0123456789012345678901"
	if _, err := store.SaveVault(key, 0, []byte("one"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault(key, 1, []byte("two"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	before, err := store.ListHistory(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 || before[0].StaleKey {
		t.Fatalf("history before the rotation = %+v", before)
	}

	meta, err := store.SaveRotated(key, 2, []byte("rekeyed"), "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version != 3 || meta.KeyEpochSince != 3 {
		t.Fatalf("rotated metadata = %+v", meta)
	}
	after, err := store.ListHistory(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) == 0 {
		t.Fatal("no snapshots to flag")
	}
	for _, h := range after {
		if !h.StaleKey {
			t.Fatalf("snapshot %s (v%d) is not flagged stale: %+v", h.ID, h.Version, h)
		}
		if _, err := store.RestoreHistory(key, h.ID); !errors.Is(err, ErrStaleKey) {
			t.Fatalf("restore of %s = %v, want ErrStaleKey", h.ID, err)
		}
	}
	rc, current, err := store.OpenVault(key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "rekeyed" || current.Version != 3 {
		t.Fatalf("a refused rollback changed the vault: %q v%d", data, current.Version)
	}
}
