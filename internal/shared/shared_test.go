package shared

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func sealed() string   { return base64.StdEncoding.EncodeToString(make([]byte, SealedKeyBytes)) }
func fp(n byte) string { return string([]byte{'A' + n, 'B', 'C', 'D', ' ', '1', '2', '3', '4'}) }

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "shared"), 90, func(string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustGet(t *testing.T, s *Store, id string) Vault {
	t.Helper()
	v, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidation(t *testing.T) {
	if !ValidID("sv_"+"abcdefghijklmnopqrstuv") || ValidID("sv_../x") || ValidID("u-1") || ValidID("") {
		t.Fatal("ValidID")
	}
	if ValidName("") == nil || ValidName("a\x00b") == nil || ValidName("a\u202eb") == nil || ValidName("a\u200bb") == nil || ValidName(strings.Repeat("a", 65)) == nil || ValidName("Finance team") != nil {
		t.Fatal("ValidName")
	}
	if ValidName(strings.Repeat("a", 64)) != nil {
		t.Fatal("ValidName: 64 runes should be accepted")
	}
	if ValidSealedKey(sealed()) != nil || ValidSealedKey("AAAA") == nil || ValidSealedKey("!!") == nil {
		t.Fatal("ValidSealedKey")
	}
}

func TestCreateListAndCaps(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(1), t0)
	if err != nil || !ValidID(v.ID) || v.KeyEpoch != 1 {
		t.Fatalf("create: %+v %v", v, err)
	}
	m := v.Members["u-1"]
	if m.Role != RoleOwner || m.State != StateActive || m.AcceptedAt == nil || m.KeyEpoch != 1 {
		t.Fatalf("owner row: %+v", m)
	}
	if n, err := s.CountOwned("u-1"); err != nil || n != 1 {
		t.Fatalf("CountOwned = %d, %v", n, err)
	}
	for i := 1; i < MaxOwnedVaults; i++ {
		if _, err := s.Create("v", "u-1", sealed(), fp(1), t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create("one too many", "u-1", sealed(), fp(1), t0); !errors.Is(err, ErrOwnedCap) {
		t.Fatalf("owned cap: %v", err)
	}
	all, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	mine, err := s.ListFor("u-1")
	if err != nil {
		t.Fatal(err)
	}
	none, err := s.ListFor("u-9")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != MaxOwnedVaults || len(mine) != MaxOwnedVaults || len(none) != 0 {
		t.Fatalf("lists: %d %d %d", len(all), len(mine), len(none))
	}
	if _, err := s.Get("sv_doesnotexist0000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestMembershipLifecycle(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", "SFP", t0); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("double invite: %v", err)
	}
	if err := s.Invite(v.ID, "u-3", Role("god"), sealed(), fp(3), "u-1", "SFP", t0); !errors.Is(err, ErrShape) {
		t.Fatalf("bad role: %v", err)
	}
	got := mustGet(t, s, v.ID)
	if got.Members["u-2"].State != StateInvited || got.Members["u-2"].SealedBy != "u-1" {
		t.Fatalf("invited row: %+v", got.Members["u-2"])
	}
	// Accept only from invited.
	if err := s.Accept(v.ID, "u-1", t0); !errors.Is(err, ErrState) {
		t.Fatalf("accept active: %v", err)
	}
	if err := s.Accept(v.ID, "u-2", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got = mustGet(t, s, v.ID)
	if got.Members["u-2"].State != StateActive || got.Members["u-2"].AcceptedAt == nil {
		t.Fatalf("accepted row: %+v", got.Members["u-2"])
	}
	// Role changes and the last-owner rule.
	if err := s.SetRole(v.ID, "u-1", "u-1", RoleReader); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demote last owner: %v", err)
	}
	if err := s.SetRole(v.ID, "u-1", "u-2", RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(v.ID, "u-1", "u-1", RoleReader); err != nil {
		t.Fatalf("demote with another owner: %v", err)
	}
	if err := s.Remove(v.ID, "u-2", "u-2"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove last owner: %v", err)
	}
	if err := s.Remove(v.ID, "", "u-2"); err != nil {
		t.Fatalf("admin removes last owner: %v", err)
	}
	got = mustGet(t, s, v.ID)
	if _, ok := got.Members["u-2"]; ok {
		t.Fatal("u-2 still present")
	}
	if err := s.Remove(v.ID, "", "u-9"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("remove non-member: %v", err)
	}
}

func TestMemberCap(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("big", "u-0", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < MaxMembers; i++ {
		if err := s.Invite(v.ID, "u-"+string(rune('a'+i%26))+string(rune('a'+i/26)), RoleReader, sealed(), fp(1), "u-0", "SFP", t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Invite(v.ID, "u-last", RoleReader, sealed(), fp(1), "u-0", "SFP", t0); !errors.Is(err, ErrMemberCap) {
		t.Fatalf("member cap: %v", err)
	}
}

// concurrent invites yield one row
func TestConcurrentInvitesYieldOneRow(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("race", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var okCount, otherErrCount int32
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", "SFP", t0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okCount++
			case !errors.Is(err, ErrAlreadyMember):
				otherErrCount++
			}
		}()
	}
	wg.Wait()
	if otherErrCount != 0 {
		t.Fatalf("losing calls returned something other than ErrAlreadyMember: %d", otherErrCount)
	}
	got := mustGet(t, s, v.ID)
	if okCount != 1 || len(got.Members) != 2 {
		t.Fatalf("ok=%d members=%d", okCount, len(got.Members))
	}
}

// suspend and restore keeps the prior state
func TestSuspendRestoreAndStale(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("a", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	w, err := s.Create("b", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(w.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(w.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}

	ids, err := s.SetSuspended("u-2", true)
	if err != nil || len(ids) != 2 {
		t.Fatalf("suspend: %v %v", ids, err)
	}
	gv := mustGet(t, s, v.ID)
	gw := mustGet(t, s, w.ID)
	if gv.Members["u-2"].State != StateSuspended || gv.Members["u-2"].SuspendedFrom != StateInvited ||
		gw.Members["u-2"].State != StateSuspended || gw.Members["u-2"].SuspendedFrom != StateActive {
		t.Fatalf("suspended rows: %+v %+v", gv.Members["u-2"], gw.Members["u-2"])
	}
	if _, err := s.SetSuspended("u-2", false); err != nil {
		t.Fatal(err)
	}
	gv = mustGet(t, s, v.ID)
	gw = mustGet(t, s, w.ID)
	if gv.Members["u-2"].State != StateInvited || gw.Members["u-2"].State != StateActive || gw.Members["u-2"].SuspendedFrom != "" {
		t.Fatalf("restored rows: %+v %+v", gv.Members["u-2"], gw.Members["u-2"])
	}

	// Key replacement: rows sealed to another fingerprint go stale; matching rows untouched.
	ids, err = s.MarkStale("u-2", fp(9))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("stale ids: %v", ids)
	}
	gw = mustGet(t, s, w.ID)
	if gw.Members["u-2"].State != StateStale {
		t.Fatalf("stale row: %+v", gw.Members["u-2"])
	}
	if err := s.Reseal(w.ID, "u-2", sealed(), fp(9), "u-1", "SFP"); err != nil {
		t.Fatal(err)
	}
	gw = mustGet(t, s, w.ID)
	if gw.Members["u-2"].State != StateActive || gw.Members["u-2"].KeyFingerprint != fp(9) {
		t.Fatalf("resealed row: %+v", gw.Members["u-2"])
	}
	// Reseal of an invited row keeps it invited.
	if err := s.Reseal(v.ID, "u-2", sealed(), fp(9), "u-1", "SFP"); err != nil {
		t.Fatal(err)
	}
	gv = mustGet(t, s, v.ID)
	if gv.Members["u-2"].State != StateInvited {
		t.Fatalf("resealed invited row: %+v", gv.Members["u-2"])
	}
	// Suspending the last owner is allowed (the vault becomes ownerless until reactivation).
	if _, err := s.SetSuspended("u-1", true); err != nil {
		t.Fatal(err)
	}
	gv = mustGet(t, s, v.ID)
	if gv.Members["u-1"].State != StateSuspended || gv.Members["u-1"].SuspendedFrom != StateActive {
		t.Fatalf("suspended owner row: %+v", gv.Members["u-1"])
	}
}

// Reseal on a suspended row refreshes SuspendedFrom to reflect a fresh seal, landing on
// active when unsuspended (accepted before suspension) or invited otherwise.
func TestResealWhileSuspended(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("a", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-3", RoleReader, sealed(), fp(3), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended("u-2", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended("u-3", true); err != nil {
		t.Fatal(err)
	}

	if err := s.Reseal(v.ID, "u-2", sealed(), fp(9), "u-1", "SFP"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reseal(v.ID, "u-3", sealed(), fp(9), "u-1", "SFP"); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, v.ID)
	if got.Members["u-2"].State != StateSuspended || got.Members["u-2"].SuspendedFrom != StateActive {
		t.Fatalf("resealed accepted suspended row: %+v", got.Members["u-2"])
	}
	if got.Members["u-3"].State != StateSuspended || got.Members["u-3"].SuspendedFrom != StateInvited {
		t.Fatalf("resealed unaccepted suspended row: %+v", got.Members["u-3"])
	}

	// Unsuspending now lands on the fresh seal's state.
	if _, err := s.SetSuspended("u-2", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended("u-3", false); err != nil {
		t.Fatal(err)
	}
	got = mustGet(t, s, v.ID)
	if got.Members["u-2"].State != StateActive {
		t.Fatalf("unsuspended accepted row: %+v", got.Members["u-2"])
	}
	if got.Members["u-3"].State != StateInvited {
		t.Fatalf("unsuspended unaccepted row: %+v", got.Members["u-3"])
	}
}

func TestDeleteMovesAndPrunes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	vaults := t.TempDir()
	moved := ""
	s, err := NewStore(dir, 1, func(id, dst string) error { moved = dst; return os.Rename(filepath.Join(vaults, id), dst) })
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create("gone", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(vaults, v.ID)
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "vault.kdbx"), []byte("ct"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(v.ID, "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if moved != filepath.Join(dir, "deleted", v.ID, "vault") {
		t.Fatalf("moved to %s", moved)
	}
	if _, err := os.Stat(filepath.Join(dir, "deleted", v.ID, "record.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "vault.kdbx")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneDeleted(t0.Add(12 * time.Hour)); err != nil || n != 0 {
		t.Fatalf("pruned early: %d, %v", n, err)
	}
	if n, err := s.PruneDeleted(t0.Add(25 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("pruned: %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deleted", v.ID)); !os.IsNotExist(err) {
		t.Fatal("deleted dir survives prune")
	}
}

func TestAtomicWriteIgnoresTmp(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("x", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, v.ID+".json.tmp"), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); err != nil {
		t.Fatal(err)
	}
	all, err := s.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("list with tmp: %d %v", len(all), err)
	}
	files, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Path) == ".tmp" {
			t.Fatal("snapshot includes tmp")
		}
	}
	if len(files) != 1 || files[0].Path != v.ID+".json" {
		t.Fatalf("snapshot: %+v", files)
	}
}

// A record on disk with an unknown role or state is rejected on read. Each corruption is
// applied to the original clean bytes, never stacked on the previous corruption, so a pass
// on the state check cannot be explained by the still-broken role from the first write.
func TestUnknownEnumOnDiskIsRejected(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("x", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(s.path(v.ID))
	if err != nil {
		t.Fatal(err)
	}

	badRole := strings.Replace(string(original), `"role": "owner"`, `"role": "superowner"`, 1)
	if badRole == string(original) {
		t.Fatal("role replacement did not match record contents")
	}
	if err := os.WriteFile(s.path(v.ID), []byte(badRole), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown role: %v", err)
	}

	badState := strings.Replace(string(original), `"state": "active"`, `"state": "zombie"`, 1)
	if badState == string(original) {
		t.Fatal("state replacement did not match record contents")
	}
	if err := os.WriteFile(s.path(v.ID), []byte(badState), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown state: %v", err)
	}
}

// A suspended row's SuspendedFrom must be invited, active or stale; empty (no recorded
// prior state) or any other value is rejected on read, same as an unknown role or state.
func TestSuspendedFromOnDiskIsValidated(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("x", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended("u-1", true); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(s.path(v.ID))
	if err != nil {
		t.Fatal(err)
	}

	emptyFrom := strings.Replace(string(original), `"suspendedFrom": "active",`, "", 1)
	if emptyFrom == string(original) {
		t.Fatal("suspendedFrom removal did not match record contents")
	}
	if err := os.WriteFile(s.path(v.ID), []byte(emptyFrom), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty suspendedFrom: %v", err)
	}

	badFrom := strings.Replace(string(original), `"suspendedFrom": "active"`, `"suspendedFrom": "owner"`, 1)
	if badFrom == string(original) {
		t.Fatal("suspendedFrom replacement did not match record contents")
	}
	if err := os.WriteFile(s.path(v.ID), []byte(badFrom), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad suspendedFrom: %v", err)
	}
}

// freshState is the fallback both Reseal and SetSuspended use when a row has no usable
// prior state to resume from: active only if the member was ever accepted, else invited.
func TestFreshStateFollowsAcceptedAt(t *testing.T) {
	at := t0
	if got := freshState(Member{AcceptedAt: &at}); got != StateActive {
		t.Fatalf("accepted: %v", got)
	}
	if got := freshState(Member{}); got != StateInvited {
		t.Fatalf("unaccepted: %v", got)
	}
}

// Authority is checked on the record read under the store lock, so a request that
// resolved its caller as an owner before a removal or demotion cannot write after it.
func TestActorAuthorityIsCheckedAtTheWrite(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("team", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"u-2", "u-3", "u-4"} {
		if err := s.Invite(v.ID, id, RoleOwner, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
			t.Fatal(err)
		}
		if err := s.Accept(v.ID, id, t0); err != nil {
			t.Fatal(err)
		}
	}

	// Removed actor: every owner-only write is ErrNotMember.
	if err := s.Remove(v.ID, "u-1", "u-2"); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"rename": s.Rename(v.ID, "u-2", "mine"),
		"invite": s.Invite(v.ID, "u-2", RoleOwner, sealed(), fp(2), "u-2", "SFP", t0),
		"reseal": s.Reseal(v.ID, "u-3", sealed(), fp(3), "u-2", "SFP"),
		"role":   s.SetRole(v.ID, "u-2", "u-3", RoleReader),
		"remove": s.Remove(v.ID, "u-2", "u-3"),
		"delete": s.Delete(v.ID, "u-2", t0),
	} {
		if !errors.Is(err, ErrNotMember) {
			t.Fatalf("removed actor %s: %v", name, err)
		}
	}

	// Demoted actor: ErrForbidden.
	if err := s.SetRole(v.ID, "u-1", "u-3", RoleReader); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"rename": s.Rename(v.ID, "u-3", "mine"),
		"invite": s.Invite(v.ID, "u-9", RoleReader, sealed(), fp(9), "u-3", "SFP", t0),
		"reseal": s.Reseal(v.ID, "u-4", sealed(), fp(4), "u-3", "SFP"),
		"role":   s.SetRole(v.ID, "u-3", "u-3", RoleOwner),
		"remove": s.Remove(v.ID, "u-3", "u-4"),
		"delete": s.Delete(v.ID, "u-3", t0),
	} {
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("demoted actor %s: %v", name, err)
		}
	}
	if got := mustGet(t, s, v.ID); got.Name != "team" || len(got.Members) != 3 || got.Members["u-3"].Role != RoleReader {
		t.Fatalf("refused writes changed the record: %+v", got)
	}

	// Self-remove needs no ownership.
	if err := s.Remove(v.ID, "u-3", "u-3"); err != nil {
		t.Fatalf("reader leaves: %v", err)
	}
	// Admin "" bypasses: removes the last owners and deletes.
	if err := s.Remove(v.ID, "", "u-4"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(v.ID, "", "u-1"); err != nil {
		t.Fatalf("admin removes last owner: %v", err)
	}
	if err := s.Rename(v.ID, "", "renamed"); err != nil {
		t.Fatalf("admin rename: %v", err)
	}
	if err := s.Delete(v.ID, "", t0); err != nil {
		t.Fatalf("admin delete: %v", err)
	}
}

func TestAcceptRefusesOwnerlessVault(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("team", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", "SFP", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(v.ID, "", "u-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); !errors.Is(err, ErrState) {
		t.Fatalf("accept ownerless: %v", err)
	}
}

// A sole owner who replaced their user key is stale; they may re-seal their own row, which
// brings the vault back to an active owner. Anyone else still needs an active owner.
func TestStaleSelfReseal(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("solo", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", fp(1), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkStale("u-1", fp(8)); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-3", RoleReader, sealed(), fp(3), "u-1", fp(8), t0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale owner invites: %v", err)
	}
	// Another member re-sealing the stale owner is not an owner action they may take.
	if err := s.Reseal(v.ID, "u-1", sealed(), fp(8), "u-2", fp(2)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("editor reseals the stale owner: %v", err)
	}
	// A non-stale member cannot re-seal their own row without being an active owner.
	if err := s.Reseal(v.ID, "u-2", sealed(), fp(2), "u-2", fp(2)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("active editor self-reseal: %v", err)
	}
	if err := s.Reseal(v.ID, "u-1", sealed(), fp(8), "u-1", fp(8)); err != nil {
		t.Fatalf("stale self-reseal: %v", err)
	}
	m := mustGet(t, s, v.ID).Members["u-1"]
	if m.State != StateActive || m.KeyFingerprint != fp(8) || m.SealedBy != "u-1" || m.SealedByFingerprint != fp(8) {
		t.Fatalf("after self-reseal: %+v", m)
	}
	if err := s.Invite(v.ID, "u-3", RoleReader, sealed(), fp(3), "u-1", fp(8), t0); err != nil {
		t.Fatalf("invite after self-reseal: %v", err)
	}
	if got := mustGet(t, s, v.ID).Members["u-3"].SealedByFingerprint; got != fp(8) {
		t.Fatalf("invite sealedByFingerprint = %q", got)
	}
}

// WithWriter re-checks the row under the lock and does not run fn for anyone but an
// active owner or editor.
func TestWithWriter(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("w", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", fp(1), t0); err != nil {
		t.Fatal(err)
	}
	ran := 0
	fn := func() error { ran++; return nil }
	if err := s.WithWriter(v.ID, "u-1", fn); err != nil || ran != 1 {
		t.Fatalf("owner: %v ran=%d", err, ran)
	}
	if err := s.WithWriter(v.ID, "u-2", fn); !errors.Is(err, ErrForbidden) {
		t.Fatalf("invited reader: %v", err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.WithWriter(v.ID, "u-2", fn); !errors.Is(err, ErrForbidden) {
		t.Fatalf("active reader: %v", err)
	}
	if err := s.WithWriter(v.ID, "u-9", fn); !errors.Is(err, ErrNotMember) {
		t.Fatalf("stranger: %v", err)
	}
	if ran != 1 {
		t.Fatalf("fn ran for a refused caller: %d", ran)
	}
	sentinel := errors.New("vault write failed")
	if err := s.WithWriter(v.ID, "u-1", func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("fn error not returned: %v", err)
	}
}

// A corrupt record is ErrCorrupt to Get and skipped by every bulk path.
func TestCorruptRecordIsSkipped(t *testing.T) {
	s := newStore(t)
	bad, err := s.Create("bad", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	good, err := s.Create("good", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(bad.ID), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(bad.ID); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrShape) {
		t.Fatalf("get corrupt: %v", err)
	}
	all, err := s.List()
	if err != nil || len(all) != 1 || all[0].ID != good.ID {
		t.Fatalf("list: %+v %v", all, err)
	}
	if n, err := s.CountOwned("u-1"); err != nil || n != 1 {
		t.Fatalf("count owned: %d %v", n, err)
	}
	if ids, err := s.SetSuspended("u-1", true); err != nil || len(ids) != 1 || ids[0] != good.ID {
		t.Fatalf("suspend: %v %v", ids, err)
	}
	if _, err := s.Create("another", "u-2", sealed(), fp(2), t0); err != nil {
		t.Fatalf("create beside a corrupt record: %v", err)
	}
}

// Delete interrupted after the live record is gone: NewStore finishes the move.
func TestNewStoreFinishesInterruptedDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	vaults := t.TempDir()
	mover := func(id, dst string) error {
		src := filepath.Join(vaults, id)
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			return nil
		}
		return os.Rename(src, dst)
	}
	failing := func(string, string) error { return errors.New("crash") }
	s, err := NewStore(dir, 90, failing)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Create("half", "u-1", sealed(), fp(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(vaults, v.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaults, v.ID, "vault.kdbx"), []byte("ct"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The move fails after the live record is removed: data left behind, record gone.
	if err := s.Delete(v.ID, "u-1", t0); err == nil {
		t.Fatal("delete with a failing mover succeeded")
	}
	if _, err := s.Get(v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("live record after interrupted delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vaults, v.ID)); err != nil {
		t.Fatalf("vault dir should still be live: %v", err)
	}
	if _, err := NewStore(dir, 90, mover); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(vaults, v.ID)); !os.IsNotExist(err) {
		t.Fatalf("live vault dir survives reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deleted", v.ID, "vault", "vault.kdbx")); err != nil {
		t.Fatalf("moved vault: %v", err)
	}
	// Idempotent: a second start with nothing left to move is fine.
	if _, err := NewStore(dir, 90, mover); err != nil {
		t.Fatal(err)
	}
}
