# Shared Vaults Server and Membership (3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Server-side shared vaults: a membership store with roles, states and per-member HPKE-sealed keys; routes for lifecycle, membership, vault data and admin; hooks for deactivation and key replacement; audit and backup coverage. No UI.

**Architecture:** New `internal/shared` package owns the membership record (`data/shared/<id>.json`), invariants, caps, the deleted area and its retention. Vault data reuses `internal/vault.Store` under the key `shared/<id>`. The personal vault handlers are refactored to take a `vaultTarget` (store key + acting user + device) so the shared routes reuse them behind a member-resolution wrapper that enforces roles and states. Admin routes and the `shared.json` setting complete the API. The backup collector gains the `data/shared/` tree.

**Tech Stack:** Go 1.26 stdlib (`net/http` `PathValue`, `encoding/json`, `os`, `sync`), existing `internal/vault`, `internal/users`, `internal/userkey`, `internal/audit`, `internal/backup`.

**Spec:** `docs/superpowers/specs/2026-09-27-shared-vaults-server-design.md`

## Global Constraints

- Repo root `KyVault-server/`. Gate: `gofmt -l . | grep -v node_modules` empty, `go vet ./...`, `go test -race ./...`. Every existing test stays green unchanged (the handler refactor's regression gate).
- Store key for a shared vault's data: `shared/<vaultId>`; `vaultId` is `sv_` + 22 base64url chars from 16 random bytes; the directory is `data/vaults/shared/<vaultId>/`.
- Membership record path: `data/shared/<vaultId>.json`; deleted area `data/shared/deleted/<vaultId>/` holding `record.json` (with `deletedAt`) and the moved vault directory `vault/`.
- `sealedKey`: base64 of exactly 1168 bytes (1120 enc + 32 + 16). Never opened server-side. `keyFingerprint` must equal the target member's current `userkey` fingerprint at write time.
- Roles `owner|editor|reader`; states `invited|active|stale|suspended`; `suspendedFrom` keeps the prior state.
- Name: 1–64 characters, no control runes.
- Caps: `MaxMembers = 100`, `MaxOwnedVaults = 20`.
- At least one `active` owner: remove/demote/leave that would violate it → `shared.ErrLastOwner` (409). Admin removal is the only path that may create an ownerless vault.
- Non-member or unknown vault → 404 on every `/api/shared/{id}` route. Other members' `sealedKey` never appears in any response body.
- Write routes (`upload`, `history/{hid}/restore`, `DELETE conflicts/{cid}`) need `active` owner or editor; readers and non-active states → 403. `invited` may read nothing under `/api/shared/{id}/…`.
- `X-Vault-Key-Rotated` on a shared upload → 400. Envelope headers/fields ignored on shared uploads.
- Owner delete, admin delete, admin member removal, admin settings PUT: fresh session (`freshSessionWindow`, message prefix `re-authenticate to continue`).
- Setting file `CONFIG_DIR/shared.json` `{ "createRestrictedToAdmins": false }`.
- Audit actions exactly as the spec lists; details carry vault id and user ids, never a sealed key.
- Commit trailer: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

1. A path-shaped vault id (`../x`, `shared/../u-1`) in the URL must be 404, never touch another user's directory (Task 3 test `path-shaped vault id is 404`; `shared.ValidID` gate).
2. Concurrent invites of the same user from two owners must not produce two rows or exceed the member cap (Task 1 store lock covers it; test `concurrent invites yield one row`).
3. A member whose account is deactivated while `invited` and later reactivated returns to `invited`, not `active` (Task 1 test `suspend and restore keeps the prior state`).
4. A stale member (key replaced) must still be able to read the vault they already had open elsewhere but not write (Task 4 test `stale member reads, cannot write`).
5. Restoring a snapshot of a shared vault must keep `Metadata` envelope fields empty and must not touch the membership record (Task 4 test `shared restore leaves envelopes empty`).

---

### Task 1: `internal/shared` store

**Files:**
- Create: `internal/shared/shared.go` (types, validation, store, lifecycle)
- Create: `internal/shared/shared_test.go`

**Interfaces:**
- Produces:
  ```go
  package shared
  const (
      RoleOwner Role = "owner"; RoleEditor Role = "editor"; RoleReader Role = "reader"
      StateInvited State = "invited"; StateActive State = "active"; StateStale State = "stale"; StateSuspended State = "suspended"
      MaxMembers = 100; MaxOwnedVaults = 20; SealedKeyBytes = 1168
  )
  type Role string; type State string
  type Member struct {
      Role Role `json:"role"`; State State `json:"state"`; SuspendedFrom State `json:"suspendedFrom,omitempty"`
      SealedKey string `json:"sealedKey"`; SealedBy string `json:"sealedBy"`; KeyFingerprint string `json:"keyFingerprint"`
      KeyEpoch int `json:"keyEpoch"`; AddedAt time.Time `json:"addedAt"`; AcceptedAt *time.Time `json:"acceptedAt,omitempty"`
  }
  type Vault struct {
      ID string `json:"id"`; Name string `json:"name"`; CreatedBy string `json:"createdBy"`; CreatedAt time.Time `json:"createdAt"`
      KeyEpoch int `json:"keyEpoch"`; Members map[string]Member `json:"members"`
  }
  var ErrNotFound, ErrNotMember, ErrAlreadyMember, ErrLastOwner, ErrMemberCap, ErrOwnedCap, ErrShape, ErrState error
  func ValidID(id string) bool                       // ^sv_[A-Za-z0-9_-]{22}$
  func ValidName(name string) error
  func ValidSealedKey(b64 string) error
  func StoreKey(id string) string                     // "shared/" + id
  func NewStore(dir string, retentionDays int) (*Store, error)   // dir = DATA_DIR/shared
  func (s *Store) Create(name, ownerID, sealedKey, fingerprint string, now time.Time) (Vault, error)
  func (s *Store) Get(id string) (Vault, error)
  func (s *Store) List() ([]Vault, error)                          // all, sorted by id
  func (s *Store) ListFor(userID string) ([]Vault, error)          // vaults with a row for userID
  func (s *Store) CountOwned(userID string) (int, error)           // active owner rows
  func (s *Store) Rename(id, name string) error
  func (s *Store) Invite(id, userID string, role Role, sealedKey, fingerprint, sealedBy string, now time.Time) error
  func (s *Store) Reseal(id, userID, sealedKey, fingerprint, sealedBy string) error   // stale->active, invited stays invited
  func (s *Store) SetRole(id, userID string, role Role) error
  func (s *Store) Accept(id, userID string, now time.Time) error
  func (s *Store) Remove(id, userID string, allowLastOwner bool) error   // decline, leave, owner/admin removal
  func (s *Store) Delete(id string, moveVaultDir func(dst string) error, now time.Time) error  // moves record + vault dir
  func (s *Store) PruneDeleted(now time.Time) (int, error)
  func (s *Store) SetSuspended(userID string, suspended bool) ([]string, error)  // vault ids touched
  func (s *Store) MarkStale(userID, currentFingerprint string) ([]string, error) // rows sealed to another fp
  func (s *Store) Snapshot() ([]SnapshotFile, error)               // for backup: every file under dir, path relative
  type SnapshotFile struct { Path string; Data []byte; Mode os.FileMode }
  ```

- [ ] **Step 1: Write the failing tests**

`internal/shared/shared_test.go`:
```go
package shared

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func sealed() string { return base64.StdEncoding.EncodeToString(make([]byte, SealedKeyBytes)) }
func fp(n byte) string { return string([]byte{'A' + n, 'B', 'C', 'D', ' ', '1', '2', '3', '4'}) }

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "shared"), 90)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidation(t *testing.T) {
	if !ValidID("sv_" + "abcdefghijklmnopqrstuv") || ValidID("sv_../x") || ValidID("u-1") || ValidID("") {
		t.Fatal("ValidID")
	}
	if ValidName("") == nil || ValidName("a\x00b") == nil || ValidName(string(make([]byte, 65))) == nil || ValidName("Finance team") != nil {
		t.Fatal("ValidName")
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
	if n, _ := s.CountOwned("u-1"); n != 1 {
		t.Fatalf("CountOwned = %d", n)
	}
	for i := 1; i < MaxOwnedVaults; i++ {
		if _, err := s.Create("v", "u-1", sealed(), fp(1), t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create("one too many", "u-1", sealed(), fp(1), t0); !errors.Is(err, ErrOwnedCap) {
		t.Fatalf("owned cap: %v", err)
	}
	all, _ := s.List()
	mine, _ := s.ListFor("u-1")
	none, _ := s.ListFor("u-9")
	if len(all) != MaxOwnedVaults || len(mine) != MaxOwnedVaults || len(none) != 0 {
		t.Fatalf("lists: %d %d %d", len(all), len(mine), len(none))
	}
	if _, err := s.Get("sv_doesnotexist0000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestMembershipLifecycle(t *testing.T) {
	s := newStore(t)
	v, _ := s.Create("Finance", "u-1", sealed(), fp(1), t0)
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", t0); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("double invite: %v", err)
	}
	if err := s.Invite(v.ID, "u-3", Role("god"), sealed(), fp(3), "u-1", t0); !errors.Is(err, ErrShape) {
		t.Fatalf("bad role: %v", err)
	}
	got, _ := s.Get(v.ID)
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
	got, _ = s.Get(v.ID)
	if got.Members["u-2"].State != StateActive || got.Members["u-2"].AcceptedAt == nil {
		t.Fatalf("accepted row: %+v", got.Members["u-2"])
	}
	// Role changes and the last-owner rule.
	if err := s.SetRole(v.ID, "u-1", RoleReader); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demote last owner: %v", err)
	}
	if err := s.SetRole(v.ID, "u-2", RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(v.ID, "u-1", RoleReader); err != nil {
		t.Fatalf("demote with another owner: %v", err)
	}
	if err := s.Remove(v.ID, "u-2", false); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove last owner: %v", err)
	}
	if err := s.Remove(v.ID, "u-2", true); err != nil {
		t.Fatalf("admin removes last owner: %v", err)
	}
	got, _ = s.Get(v.ID)
	if _, ok := got.Members["u-2"]; ok {
		t.Fatal("u-2 still present")
	}
	if err := s.Remove(v.ID, "u-9", false); !errors.Is(err, ErrNotMember) {
		t.Fatalf("remove non-member: %v", err)
	}
}

func TestMemberCap(t *testing.T) {
	s := newStore(t)
	v, _ := s.Create("big", "u-0", sealed(), fp(0), t0)
	for i := 1; i < MaxMembers; i++ {
		if err := s.Invite(v.ID, "u-"+string(rune('a'+i%26))+string(rune('a'+i/26)), RoleReader, sealed(), fp(1), "u-0", t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Invite(v.ID, "u-last", RoleReader, sealed(), fp(1), "u-0", t0); !errors.Is(err, ErrMemberCap) {
		t.Fatalf("member cap: %v", err)
	}
}

// concurrent invites yield one row
func TestConcurrentInvitesYieldOneRow(t *testing.T) {
	s := newStore(t)
	v, _ := s.Create("race", "u-1", sealed(), fp(1), t0)
	var wg sync.WaitGroup
	var okCount int32
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Invite(v.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", t0); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	got, _ := s.Get(v.ID)
	if okCount != 1 || len(got.Members) != 2 {
		t.Fatalf("ok=%d members=%d", okCount, len(got.Members))
	}
}

// suspend and restore keeps the prior state
func TestSuspendRestoreAndStale(t *testing.T) {
	s := newStore(t)
	v, _ := s.Create("a", "u-1", sealed(), fp(1), t0)
	_ = s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(2), "u-1", t0)
	w, _ := s.Create("b", "u-1", sealed(), fp(1), t0)
	_ = s.Invite(w.ID, "u-2", RoleReader, sealed(), fp(2), "u-1", t0)
	_ = s.Accept(w.ID, "u-2", t0)

	ids, err := s.SetSuspended("u-2", true)
	if err != nil || len(ids) != 2 {
		t.Fatalf("suspend: %v %v", ids, err)
	}
	gv, _ := s.Get(v.ID)
	gw, _ := s.Get(w.ID)
	if gv.Members["u-2"].State != StateSuspended || gv.Members["u-2"].SuspendedFrom != StateInvited ||
		gw.Members["u-2"].State != StateSuspended || gw.Members["u-2"].SuspendedFrom != StateActive {
		t.Fatalf("suspended rows: %+v %+v", gv.Members["u-2"], gw.Members["u-2"])
	}
	if _, err := s.SetSuspended("u-2", false); err != nil {
		t.Fatal(err)
	}
	gv, _ = s.Get(v.ID)
	gw, _ = s.Get(w.ID)
	if gv.Members["u-2"].State != StateInvited || gw.Members["u-2"].State != StateActive || gw.Members["u-2"].SuspendedFrom != "" {
		t.Fatalf("restored rows: %+v %+v", gv.Members["u-2"], gw.Members["u-2"])
	}

	// Key replacement: rows sealed to another fingerprint go stale; matching rows untouched.
	ids, _ = s.MarkStale("u-2", fp(9))
	if len(ids) != 2 {
		t.Fatalf("stale ids: %v", ids)
	}
	gw, _ = s.Get(w.ID)
	if gw.Members["u-2"].State != StateStale {
		t.Fatalf("stale row: %+v", gw.Members["u-2"])
	}
	if err := s.Reseal(w.ID, "u-2", sealed(), fp(9), "u-1"); err != nil {
		t.Fatal(err)
	}
	gw, _ = s.Get(w.ID)
	if gw.Members["u-2"].State != StateActive || gw.Members["u-2"].KeyFingerprint != fp(9) {
		t.Fatalf("resealed row: %+v", gw.Members["u-2"])
	}
	// Reseal of an invited row keeps it invited.
	_ = s.Reseal(v.ID, "u-2", sealed(), fp(9), "u-1")
	gv, _ = s.Get(v.ID)
	if gv.Members["u-2"].State != StateInvited {
		t.Fatalf("resealed invited row: %+v", gv.Members["u-2"])
	}
	// Suspending the last owner is allowed (the vault becomes ownerless until reactivation).
	if _, err := s.SetSuspended("u-1", true); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteMovesAndPrunes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	s, _ := NewStore(dir, 1)
	v, _ := s.Create("gone", "u-1", sealed(), fp(1), t0)
	vaultDir := filepath.Join(t.TempDir(), "vaults", "shared", v.ID)
	_ = os.MkdirAll(vaultDir, 0o700)
	_ = os.WriteFile(filepath.Join(vaultDir, "vault.kdbx"), []byte("ct"), 0o600)
	moved := ""
	err := s.Delete(v.ID, func(dst string) error { moved = dst; return os.Rename(vaultDir, dst) }, t0)
	if err != nil {
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
	if n, _ := s.PruneDeleted(t0.Add(12 * time.Hour)); n != 0 {
		t.Fatalf("pruned early: %d", n)
	}
	if n, _ := s.PruneDeleted(t0.Add(25 * time.Hour)); n != 1 {
		t.Fatalf("pruned: %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "deleted", v.ID)); !os.IsNotExist(err) {
		t.Fatal("deleted dir survives prune")
	}
}

func TestAtomicWriteIgnoresTmp(t *testing.T) {
	s := newStore(t)
	v, _ := s.Create("x", "u-1", sealed(), fp(1), t0)
	_ = os.WriteFile(filepath.Join(s.dir, v.ID+".json.tmp"), []byte("{garbage"), 0o600)
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
```

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/shared/`
Expected: build failure, package missing.

- [ ] **Step 3: Implement**

`internal/shared/shared.go`:
```go
// Package shared owns shared-vault membership: who may open a shared vault, in what role
// and state, and each member's copy of the vault key sealed to their user key. The vault
// bytes themselves live in internal/vault under the key StoreKey(id). Nothing here can
// open a sealed key.
package shared

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

type Role string
type State string

const (
	RoleOwner  Role = "owner"
	RoleEditor Role = "editor"
	RoleReader Role = "reader"

	StateInvited   State = "invited"
	StateActive    State = "active"
	StateStale     State = "stale"
	StateSuspended State = "suspended"

	MaxMembers     = 100
	MaxOwnedVaults = 20
	// SealedKeyBytes is HPKE enc (1120) + 32-byte vault key + 16-byte tag.
	SealedKeyBytes = 1120 + 32 + 16
	maxNameRunes   = 64
)

var (
	ErrNotFound      = errors.New("shared vault not found")
	ErrNotMember     = errors.New("not a member")
	ErrAlreadyMember = errors.New("already a member")
	ErrLastOwner     = errors.New("a shared vault keeps at least one active owner")
	ErrMemberCap     = errors.New("shared vault member limit reached")
	ErrOwnedCap      = errors.New("owned shared vault limit reached")
	ErrShape         = errors.New("invalid shared vault input")
	ErrState         = errors.New("member is not in the required state")
)

type Member struct {
	Role           Role       `json:"role"`
	State          State      `json:"state"`
	SuspendedFrom  State      `json:"suspendedFrom,omitempty"`
	SealedKey      string     `json:"sealedKey"`
	SealedBy       string     `json:"sealedBy"`
	KeyFingerprint string     `json:"keyFingerprint"`
	KeyEpoch       int        `json:"keyEpoch"`
	AddedAt        time.Time  `json:"addedAt"`
	AcceptedAt     *time.Time `json:"acceptedAt,omitempty"`
}

type Vault struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	CreatedBy string            `json:"createdBy"`
	CreatedAt time.Time         `json:"createdAt"`
	KeyEpoch  int               `json:"keyEpoch"`
	Members   map[string]Member `json:"members"`
	DeletedAt *time.Time        `json:"deletedAt,omitempty"`
}

type SnapshotFile struct {
	Path string
	Data []byte
	Mode os.FileMode
}

var idPattern = regexp.MustCompile(`^sv_[A-Za-z0-9_-]{22}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }

func ValidName(name string) error {
	n := 0
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: name has a control character", ErrShape)
		}
		n++
	}
	if n == 0 || n > maxNameRunes {
		return fmt.Errorf("%w: name must be 1 to %d characters", ErrShape, maxNameRunes)
	}
	return nil
}

func ValidSealedKey(b64 string) error {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != SealedKeyBytes {
		return fmt.Errorf("%w: sealedKey must be %d bytes of standard base64", ErrShape, SealedKeyBytes)
	}
	return nil
}

func validRole(r Role) bool { return r == RoleOwner || r == RoleEditor || r == RoleReader }
func validState(s State) bool {
	return s == StateInvited || s == StateActive || s == StateStale || s == StateSuspended
}

// StoreKey is the internal/vault key that holds a shared vault's KDBX and history.
func StoreKey(id string) string { return "shared/" + id }

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sv_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

type Store struct {
	dir           string
	retentionDays int
	mu            sync.Mutex
}

func NewStore(dir string, retentionDays int) (*Store, error) {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if err := os.MkdirAll(filepath.Join(dir, "deleted"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, retentionDays: retentionDays}, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) loadLocked(id string) (Vault, error) {
	if !ValidID(id) {
		return Vault{}, ErrNotFound
	}
	data, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return Vault{}, ErrNotFound
	}
	if err != nil {
		return Vault{}, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return Vault{}, fmt.Errorf("shared: parse %s: %w", id, err)
	}
	if v.ID != id || v.Members == nil {
		return Vault{}, fmt.Errorf("shared: record %s is inconsistent", id)
	}
	for uid, m := range v.Members {
		if !validRole(m.Role) || !validState(m.State) {
			return Vault{}, fmt.Errorf("shared: record %s member %s has an unknown role or state", id, uid)
		}
	}
	return v, nil
}

func writeAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) saveLocked(v Vault) error { return writeAtomic(s.path(v.ID), v) }

func (s *Store) listLocked() ([]Vault, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Vault
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		v, err := s.loadLocked(id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func activeOwners(v Vault) int {
	n := 0
	for _, m := range v.Members {
		if m.Role == RoleOwner && m.State == StateActive {
			n++
		}
	}
	return n
}

func (s *Store) Create(name, ownerID, sealedKey, fingerprint string, now time.Time) (Vault, error) {
	if err := ValidName(name); err != nil {
		return Vault{}, err
	}
	if err := ValidSealedKey(sealedKey); err != nil {
		return Vault{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owned, err := s.countOwnedLocked(ownerID)
	if err != nil {
		return Vault{}, err
	}
	if owned >= MaxOwnedVaults {
		return Vault{}, ErrOwnedCap
	}
	id, err := newID()
	if err != nil {
		return Vault{}, err
	}
	at := now.UTC()
	v := Vault{ID: id, Name: name, CreatedBy: ownerID, CreatedAt: at, KeyEpoch: 1, Members: map[string]Member{
		ownerID: {Role: RoleOwner, State: StateActive, SealedKey: sealedKey, SealedBy: ownerID, KeyFingerprint: fingerprint, KeyEpoch: 1, AddedAt: at, AcceptedAt: &at},
	}}
	return v, s.saveLocked(v)
}

func (s *Store) countOwnedLocked(userID string) (int, error) {
	all, err := s.listLocked()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range all {
		if m, ok := v.Members[userID]; ok && m.Role == RoleOwner && m.State == StateActive {
			n++
		}
	}
	return n, nil
}

func (s *Store) CountOwned(userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countOwnedLocked(userID)
}

func (s *Store) Get(id string) (Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(id)
}

func (s *Store) List() ([]Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked()
}

func (s *Store) ListFor(userID string) ([]Vault, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, v := range all {
		if _, ok := v.Members[userID]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// update loads, applies fn under the lock and saves. fn returns the error to surface.
func (s *Store) update(id string, fn func(v *Vault) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.loadLocked(id)
	if err != nil {
		return err
	}
	if err := fn(&v); err != nil {
		return err
	}
	return s.saveLocked(v)
}

func (s *Store) Rename(id, name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return s.update(id, func(v *Vault) error { v.Name = name; return nil })
}

func (s *Store) Invite(id, userID string, role Role, sealedKey, fingerprint, sealedBy string, now time.Time) error {
	if !validRole(role) {
		return fmt.Errorf("%w: unknown role", ErrShape)
	}
	if err := ValidSealedKey(sealedKey); err != nil {
		return err
	}
	return s.update(id, func(v *Vault) error {
		if _, ok := v.Members[userID]; ok {
			return ErrAlreadyMember
		}
		if len(v.Members) >= MaxMembers {
			return ErrMemberCap
		}
		v.Members[userID] = Member{Role: role, State: StateInvited, SealedKey: sealedKey, SealedBy: sealedBy, KeyFingerprint: fingerprint, KeyEpoch: v.KeyEpoch, AddedAt: now.UTC()}
		return nil
	})
}

func (s *Store) Reseal(id, userID, sealedKey, fingerprint, sealedBy string) error {
	if err := ValidSealedKey(sealedKey); err != nil {
		return err
	}
	return s.update(id, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		m.SealedKey, m.KeyFingerprint, m.SealedBy, m.KeyEpoch = sealedKey, fingerprint, sealedBy, v.KeyEpoch
		if m.State == StateStale {
			// A row that was never accepted goes back to invited, not active.
			if m.AcceptedAt != nil {
				m.State = StateActive
			} else {
				m.State = StateInvited
			}
		}
		v.Members[userID] = m
		return nil
	})
}

func (s *Store) SetRole(id, userID string, role Role) error {
	if !validRole(role) {
		return fmt.Errorf("%w: unknown role", ErrShape)
	}
	return s.update(id, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if m.Role == RoleOwner && role != RoleOwner && m.State == StateActive && activeOwners(*v) == 1 {
			return ErrLastOwner
		}
		m.Role = role
		v.Members[userID] = m
		return nil
	})
}

func (s *Store) Accept(id, userID string, now time.Time) error {
	return s.update(id, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if m.State != StateInvited {
			return ErrState
		}
		at := now.UTC()
		m.State, m.AcceptedAt = StateActive, &at
		v.Members[userID] = m
		return nil
	})
}

func (s *Store) Remove(id, userID string, allowLastOwner bool) error {
	return s.update(id, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if !allowLastOwner && m.Role == RoleOwner && m.State == StateActive && activeOwners(*v) == 1 {
			return ErrLastOwner
		}
		delete(v.Members, userID)
		return nil
	})
}

// Delete moves the record and, through moveVaultDir, the vault directory into the deleted
// area. moveVaultDir receives the destination and must rename the vault directory there;
// a missing vault directory (never uploaded) is not an error for the caller to raise.
func (s *Store) Delete(id string, moveVaultDir func(dst string) error, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.loadLocked(id)
	if err != nil {
		return err
	}
	dst := filepath.Join(s.dir, "deleted", id)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	at := now.UTC()
	v.DeletedAt = &at
	if err := writeAtomic(filepath.Join(dst, "record.json"), v); err != nil {
		return err
	}
	if err := moveVaultDir(filepath.Join(dst, "vault")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(s.path(id))
}

func (s *Store) PruneDeleted(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "deleted"))
	if err != nil {
		return 0, err
	}
	cutoff := now.Add(-time.Duration(s.retentionDays) * 24 * time.Hour)
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.dir, "deleted", e.Name())
		data, err := os.ReadFile(filepath.Join(dir, "record.json"))
		if err != nil {
			continue
		}
		var v Vault
		if json.Unmarshal(data, &v) != nil || v.DeletedAt == nil || !v.DeletedAt.Before(cutoff) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Store) SetSuspended(userID string, suspended bool) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.listLocked()
	if err != nil {
		return nil, err
	}
	var touched []string
	for _, v := range all {
		m, ok := v.Members[userID]
		if !ok {
			continue
		}
		switch {
		case suspended && m.State != StateSuspended:
			m.SuspendedFrom, m.State = m.State, StateSuspended
		case !suspended && m.State == StateSuspended:
			m.State, m.SuspendedFrom = m.SuspendedFrom, ""
			if m.State == "" {
				m.State = StateActive
			}
		default:
			continue
		}
		v.Members[userID] = m
		if err := s.saveLocked(v); err != nil {
			return touched, err
		}
		touched = append(touched, v.ID)
	}
	return touched, nil
}

// MarkStale flags every row of userID sealed to a fingerprint other than their current one.
func (s *Store) MarkStale(userID, currentFingerprint string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.listLocked()
	if err != nil {
		return nil, err
	}
	var touched []string
	for _, v := range all {
		m, ok := v.Members[userID]
		if !ok || m.KeyFingerprint == currentFingerprint || m.State == StateStale {
			continue
		}
		switch m.State {
		case StateSuspended:
			m.SuspendedFrom = StateStale
		default: // active and invited both need a re-seal before the key is usable
			m.State = StateStale
		}
		v.Members[userID] = m
		if err := s.saveLocked(v); err != nil {
			return touched, err
		}
		touched = append(touched, v.ID)
	}
	return touched, nil
}

// Snapshot returns every regular file under the store directory (records and the deleted
// area), paths relative to it, for the backup capsule.
func (s *Store) Snapshot() ([]SnapshotFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var files []SnapshotFile
	err := filepath.WalkDir(s.dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("shared snapshot refuses symlink %s", path)
		}
		if entry.IsDir() || !entry.Type().IsRegular() || strings.HasSuffix(entry.Name(), ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("shared snapshot path escapes base directory: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, SnapshotFile{Path: filepath.ToSlash(rel), Data: data, Mode: info.Mode().Perm()})
		return nil
	})
	return files, err
}
```
`MarkStale` marks both active and invited rows stale (an invited row still needs a re-seal before its key is usable); `Reseal` returns a stale row to `active` only if it had been accepted, else to `invited`. `TestSuspendRestoreAndStale` pins both.

- [ ] **Step 4: Run tests**

Run: `gofmt -l internal/shared; go vet ./internal/shared/ && go test -race ./internal/shared/`
Expected: gofmt empty; PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared
git commit -m "shared: membership store with roles, states, sealed keys and deleted area

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Parameterise the personal vault handlers

**Files:**
- Modify: `internal/api/vault_handlers.go`
- Modify: `internal/api/server.go` (routes call the wrappers)

**Interfaces:**
- Produces:
  ```go
  // vaultTarget names which store entry a data handler acts on and who is acting.
  type vaultTarget struct {
      key      string      // vault.Store key: u.ID or shared.StoreKey(id)
      user     users.User  // acting user, for audit
      deviceID string      // session DeviceID, for audit and conflict filenames
      shared   bool        // true → envelopes/rotation headers refused/ignored, audit prefix "shared."
      filename string      // Content-Disposition base name
      fileParam string     // PathValue name of a history/conflict id: "id" personal, "hid"/"cid" shared
  }
  func (s *Server) vaultMetadata(w, r, t vaultTarget)
  func (s *Server) vaultDownload(w, r, t vaultTarget)
  func (s *Server) vaultUpload(w, r, t vaultTarget)
  func (s *Server) vaultHistory(w, r, t vaultTarget)
  func (s *Server) vaultHistoryRestore(w, r, t vaultTarget)
  func (s *Server) vaultHistoryDownload(w, r, t vaultTarget)
  func (s *Server) vaultConflicts(w, r, t vaultTarget)
  func (s *Server) vaultConflictDiscard(w, r, t vaultTarget)
  func (s *Server) vaultConflictDownload(w, r, t vaultTarget)
  func (s *Server) personalTarget(r *http.Request, u users.User) vaultTarget
  ```
  The existing `handleVault*` names stay as thin wrappers: `func (s *Server) handleVaultMetadata(w, r, u) { s.vaultMetadata(w, r, s.personalTarget(r, u)) }` etc., so `server.go` route lines do not change.

- [ ] **Step 1: Refactor**

For each handler in `internal/api/vault_handlers.go`:
- Replace `u.ID` in `s.vault.*` calls with `t.key`.
- Replace `u.ID` in `s.record(...)` with `t.user.ID`; audit action gets `t.auditAction("vault.saved")` which returns `"shared.saved"` when `t.shared` (map the personal suffixes: `vault.download`→`shared.download`, `vault.saved`→`shared.saved`, `vault.conflict_rejected`→`shared.conflict_rejected`, `vault.restored_snapshot`→`shared.rolled_back`, `vault.snapshot_downloaded`→`shared.snapshot_downloaded`, `vault.conflict_discarded`→`shared.conflict_discarded`, `vault.conflict_download`→`shared.conflict_downloaded`). Implement as:
  ```go
  func (t vaultTarget) auditAction(personal string) string {
      if !t.shared { return personal }
      switch personal {
      case "vault.restored_snapshot": return "shared.rolled_back"
      case "vault.conflict_download": return "shared.conflict_downloaded"
      }
      return "shared." + strings.TrimPrefix(personal, "vault.")
  }
  ```
  Put every shared vault-id in the detail: prefix details with `t.key + ": "` when `t.shared`.
- `vaultUpload`: `devID` comes from `t.deviceID`. When `t.shared`: if `X-Vault-Key-Rotated == "1"` → 400 `"shared vaults do not rotate through this route"`; ignore `pwEnv`/`recEnv`/`X-User-Key` (set them to empty before `SaveVault`) and skip `revokeAllDevices`.
- `vaultDownload`: filename from `t.filename`.
- `personalTarget`: `vaultTarget{key: u.ID, user: u, deviceID: sess.DeviceID, filename: u.Username + "-vault.kdbx", fileParam: "id"}` with `sess, _ := s.currentSession(r)`. Every history/conflict handler reads its file id with `r.PathValue(t.fileParam)`.

- [ ] **Step 2: Gate**

Run: `gofmt -l internal/api; go vet ./internal/api/ && go test -race ./internal/api/`
Expected: every existing test PASS with no test file changed (`git status --short internal/api/*_test.go` empty).

- [ ] **Step 3: Commit**

```bash
git add internal/api/vault_handlers.go internal/api/server.go
git commit -m "api: vault data handlers take a target (store key + actor) for reuse

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Shared vault lifecycle, membership and admin routes

**Files:**
- Create: `internal/api/shared_handlers.go`
- Create: `internal/api/shared_settings.go`
- Modify: `internal/api/server.go` (fields, construction, routes)
- Create: `internal/api/shared_test.go`

**Interfaces:**
- Consumes: `internal/shared` (Task 1); `withAuth`, `withAdmin`, `withFreshAdmin`, `freshSessionWindow`, `s.record`, `writeJSON`, `clientIP`, `s.users.Get`, `s.vault.GetMetadata`, `userkey.Record.Fingerprint`.
- Produces:
  ```go
  // Server fields
  shared *shared.Store            // NewStore(cfg.DataDir+"/shared", cfg.RetentionDays)
  sharedSettings *sharedSettings  // CONFIG_DIR/shared.json
  type sharedSettings struct { path string; mu sync.Mutex }
  func (c *sharedSettings) Get() (SharedSettings, error)       // {CreateRestrictedToAdmins bool `json:"createRestrictedToAdmins"`}
  func (c *sharedSettings) Put(v SharedSettings) error
  // member resolution
  type sharedCtx struct { vault shared.Vault; me shared.Member; user users.User; session Session }
  func (s *Server) sharedMember(w http.ResponseWriter, r *http.Request, u users.User) (sharedCtx, bool) // 404 on !ValidID / not found / not a member
  func (s *Server) requireFresh(w http.ResponseWriter, sess Session) bool  // 403 re-authenticate…
  func (s *Server) currentFingerprint(userID string) (string, bool)   // from vault metadata UserKey
  ```
  Routes (all in `server.go`):
  ```go
  mux.HandleFunc("POST /api/shared", s.withAuth(s.handleSharedCreate))
  mux.HandleFunc("GET /api/shared", s.withAuth(s.handleSharedList))
  mux.HandleFunc("GET /api/shared/{id}", s.withAuth(s.handleSharedGet))
  mux.HandleFunc("PATCH /api/shared/{id}", s.withAuth(s.handleSharedRename))
  mux.HandleFunc("DELETE /api/shared/{id}", s.withAuth(s.handleSharedDelete))
  mux.HandleFunc("POST /api/shared/{id}/members", s.withAuth(s.handleSharedInvite))
  mux.HandleFunc("PUT /api/shared/{id}/members/{userId}", s.withAuth(s.handleSharedMemberUpdate))
  mux.HandleFunc("DELETE /api/shared/{id}/members/{userId}", s.withAuth(s.handleSharedMemberRemove))
  mux.HandleFunc("POST /api/shared/{id}/accept", s.withAuth(s.handleSharedAccept))
  mux.HandleFunc("POST /api/shared/{id}/decline", s.withAuth(s.handleSharedDecline))
  mux.HandleFunc("GET /api/admin/shared", s.withAdmin(s.handleAdminSharedList))
  mux.HandleFunc("DELETE /api/admin/shared/{id}", s.withFreshAdmin(s.handleAdminSharedDelete))
  mux.HandleFunc("DELETE /api/admin/shared/{id}/members/{userId}", s.withFreshAdmin(s.handleAdminSharedMemberRemove))
  mux.HandleFunc("GET /api/admin/shared/settings", s.withAdmin(s.handleAdminSharedSettingsGet))
  mux.HandleFunc("PUT /api/admin/shared/settings", s.withFreshAdmin(s.handleAdminSharedSettingsPut))
  ```
  Register `GET /api/admin/shared/settings` BEFORE `GET /api/admin/shared` is not needed (different paths), but `DELETE /api/admin/shared/{id}` vs `/settings`: `{id}` would match `settings` on DELETE only; there is no DELETE settings route, fine.

- [ ] **Step 1: Write the failing tests**

`internal/api/shared_test.go`:
```go
package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

func sealedKeyB64() string { return base64.StdEncoding.EncodeToString(make([]byte, shared.SealedKeyBytes)) }

// publishKey gives u a user key with public key bytes all = pk and returns its fingerprint.
func publishKey(t *testing.T, srv *Server, u users.User, pk byte) string {
	t.Helper()
	if meta, _ := srv.vault.GetMetadata(u.ID); meta.Version == 0 {
		if _, err := srv.vault.SaveVault(u.ID, 0, []byte("v"), "pw", "rec", ""); err != nil {
			t.Fatal(err)
		}
	}
	rec := userkey.Record{Alg: userkey.AlgXWing, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{pk}, userkey.PublicKeyBytes)),
		WrappedSeed: base64.StdEncoding.EncodeToString(make([]byte, userkey.WrappedSeedBytes)), CreatedAt: t0}
	meta, _ := srv.vault.GetMetadata(u.ID)
	if _, err := srv.vault.SaveUserKey(u.ID, meta.Version, rec, false); err != nil {
		t.Fatal(err)
	}
	fp, _ := rec.Fingerprint()
	return fp
}

func do(handler http.Handler, method, path string, cookie *http.Cookie, body any, headers map[string]string) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func createShared(t *testing.T, handler http.Handler, cookie *http.Cookie, name, fp string) string {
	t.Helper()
	rec := do(handler, http.MethodPost, "/api/shared", cookie, map[string]any{"name": name, "sealedKey": sealedKeyB64(), "keyFingerprint": fp}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestSharedCreateInviteAcceptAndVisibility(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	_, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)

	// No published key → 404 on create.
	if rec := do(h, http.MethodPost, "/api/shared", carolC, map[string]any{"name": "x", "sealedKey": sealedKeyB64(), "keyFingerprint": "nope"}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("create without key = %d", rec.Code)
	}
	// Fingerprint mismatch → 400.
	if rec := do(h, http.MethodPost, "/api/shared", aliceC, map[string]any{"name": "x", "sealedKey": sealedKeyB64(), "keyFingerprint": bobFP}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("create fp mismatch = %d", rec.Code)
	}
	id := createShared(t, h, aliceC, "Finance", aliceFP)

	// path-shaped vault id is 404
	for _, p := range []string{"/api/shared/../" + alice.ID, "/api/shared/shared%2F..%2F" + alice.ID, "/api/shared/u-1", "/api/shared/sv_zzzzzzzzzzzzzzzzzzzzzz"} {
		if rec := do(h, http.MethodGet, p, aliceC, nil, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d", p, rec.Code)
		}
	}
	// Non-member sees 404 everywhere.
	for _, m := range []struct{ method, path string }{{"GET", "/api/shared/" + id}, {"PATCH", "/api/shared/" + id}, {"DELETE", "/api/shared/" + id}, {"POST", "/api/shared/" + id + "/members"}, {"POST", "/api/shared/" + id + "/accept"}} {
		if rec := do(h, m.method, m.path, carolC, map[string]any{"name": "y"}, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("non-member %s %s = %d", m.method, m.path, rec.Code)
		}
	}

	// Invite bob (wrong fp → 400; right → 200); reader role for the check later.
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": sealedKeyB64(), "keyFingerprint": aliceFP}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invite fp mismatch = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": sealedKeyB64(), "keyFingerprint": bobFP}, nil); rec.Code != http.StatusOK {
		t.Fatalf("invite = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "reader", "sealedKey": sealedKeyB64(), "keyFingerprint": bobFP}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("double invite = %d", rec.Code)
	}

	// Bob's list shows the invitation with alice's fingerprint; bob cannot read the vault yet.
	rec := do(h, http.MethodGet, "/api/shared", bobC, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"invited"`) || !strings.Contains(rec.Body.String(), aliceFP) {
		t.Fatalf("bob list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/shared/"+id, bobC, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("invited GET vault = %d", rec.Code)
	}
	// Alice's GET shows members without any sealedKey.
	rec = do(h, http.MethodGet, "/api/shared/"+id, aliceC, nil, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sealedKey") {
		t.Fatalf("owner GET = %d %s", rec.Code, rec.Body.String())
	}
	// Only bob can accept; alice (active) cannot.
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/accept", aliceC, nil, nil); rec.Code != http.StatusConflict {
		t.Fatalf("owner accept = %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("bob accept = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, http.MethodGet, "/api/shared", bobC, nil, nil)
	if !strings.Contains(rec.Body.String(), `"state":"active"`) || strings.Count(rec.Body.String(), "sealedKey") != 1 {
		t.Fatalf("bob list after accept: %s", rec.Body.String())
	}

	// Rename: editors cannot, owners can, validation applies.
	if rec := do(h, http.MethodPatch, "/api/shared/"+id, bobC, map[string]any{"name": "Ops"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("editor rename = %d", rec.Code)
	}
	if rec := do(h, http.MethodPatch, "/api/shared/"+id, aliceC, map[string]any{"name": ""}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty rename = %d", rec.Code)
	}
	if rec := do(h, http.MethodPatch, "/api/shared/"+id, aliceC, map[string]any{"name": "Ops"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("rename = %d", rec.Code)
	}

	// Last-owner rule via the API, then leave.
	if rec := do(h, http.MethodPut, "/api/shared/"+id+"/members/"+alice.ID, aliceC, map[string]any{"role": "reader"}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("demote last owner = %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/shared/"+id+"/members/"+bob.ID, bobC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("bob leaves = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/shared/"+id, bobC, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after leave = %d", rec.Code)
	}

	// Owner delete needs a fresh session; then the vault is gone for everyone.
	stale := staleSession(t, srv, alice)
	if rec := do(h, http.MethodDelete, "/api/shared/"+id, stale, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stale delete = %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/shared/"+id, aliceC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/shared/"+id, aliceC, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete = %d", rec.Code)
	}

	entries, _ := srv.audit.List(200)
	want := map[string]bool{"shared.created": false, "shared.member_invited": false, "shared.member_accepted": false, "shared.renamed": false, "shared.member_left": false, "shared.deleted": false}
	for _, e := range entries {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
		if strings.Contains(e.Details, sealedKeyB64()[:40]) {
			t.Fatalf("audit detail carries a sealed key: %s", e.Action)
		}
	}
	for a, seen := range want {
		if !seen {
			t.Fatalf("missing audit %s", a)
		}
	}
}

func TestSharedAdminAndSettings(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	admin, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, h, aliceC, "Finance", aliceFP)

	// Admin sees it, is not a member, cannot read it through member routes.
	rec := do(h, http.MethodGet, "/api/admin/shared", adminC, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), id) || strings.Contains(rec.Body.String(), "sealedKey") {
		t.Fatalf("admin list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/shared/"+id, adminC, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("admin member GET = %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/admin/shared", aliceC, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("user admin list = %d", rec.Code)
	}

	// Settings: restrict creation to admins.
	if rec := do(h, http.MethodPut, "/api/admin/shared/settings", adminC, map[string]any{"createRestrictedToAdmins": true}, nil); rec.Code != http.StatusOK {
		t.Fatalf("settings put = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/shared", aliceC, map[string]any{"name": "x", "sealedKey": sealedKeyB64(), "keyFingerprint": aliceFP}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("restricted create = %d", rec.Code)
	}
	adminFP := publishKey(t, srv, admin, 3)
	createShared(t, h, adminC, "Admin vault", adminFP)
	rec = do(h, http.MethodGet, "/api/admin/shared/settings", adminC, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"createRestrictedToAdmins":true`) {
		t.Fatalf("settings get = %d %s", rec.Code, rec.Body.String())
	}

	// Admin removes the last owner: vault becomes ownerless, flagged, undeletable by members, deletable by admin.
	if rec := do(h, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+alice.ID, adminC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin remove owner = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, http.MethodGet, "/api/admin/shared", adminC, nil, nil)
	if !strings.Contains(rec.Body.String(), `"ownerless":true`) {
		t.Fatalf("ownerless flag missing: %s", rec.Body.String())
	}
	stale := staleSession(t, srv, admin)
	if rec := do(h, http.MethodDelete, "/api/admin/shared/"+id, stale, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("stale admin delete = %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/admin/shared/"+id, adminC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin delete = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := srv.shared.Get(id); err == nil {
		t.Fatal("vault still exists after admin delete")
	}
}
```
`t0` is declared in `user_key_test.go`? No: declare `var t0 = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)` at the top of `shared_test.go` (add the `time` import) unless a `t0` already exists in package `api` tests (`grep -n "t0 " internal/api/*_test.go`).

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/api/ -run TestShared`
Expected: compile failure (`srv.shared` undefined).

- [ ] **Step 3: Implement settings**

`internal/api/shared_settings.go`:
```go
package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type SharedSettings struct {
	CreateRestrictedToAdmins bool `json:"createRestrictedToAdmins"`
}

// sharedSettings is CONFIG_DIR/shared.json; absent means defaults.
type sharedSettings struct {
	path string
	mu   sync.Mutex
}

func newSharedSettings(configDir string) *sharedSettings {
	return &sharedSettings{path: filepath.Join(configDir, "shared.json")}
}

func (c *sharedSettings) Get() (SharedSettings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var v SharedSettings
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(data, &v)
}

func (c *sharedSettings) Put(v SharedSettings) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, _ := json.MarshalIndent(v, "", "  ")
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
```

- [ ] **Step 4: Implement handlers**

`internal/api/shared_handlers.go`:
```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

const sharedBodyLimit = 64 << 10

type sharedCtx struct {
	vault   shared.Vault
	me      shared.Member
	user    users.User
	session Session
}

// sharedMember resolves the caller's row. Anything short of membership is 404 so a
// vault's existence is never confirmed to outsiders.
func (s *Server) sharedMember(w http.ResponseWriter, r *http.Request, u users.User) (sharedCtx, bool) {
	id := r.PathValue("id")
	if !shared.ValidID(id) {
		http.Error(w, "not found", http.StatusNotFound)
		return sharedCtx{}, false
	}
	v, err := s.shared.Get(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return sharedCtx{}, false
	}
	m, ok := v.Members[u.ID]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return sharedCtx{}, false
	}
	sess, _ := s.currentSession(r)
	return sharedCtx{vault: v, me: m, user: u, session: sess}, true
}

func (c sharedCtx) activeOwner() bool  { return c.me.Role == shared.RoleOwner && c.me.State == shared.StateActive }
func (c sharedCtx) canWrite() bool     { return c.me.State == shared.StateActive && (c.me.Role == shared.RoleOwner || c.me.Role == shared.RoleEditor) }
func (c sharedCtx) canRead() bool      { return c.me.State == shared.StateActive || c.me.State == shared.StateStale }

func (s *Server) requireFresh(w http.ResponseWriter, sess Session) bool {
	if sess.AuthenticatedAt.IsZero() || time.Since(sess.AuthenticatedAt) > freshSessionWindow {
		http.Error(w, "re-authenticate to continue: sign in again through KySignOn", http.StatusForbidden)
		return false
	}
	return true
}

// currentFingerprint is the fingerprint of userID's published user key, if any.
func (s *Server) currentFingerprint(userID string) (string, bool) {
	meta, err := s.vault.GetMetadata(userID)
	if err != nil || meta.UserKey == nil {
		return "", false
	}
	fp, err := meta.UserKey.Fingerprint()
	return fp, err == nil
}

func decodeShared(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, sharedBodyLimit)).Decode(v); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func sharedErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrShape):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, shared.ErrAlreadyMember), errors.Is(err, shared.ErrLastOwner), errors.Is(err, shared.ErrMemberCap), errors.Is(err, shared.ErrOwnedCap), errors.Is(err, shared.ErrState):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, shared.ErrNotFound), errors.Is(err, shared.ErrNotMember):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "shared vault error: "+err.Error(), http.StatusInternalServerError)
	}
}

type memberView struct {
	UserID         string     `json:"userId"`
	Username       string     `json:"username"`
	Role           shared.Role  `json:"role"`
	State          shared.State `json:"state"`
	KeyFingerprint string     `json:"keyFingerprint"`
	KeyEpoch       int        `json:"keyEpoch"`
	AddedAt        time.Time  `json:"addedAt"`
	AcceptedAt     *time.Time `json:"acceptedAt,omitempty"`
}

func (s *Server) memberViews(v shared.Vault) []memberView {
	out := make([]memberView, 0, len(v.Members))
	for uid, m := range v.Members {
		name := ""
		if u, err := s.users.Get(uid); err == nil {
			name = u.Username
		}
		out = append(out, memberView{UserID: uid, Username: name, Role: m.Role, State: m.State, KeyFingerprint: m.KeyFingerprint, KeyEpoch: m.KeyEpoch, AddedAt: m.AddedAt, AcceptedAt: m.AcceptedAt})
	}
	sortMemberViews(out)
	return out
}

func sortMemberViews(v []memberView) {
	// owners first, then by username, then id — deterministic for clients and tests
	sort.Slice(v, func(i, j int) bool {
		if (v[i].Role == shared.RoleOwner) != (v[j].Role == shared.RoleOwner) {
			return v[i].Role == shared.RoleOwner
		}
		if v[i].Username != v[j].Username {
			return v[i].Username < v[j].Username
		}
		return v[i].UserID < v[j].UserID
	})
}

// POST /api/shared
func (s *Server) handleSharedCreate(w http.ResponseWriter, r *http.Request, u users.User) {
	var req struct {
		Name           string `json:"name"`
		SealedKey      string `json:"sealedKey"`
		KeyFingerprint string `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	settings, err := s.sharedSettings.Get()
	if err != nil {
		http.Error(w, "shared settings unreadable", http.StatusInternalServerError)
		return
	}
	if settings.CreateRestrictedToAdmins && u.Role != users.RoleAdmin {
		http.Error(w, "an administrator has restricted shared vault creation to administrators", http.StatusForbidden)
		return
	}
	fp, ok := s.currentFingerprint(u.ID)
	if !ok {
		http.Error(w, "publish a user key before creating a shared vault", http.StatusNotFound)
		return
	}
	if req.KeyFingerprint != fp {
		http.Error(w, "keyFingerprint does not match your current user key", http.StatusBadRequest)
		return
	}
	v, err := s.shared.Create(req.Name, u.ID, req.SealedKey, fp, time.Now())
	if err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.created", u.ID, "", clientIP(r), v.ID+" "+v.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"id": v.ID})
}

type myKeyView struct {
	SealedKey           string `json:"sealedKey"`
	KeyFingerprint      string `json:"keyFingerprint"`
	KeyEpoch            int    `json:"keyEpoch"`
	SealedBy            string `json:"sealedBy"`
	SealedByFingerprint string `json:"sealedByFingerprint"`
}

type inviterView struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
}

// GET /api/shared
func (s *Server) handleSharedList(w http.ResponseWriter, r *http.Request, u users.User) {
	vaults, err := s.shared.ListFor(u.ID)
	if err != nil {
		http.Error(w, "failed to list shared vaults", http.StatusInternalServerError)
		return
	}
	type row struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		Role      shared.Role  `json:"role"`
		State     shared.State `json:"state"`
		KeyEpoch  int          `json:"keyEpoch"`
		MyKey     myKeyView    `json:"myKey"`
		InvitedBy *inviterView `json:"invitedBy,omitempty"`
	}
	out := make([]row, 0, len(vaults))
	for _, v := range vaults {
		m := v.Members[u.ID]
		sealerFP, _ := s.currentFingerprint(m.SealedBy)
		rw := row{ID: v.ID, Name: v.Name, Role: m.Role, State: m.State, KeyEpoch: v.KeyEpoch,
			MyKey: myKeyView{SealedKey: m.SealedKey, KeyFingerprint: m.KeyFingerprint, KeyEpoch: m.KeyEpoch, SealedBy: m.SealedBy, SealedByFingerprint: sealerFP}}
		if m.State == shared.StateInvited {
			name := ""
			if inv, err := s.users.Get(m.SealedBy); err == nil {
				name = inv.Username
			}
			rw.InvitedBy = &inviterView{UserID: m.SealedBy, Username: name, Fingerprint: sealerFP}
		}
		out = append(out, rw)
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/shared/{id}
func (s *Server) handleSharedGet(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if c.me.State == shared.StateInvited {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": c.vault.ID, "name": c.vault.Name, "createdBy": c.vault.CreatedBy, "createdAt": c.vault.CreatedAt,
		"keyEpoch": c.vault.KeyEpoch, "members": s.memberViews(c.vault),
	})
}

// PATCH /api/shared/{id}
func (s *Server) handleSharedRename(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can rename a shared vault", http.StatusForbidden)
		return
	}
	var req struct{ Name string `json:"name"` }
	if !decodeShared(w, r, &req) {
		return
	}
	if err := s.shared.Rename(c.vault.ID, req.Name); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.renamed", u.ID, "", clientIP(r), c.vault.ID+" "+req.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// deleteShared moves the record and vault data to the deleted area.
func (s *Server) deleteShared(id string) error {
	src := filepath.Join(s.dataDir, "vaults", "shared", id)
	return s.shared.Delete(id, func(dst string) error {
		if _, err := os.Stat(src); err != nil {
			return err // os.IsNotExist is tolerated by the store
		}
		return os.Rename(src, dst)
	}, time.Now())
}

// DELETE /api/shared/{id}
func (s *Server) handleSharedDelete(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can delete a shared vault", http.StatusForbidden)
		return
	}
	if !s.requireFresh(w, c.session) {
		return
	}
	if err := s.deleteShared(c.vault.ID); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.deleted", u.ID, "", clientIP(r), c.vault.ID+" "+c.vault.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/shared/{id}/members
func (s *Server) handleSharedInvite(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can add members", http.StatusForbidden)
		return
	}
	var req struct {
		UserID         string      `json:"userId"`
		Role           shared.Role `json:"role"`
		SealedKey      string      `json:"sealedKey"`
		KeyFingerprint string      `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	target, err := s.users.Get(req.UserID)
	if err != nil || !target.Active {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	fp, ok := s.currentFingerprint(target.ID)
	if !ok {
		http.Error(w, "that user has not published a key yet", http.StatusNotFound)
		return
	}
	if req.KeyFingerprint != fp {
		http.Error(w, "keyFingerprint does not match that user's current key", http.StatusBadRequest)
		return
	}
	if err := s.shared.Invite(c.vault.ID, target.ID, req.Role, req.SealedKey, fp, u.ID, time.Now()); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_invited", u.ID, "", clientIP(r), c.vault.ID+" "+target.ID+" "+string(req.Role))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// PUT /api/shared/{id}/members/{userId}
func (s *Server) handleSharedMemberUpdate(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can change members", http.StatusForbidden)
		return
	}
	target := r.PathValue("userId")
	var req struct {
		Role           *shared.Role `json:"role"`
		SealedKey      string       `json:"sealedKey"`
		KeyFingerprint string       `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	if (req.SealedKey == "") != (req.KeyFingerprint == "") {
		http.Error(w, "sealedKey and keyFingerprint come together", http.StatusBadRequest)
		return
	}
	if req.SealedKey != "" {
		fp, ok := s.currentFingerprint(target)
		if !ok || fp != req.KeyFingerprint {
			http.Error(w, "keyFingerprint does not match that user's current key", http.StatusBadRequest)
			return
		}
		if err := s.shared.Reseal(c.vault.ID, target, req.SealedKey, fp, u.ID); err != nil {
			sharedErr(w, err)
			return
		}
		s.record(r, "shared.member_resealed", u.ID, "", clientIP(r), c.vault.ID+" "+target)
	}
	if req.Role != nil {
		if err := s.shared.SetRole(c.vault.ID, target, *req.Role); err != nil {
			sharedErr(w, err)
			return
		}
		s.record(r, "shared.member_role_changed", u.ID, "", clientIP(r), c.vault.ID+" "+target+" "+string(*req.Role))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DELETE /api/shared/{id}/members/{userId}: owners remove anyone; anyone leaves.
func (s *Server) handleSharedMemberRemove(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	target := r.PathValue("userId")
	self := target == u.ID
	if !self && !c.activeOwner() {
		http.Error(w, "only an owner can remove members", http.StatusForbidden)
		return
	}
	if err := s.shared.Remove(c.vault.ID, target, false); err != nil {
		sharedErr(w, err)
		return
	}
	action := "shared.member_removed"
	if self {
		action = "shared.member_left"
	}
	s.record(r, action, u.ID, "", clientIP(r), c.vault.ID+" "+target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/shared/{id}/accept
func (s *Server) handleSharedAccept(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if err := s.shared.Accept(c.vault.ID, u.ID, time.Now()); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_accepted", u.ID, "", clientIP(r), c.vault.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/shared/{id}/decline
func (s *Server) handleSharedDecline(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if c.me.State != shared.StateInvited {
		http.Error(w, "only an invitation can be declined", http.StatusConflict)
		return
	}
	if err := s.shared.Remove(c.vault.ID, u.ID, false); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_declined", u.ID, "", clientIP(r), c.vault.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Admin

func (s *Server) handleAdminSharedList(w http.ResponseWriter, r *http.Request, _ users.User) {
	vaults, err := s.shared.List()
	if err != nil {
		http.Error(w, "failed to list shared vaults", http.StatusInternalServerError)
		return
	}
	type row struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		CreatedBy string       `json:"createdBy"`
		CreatedAt time.Time    `json:"createdAt"`
		KeyEpoch  int          `json:"keyEpoch"`
		Ownerless bool         `json:"ownerless"`
		Members   []memberView `json:"members"`
	}
	out := make([]row, 0, len(vaults))
	for _, v := range vaults {
		owners := 0
		for _, m := range v.Members {
			if m.Role == shared.RoleOwner && m.State == shared.StateActive {
				owners++
			}
		}
		out = append(out, row{ID: v.ID, Name: v.Name, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, KeyEpoch: v.KeyEpoch, Ownerless: owners == 0, Members: s.memberViews(v)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAdminSharedDelete(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	if !shared.ValidID(id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	v, err := s.shared.Get(id)
	if err != nil {
		sharedErr(w, err)
		return
	}
	if err := s.deleteShared(id); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "admin.shared_deleted", admin.ID, "", clientIP(r), id+" "+v.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminSharedMemberRemove(w http.ResponseWriter, r *http.Request, admin users.User) {
	id, target := r.PathValue("id"), r.PathValue("userId")
	if !shared.ValidID(id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.shared.Remove(id, target, true); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "admin.shared_member_removed", admin.ID, "", clientIP(r), id+" "+target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminSharedSettingsGet(w http.ResponseWriter, r *http.Request, _ users.User) {
	v, err := s.sharedSettings.Get()
	if err != nil {
		http.Error(w, "shared settings unreadable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleAdminSharedSettingsPut(w http.ResponseWriter, r *http.Request, admin users.User) {
	var v SharedSettings
	if !decodeShared(w, r, &v) {
		return
	}
	if err := s.sharedSettings.Put(v); err != nil {
		http.Error(w, "failed to save shared settings", http.StatusInternalServerError)
		return
	}
	s.record(r, "admin.shared_settings_updated", admin.ID, "", clientIP(r), fmt.Sprintf("createRestrictedToAdmins=%t", v.CreateRestrictedToAdmins))
	writeJSON(w, http.StatusOK, v)
}
```
Add the `fmt` and `sort` imports. In `server.go`: add fields `shared *shared.Store` and `sharedSettings *sharedSettings`; construct `shared.NewStore(cfg.DataDir+"/shared", cfg.RetentionDays)` next to the vault store (error → `init shared store`), `newSharedSettings(cfg.ConfigDir)`; call `s.shared.PruneDeleted(time.Now())` once in `NewServer` after construction (log and continue on error); register the routes.

- [ ] **Step 5: Gate**

Run: `gofmt -l internal; go vet ./... && go test -race ./internal/api/ ./internal/shared/`
Expected: PASS, including both new tests. Then the full `go test -race ./...`.

- [ ] **Step 6: Commit**

```bash
git add internal/api/shared_handlers.go internal/api/shared_settings.go internal/api/server.go internal/api/shared_test.go
git commit -m "api: shared vault lifecycle, membership, admin routes and settings

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Shared vault data routes and hooks

**Files:**
- Modify: `internal/api/shared_handlers.go` (data routes)
- Modify: `internal/api/server.go` (routes)
- Modify: `internal/api/admin_handlers.go`, `internal/api/scim_handlers.go`, `internal/api/sync_handlers.go` (deactivation hook), `internal/api/user_key_handlers.go` (stale hook)
- Modify: `internal/api/shared_test.go` (append)

**Interfaces:**
- Consumes: `vaultTarget` and the `vault*` handlers (Task 2); `sharedCtx` (Task 3); `s.shared.SetSuspended`, `MarkStale`.
- Produces:
  ```go
  func (s *Server) sharedTarget(c sharedCtx) vaultTarget   // key shared.StoreKey(id), shared: true, filename "<name>.kdbx"
  func (s *Server) withSharedRead(next func(http.ResponseWriter, *http.Request, vaultTarget)) func(http.ResponseWriter, *http.Request, users.User)
  func (s *Server) withSharedWrite(next ...) ...
  func (s *Server) userActiveChanged(r *http.Request, userID string, active bool)   // hook
  func (s *Server) userKeyReplaced(r *http.Request, userID, newFingerprint string)  // hook
  ```
  Routes:
  ```go
  mux.HandleFunc("GET /api/shared/{id}/metadata", s.withAuth(s.withSharedRead(s.vaultMetadata)))
  mux.HandleFunc("GET /api/shared/{id}/kdbx", s.withAuth(s.withSharedRead(s.vaultDownload)))
  mux.HandleFunc("POST /api/shared/{id}/upload", s.withAuth(s.withSharedWrite(s.vaultUpload)))
  mux.HandleFunc("GET /api/shared/{id}/history", s.withAuth(s.withSharedRead(s.vaultHistory)))
  mux.HandleFunc("GET /api/shared/{id}/history/{hid}", s.withAuth(s.withSharedRead(s.vaultHistoryDownload)))
  mux.HandleFunc("POST /api/shared/{id}/history/{hid}/restore", s.withAuth(s.withSharedWrite(s.vaultHistoryRestore)))
  mux.HandleFunc("GET /api/shared/{id}/conflicts", s.withAuth(s.withSharedRead(s.vaultConflicts)))
  mux.HandleFunc("GET /api/shared/{id}/conflicts/{cid}", s.withAuth(s.withSharedRead(s.vaultConflictDownload)))
  mux.HandleFunc("DELETE /api/shared/{id}/conflicts/{cid}", s.withAuth(s.withSharedWrite(s.vaultConflictDiscard)))
  ```
  The Task 2 handlers read the history/conflict id with `r.PathValue("id")`; on the shared routes that is the vault id. Change the Task 2 handlers to read `t.fileID(r)`, where `vaultTarget` gains `fileParam string` (`"id"` for personal, `"hid"`/`"cid"` for shared; set by `withSharedRead/Write` from the route: simplest is `fileParam` = `"hid"` when `r.PathValue("hid") != ""` else `"cid"` else `"id"`, computed once in `sharedTarget`).

- [ ] **Step 1: Write the failing tests**

Append to `internal/api/shared_test.go`:
```go
func TestSharedDataRoutesAndRoles(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	carolFP := publishKey(t, srv, carol, 3)
	id := createShared(t, h, aliceC, "Finance", aliceFP)
	invite := func(u users.User, fp, role string) {
		if rec := do(h, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": u.ID, "role": role, "sealedKey": sealedKeyB64(), "keyFingerprint": fp}, nil); rec.Code != http.StatusOK {
			t.Fatalf("invite %s = %d %s", u.Username, rec.Code, rec.Body.String())
		}
	}
	invite(bob, bobFP, "editor")
	invite(carol, carolFP, "reader")
	_ = do(h, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil, nil)
	_ = do(h, http.MethodPost, "/api/shared/"+id+"/accept", carolC, nil, nil)

	upload := func(c *http.Cookie, ifMatch, body string, extra map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/shared/"+id+"/upload", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("If-Match", ifMatch)
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Owner uploads v1 with envelope headers, which are ignored; rotation header refused.
	if rec := upload(aliceC, `"0"`, "kdbx-v1", map[string]string{"X-Password-Envelope": "should-be-ignored", "X-Recovery-Envelope": "x"}); rec.Code != http.StatusOK {
		t.Fatalf("owner upload = %d %s", rec.Code, rec.Body.String())
	}
	if rec := upload(aliceC, `"1"`, "kdbx-v2", map[string]string{"X-Vault-Key-Rotated": "1", "X-Password-Envelope": "p", "X-Recovery-Envelope": "r"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotation header = %d", rec.Code)
	}
	meta, _ := srv.vault.GetMetadata(shared.StoreKey(id))
	if meta.Version != 1 || meta.PasswordEnvelope != "" || meta.RecoveryEnvelope != "" {
		t.Fatalf("shared metadata: %+v", meta)
	}
	// Editor writes; reader reads but cannot write; non-member 404.
	if rec := upload(bobC, `"1"`, "kdbx-v2", nil); rec.Code != http.StatusOK {
		t.Fatalf("editor upload = %d %s", rec.Code, rec.Body.String())
	}
	if rec := upload(carolC, `"2"`, "kdbx-v3", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reader upload = %d", rec.Code)
	}
	for _, p := range []string{"/metadata", "/kdbx", "/history", "/conflicts"} {
		if rec := do(h, http.MethodGet, "/api/shared/"+id+p, carolC, nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("reader GET %s = %d", p, rec.Code)
		}
	}
	rec := do(h, http.MethodGet, "/api/shared/"+id+"/kdbx", carolC, nil, nil)
	if rec.Body.String() != "kdbx-v2" || !strings.Contains(rec.Header().Get("Content-Disposition"), "Finance.kdbx") {
		t.Fatalf("download body/disposition: %q %q", rec.Body.String(), rec.Header().Get("Content-Disposition"))
	}
	_, daveC := signedInUser(t, srv, "dave", users.RoleUser)
	if rec := do(h, http.MethodGet, "/api/shared/"+id+"/metadata", daveC, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("non-member metadata = %d", rec.Code)
	}
	// Conflict: stale If-Match preserves a conflict; reader cannot discard, editor can.
	if rec := upload(bobC, `"1"`, "kdbx-stale", nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale upload = %d", rec.Code)
	}
	rec = do(h, http.MethodGet, "/api/shared/"+id+"/conflicts", bobC, nil, nil)
	var conflicts []struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &conflicts)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts: %s", rec.Body.String())
	}
	if rec := do(h, http.MethodDelete, "/api/shared/"+id+"/conflicts/"+conflicts[0].ID, carolC, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reader discard = %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/shared/"+id+"/conflicts/"+conflicts[0].ID, bobC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("editor discard = %d %s", rec.Code, rec.Body.String())
	}
	// shared restore leaves envelopes empty
	rec = do(h, http.MethodGet, "/api/shared/"+id+"/history", bobC, nil, nil)
	var hist []struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &hist)
	if len(hist) == 0 {
		t.Fatalf("history: %s", rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/history/"+hist[0].ID+"/restore", carolC, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reader restore = %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/shared/"+id+"/history/"+hist[0].ID+"/restore", bobC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("editor restore = %d %s", rec.Code, rec.Body.String())
	}
	meta, _ = srv.vault.GetMetadata(shared.StoreKey(id))
	if meta.PasswordEnvelope != "" || meta.UserKey != nil {
		t.Fatalf("restore polluted metadata: %+v", meta)
	}
	if v, _ := srv.shared.Get(id); len(v.Members) != 3 {
		t.Fatal("restore touched the membership record")
	}
	// Device token of an editor can read and write.
	_, token := pairDeviceForTest(t, h, bobC)
	req := httptest.NewRequest(http.MethodPost, "/api/shared/"+id+"/upload", bytes.NewReader([]byte("kdbx-dev")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-Match", `"`+strconvI(meta.Version)+`"`)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("device upload = %d %s", out.Code, out.Body.String())
	}
	meta, _ = srv.vault.GetMetadata(shared.StoreKey(id))
	if meta.UpdatedByDevice == "" {
		t.Fatal("device id not recorded on shared save")
	}

	entries, _ := srv.audit.List(200)
	var saved, rejected, rolled, discarded bool
	for _, e := range entries {
		saved = saved || e.Action == "shared.saved"
		rejected = rejected || e.Action == "shared.conflict_rejected"
		rolled = rolled || e.Action == "shared.rolled_back"
		discarded = discarded || e.Action == "shared.conflict_discarded"
		if strings.HasPrefix(e.Action, "shared.") && !strings.Contains(e.Details, id) {
			t.Fatalf("audit %s lacks the vault id: %q", e.Action, e.Details)
		}
	}
	if !saved || !rejected || !rolled || !discarded {
		t.Fatalf("audit: saved=%v rejected=%v rolled=%v discarded=%v", saved, rejected, rolled, discarded)
	}
}

func strconvI(v int64) string { return strconv.FormatInt(v, 10) }

// stale member reads, cannot write; suspension follows the account.
func TestSharedHooksStaleAndSuspended(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	admin, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	_ = admin
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	id := createShared(t, h, aliceC, "Finance", aliceFP)
	_ = do(h, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": sealedKeyB64(), "keyFingerprint": bobFP}, nil)
	_ = do(h, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/shared/"+id+"/upload", bytes.NewReader([]byte("v1")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-Match", `"0"`)
	req.AddCookie(aliceC)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Bob replaces his user key → his row goes stale: reads ok, writes refused, list says stale.
	newBobFP := publishKey(t, srv, bob, 9)
	v, _ := srv.shared.Get(id)
	if v.Members[bob.ID].State != shared.StateStale {
		t.Fatalf("bob after key replace: %+v", v.Members[bob.ID])
	}
	if rec := do(h, http.MethodGet, "/api/shared/"+id+"/metadata", bobC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("stale read = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/shared/"+id+"/upload", bytes.NewReader([]byte("v2")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-Match", `"1"`)
	req.AddCookie(bobC)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale write = %d", rec.Code)
	}
	// Owner re-seals with the new fingerprint → active again.
	if rec := do(h, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"sealedKey": sealedKeyB64(), "keyFingerprint": newBobFP}, nil); rec.Code != http.StatusOK {
		t.Fatalf("reseal = %d %s", rec.Code, rec.Body.String())
	}
	v, _ = srv.shared.Get(id)
	if v.Members[bob.ID].State != shared.StateActive {
		t.Fatalf("bob after reseal: %+v", v.Members[bob.ID])
	}

	// Admin deactivates bob → suspended (from active); reactivation restores active.
	if rec := do(h, http.MethodPost, "/api/admin/users/"+bob.ID+"/deactivate", adminC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d %s", rec.Code, rec.Body.String())
	}
	v, _ = srv.shared.Get(id)
	if v.Members[bob.ID].State != shared.StateSuspended || v.Members[bob.ID].SuspendedFrom != shared.StateActive {
		t.Fatalf("bob suspended: %+v", v.Members[bob.ID])
	}
	if rec := do(h, http.MethodPost, "/api/admin/users/"+bob.ID+"/reactivate", adminC, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("reactivate = %d", rec.Code)
	}
	v, _ = srv.shared.Get(id)
	if v.Members[bob.ID].State != shared.StateActive {
		t.Fatalf("bob restored: %+v", v.Members[bob.ID])
	}
	entries, _ := srv.audit.List(200)
	var stale, susp, restored bool
	for _, e := range entries {
		stale = stale || e.Action == "shared.member_stale"
		susp = susp || e.Action == "shared.member_suspended"
		restored = restored || e.Action == "shared.member_restored"
	}
	if !stale || !susp || !restored {
		t.Fatalf("hook audit: stale=%v suspended=%v restored=%v", stale, susp, restored)
	}
}
```
Add `strconv` to the imports. `publishKey` calling `SaveUserKey` directly does not run the API hook; for the "replace" step the test must go through the API instead: replace the `newBobFP := publishKey(...)` line with a `PUT /api/vault/user-key` from `bobC` carrying a record with public key bytes `9` and `If-Match` on bob's vault version (build the body like `userKeyBody(t, 9)` from `user_key_test.go`), then compute `newBobFP := userkey.Fingerprint(bytes.Repeat([]byte{9}, userkey.PublicKeyBytes))`.

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/api/ -run 'TestSharedDataRoutes|TestSharedHooks'`
Expected: FAIL (404 on data routes / missing hooks).

- [ ] **Step 3: Implement data routes**

In `shared_handlers.go`:
```go
func (s *Server) sharedTarget(r *http.Request, c sharedCtx) vaultTarget {
	param := "cid"
	if r.PathValue("hid") != "" {
		param = "hid"
	}
	return vaultTarget{key: shared.StoreKey(c.vault.ID), user: c.user, deviceID: c.session.DeviceID, shared: true, filename: c.vault.Name + ".kdbx", fileParam: param}
}

func (s *Server) withSharedRead(next func(http.ResponseWriter, *http.Request, vaultTarget)) func(http.ResponseWriter, *http.Request, users.User) {
	return func(w http.ResponseWriter, r *http.Request, u users.User) {
		c, ok := s.sharedMember(w, r, u)
		if !ok {
			return
		}
		if !c.canRead() {
			http.Error(w, "not found", http.StatusNotFound) // invited: the vault is not theirs yet
			return
		}
		next(w, r, s.sharedTarget(r, c))
	}
}

func (s *Server) withSharedWrite(next func(http.ResponseWriter, *http.Request, vaultTarget)) func(http.ResponseWriter, *http.Request, users.User) {
	return func(w http.ResponseWriter, r *http.Request, u users.User) {
		c, ok := s.sharedMember(w, r, u)
		if !ok {
			return
		}
		if !c.canRead() {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !c.canWrite() {
			http.Error(w, "this vault is read-only for you", http.StatusForbidden)
			return
		}
		next(w, r, s.sharedTarget(r, c))
	}
}
```
`vaultTarget.fileParam` already exists from Task 2. Filename: sanitise `c.vault.Name` for the header by replacing `"` and control runes with `_` (a tiny helper `headerToken`).

- [ ] **Step 4: Implement hooks**

In `shared_handlers.go`:
```go
// userActiveChanged mirrors an account's active flag onto its memberships. Best effort:
// a failure is audited, never surfaced to the caller that changed the account.
func (s *Server) userActiveChanged(r *http.Request, userID string, active bool) {
	ids, err := s.shared.SetSuspended(userID, !active)
	if err != nil {
		s.record(r, "shared.hook_failed", userID, "", clientIP(r), "suspend: "+err.Error())
		return
	}
	action := "shared.member_suspended"
	if active {
		action = "shared.member_restored"
	}
	for _, id := range ids {
		s.record(r, action, userID, "", clientIP(r), id+" "+userID)
	}
}

// userKeyReplaced marks every membership sealed to a previous key stale.
func (s *Server) userKeyReplaced(r *http.Request, userID, fingerprint string) {
	ids, err := s.shared.MarkStale(userID, fingerprint)
	if err != nil {
		s.record(r, "shared.hook_failed", userID, "", clientIP(r), "stale: "+err.Error())
		return
	}
	for _, id := range ids {
		s.record(r, "shared.member_stale", userID, "", clientIP(r), id+" "+userID)
	}
}
```
Call sites:
- `admin_handlers.go` `handleAdminUserDeactivate`: after the users write succeeds, `s.userActiveChanged(r, id, false)`; `handleAdminUserReactivate`: `s.userActiveChanged(r, id, true)`.
- `scim_handlers.go`: after the DELETE branch's `UpdateDirectory`, `s.userActiveChanged(r, id, false)`; after the PUT/POST/PATCH branch's `UpdateDirectory`, `s.userActiveChanged(r, id, attrs.Active)`.
- `sync_handlers.go`: after the `user.deleted` `UpdateDirectory`, `s.userActiveChanged(r, existing.ID, false)`; `applySCIMUpdate` gains an `r *http.Request` parameter and calls `s.userActiveChanged(r, existing.ID, u.Active)` (update its callers).
- `user_key_handlers.go` `handleUserKeyPut`: after a successful save when `!created`, `s.userKeyReplaced(r, u.ID, fp)`.
Read each call site first; if `UpdateDirectory` is also used for creates (`user.created`), calling the hook with `active` there is harmless (no rows).

- [ ] **Step 5: Gate**

Run: `gofmt -l internal; go vet ./... && go test -race ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api
git commit -m "api: shared vault data routes with role gates; deactivation and key-replacement hooks

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Backup coverage and restore docs

**Files:**
- Modify: `internal/backup/backup.go` (Collector `Shared *shared.Store`, files under `data/shared/`)
- Modify: `internal/backup/config.go:32` (protected roots include `data/shared`)
- Modify: `internal/api/server.go:~153` and `cmd/server/backup.go:78` (pass `Shared`)
- Modify: `internal/backup/backup_test.go` (append)
- Modify: `docs/RESTORE.md` (table rows)

**Interfaces:**
- Consumes: `shared.Store.Snapshot()` (Task 1).

- [ ] **Step 1: Write the failing test**

Append to `internal/backup/backup_test.go` (reuse its existing collector fixture; read the file first to find the helper that builds a `Collector` with temp stores, and extend it to construct a `shared.Store` in `dataDir/shared`):
```go
func TestCapsuleIncludesSharedVaults(t *testing.T) {
	c, dataDir := testCollector(t) // existing helper name may differ; adapt
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
	_ = dataDir
}
```
If the existing collector test fixture is a `Collector` literal, add `Shared:` to it; if `Collect()` requires `Shared != nil`, every existing test that builds a `Collector` must set it (add to the fixture in one place).

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/backup/ -run TestCapsuleIncludesSharedVaults`
Expected: compile failure (`c.Shared` undefined).

- [ ] **Step 3: Implement**

`backup.go`: add `Shared *shared.Store` to `Collector`; in `Collect`, after `vaultFiles`:
```go
	sharedFiles, err := c.Shared.Snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
```
and after the vault-files loop:
```go
	for _, file := range sharedFiles {
		files = append(files, capsule.File{Path: "data/shared/" + file.Path, Content: file.Data, Mode: file.Mode})
	}
```
Add `c.Shared == nil` to the missing-source check. `config.go`: add `filepath.Join(data, "shared")` to the protected roots list. `server.go` and `cmd/server/backup.go`: pass `Shared: sStore` (construct a `shared.NewStore` in `cmd/server/backup.go` beside its vault store). The drill's restore check already walks `data/vaults` recursively; add a second walk over `data/shared` that parses each `*.json` record with `shared`'s loader rules (unmarshal into `shared.Vault`, require `ID` to match the filename) and adds a check line `"shared vault records"`.

`docs/RESTORE.md`: add table rows:
```md
| `data/vaults/shared/<id>/vault.kdbx`, `metadata.json`, `history/`, `conflicts/` | Each shared vault's encrypted KDBX with its version history. Encrypted under a key only its members hold |
| `data/shared/<id>.json` | Shared vault membership: name, members, roles, states and each member's copy of the vault key sealed to that member's user key. The server cannot open these |
| `data/shared/deleted/<id>/` | Shared vaults deleted within the retention window (record and vault data), kept for operator recovery |
| `config/shared.json` | Shared vault settings (creation restricted to admins or not) |
```
and, in the restore verification paragraph, mention that a restored instance with no shared vaults has no `data/shared/*.json`, which is not an error. Also add `config/shared.json` to the capsule (optional file: include only when it exists, like `scim.token`).

- [ ] **Step 4: Gate**

Run: `gofmt -l internal cmd; go vet ./... && go test -race ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/backup internal/api/server.go cmd/server/backup.go docs/RESTORE.md
git commit -m "backup: collect shared vault records and settings into the capsule

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Docs and full verification

**Files:**
- Create: `internal/shared/AGENTS.md`
- Modify: `AGENTS.md` (Authentication routes, Child DOX Index, capabilities list)

- [ ] **Step 1: `internal/shared/AGENTS.md`**

```md
# Shared vault membership

## Purpose
Owns who may open a shared vault, in what role and state, and each member's copy of the vault
key sealed to their user key. Vault bytes live in `internal/vault` under `StoreKey(id)`
(`shared/<id>`). Nothing here can open a sealed key.

## Ownership
- `shared.go`: record shape, validation, store, lifecycle, deleted area, backup snapshot.
- `shared_test.go`: every transition and invariant.

## Local Contracts
- Record: `data/shared/<id>.json`, atomic tmp+rename, one mutex for the store.
- Roles `owner|editor|reader`; states `invited|active|stale|suspended` (`suspendedFrom` keeps
  the prior state). Unknown values fail on load.
- `sealedKey` is exactly 1168 bytes of standard base64 (HPKE enc + key + tag), shape-checked
  only. `keyFingerprint` records which user key it was sealed to.
- Invariants: at least one active owner (`ErrLastOwner`) unless `Remove(…, allowLastOwner=true)`
  (admin path); caps `MaxMembers` 100, `MaxOwnedVaults` 20; a row always carries a sealed key.
- `MarkStale` flags active and invited rows sealed to another fingerprint; `Reseal` returns a
  stale row to active if it had been accepted, else invited. `SetSuspended` mirrors the account.
- `Delete` moves record + vault directory to `deleted/<id>/`; `PruneDeleted` removes entries
  older than the retention window. Called once at server start.

## Verification
`go test -race ./internal/shared/`.
```

- [ ] **Step 2: Root `AGENTS.md`**

- Core capabilities: add item 10 "**Shared Vaults (server side)**: `internal/shared` membership with per-member HPKE-sealed keys; vault data under `internal/vault` key `shared/<id>`; roles enforced server-side, contents never readable by the server or admins."
- Authentication section: list the `/api/shared/*` and `/api/admin/shared*` routes with their gates (member 404 rule, role gates, fresh session for deletes/admin removal/settings).
- Child DOX Index: `internal/shared/AGENTS.md` entry, plus a bullet for `internal/api/shared_handlers.go` covering: `sharedMember` 404 rule, `withSharedRead/Write`, `vaultTarget` reuse and audit prefix mapping, the two hooks and their call sites, `shared.json` setting, admin ownerless flag, and "3b/3c/3d not built: no UI, no shared key rotation, extension/KyAuth unaware".

- [ ] **Step 3: Full verification**

`gofmt -l . | grep -v node_modules` (empty), `go vet ./...`, `go test -race ./...`, `govulncheck ./...` (via `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` if not installed). Frontend untouched: `cd frontend && npm test && npm run build` must still pass (no change expected).

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md internal/shared/AGENTS.md
git commit -m "docs: shared vault membership contract and routes

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
