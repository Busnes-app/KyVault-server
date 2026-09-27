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
	ErrForbidden     = errors.New("only an active owner may do that")
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

// validSuspendedFrom holds when SuspendedFrom is empty for a non-suspended row, or one of
// invited/active/stale for a suspended one; a suspended row can never resume as suspended
// or as an unrecorded (empty) state.
func validSuspendedFrom(m Member) bool {
	if m.State != StateSuspended {
		return m.SuspendedFrom == ""
	}
	switch m.SuspendedFrom {
	case StateInvited, StateActive, StateStale:
		return true
	default:
		return false
	}
}

// freshState is the state a newly sealed row lands on: active if it was ever accepted,
// else invited. Reseal and an unsuspend with no usable SuspendedFrom both use this.
func freshState(m Member) State {
	if m.AcceptedAt != nil {
		return StateActive
	}
	return StateInvited
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
		return Vault{}, fmt.Errorf("%w: shared record %s: %v", ErrShape, id, err)
	}
	if v.ID != id || v.Members == nil {
		return Vault{}, fmt.Errorf("%w: shared record %s is inconsistent", ErrShape, id)
	}
	for uid, m := range v.Members {
		if !validRole(m.Role) || !validState(m.State) || !validSuspendedFrom(m) {
			return Vault{}, fmt.Errorf("%w: shared record %s member %s has an unknown role or state", ErrShape, id, uid)
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

// authorize checks, on the record read under the lock, that actorID may manage the
// vault: "" is an admin; anyone else must hold an active owner row.
func authorize(v Vault, actorID string) error {
	if actorID == "" {
		return nil
	}
	m, ok := v.Members[actorID]
	if !ok {
		return ErrNotMember
	}
	if m.Role != RoleOwner || m.State != StateActive {
		return ErrForbidden
	}
	return nil
}

// update loads, authorizes actorID, applies fn under the lock and saves. fn returns the
// error to surface.
func (s *Store) update(id, actorID string, fn func(v *Vault) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.loadLocked(id)
	if err != nil {
		return err
	}
	if err := authorize(v, actorID); err != nil {
		return err
	}
	if err := fn(&v); err != nil {
		return err
	}
	return s.saveLocked(v)
}

func (s *Store) Rename(id, actorID, name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return s.update(id, actorID, func(v *Vault) error { v.Name = name; return nil })
}

// Invite adds an invited row sealed by sealedBy, who must be an active owner.
func (s *Store) Invite(id, userID string, role Role, sealedKey, fingerprint, sealedBy string, now time.Time) error {
	if !validRole(role) {
		return fmt.Errorf("%w: unknown role", ErrShape)
	}
	if err := ValidSealedKey(sealedKey); err != nil {
		return err
	}
	return s.update(id, sealedBy, func(v *Vault) error {
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

// Reseal replaces a member's sealed key, e.g. after a user key rotation. A stale row
// (sealed to a retired user key) returns to active if it had been accepted, else invited.
// A suspended row stays suspended, but SuspendedFrom is refreshed to the state the fresh
// seal would land on, so unsuspending later resumes from the new seal rather than from
// whatever the row was suspended from before the reseal. sealedBy must be an active owner.
func (s *Store) Reseal(id, userID, sealedKey, fingerprint, sealedBy string) error {
	if err := ValidSealedKey(sealedKey); err != nil {
		return err
	}
	return s.update(id, sealedBy, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		m.SealedKey, m.KeyFingerprint, m.SealedBy, m.KeyEpoch = sealedKey, fingerprint, sealedBy, v.KeyEpoch
		switch m.State {
		case StateStale:
			m.State = freshState(m)
		case StateSuspended:
			m.SuspendedFrom = freshState(m)
		}
		v.Members[userID] = m
		return nil
	})
}

func (s *Store) SetRole(id, actorID, userID string, role Role) error {
	if !validRole(role) {
		return fmt.Errorf("%w: unknown role", ErrShape)
	}
	return s.update(id, actorID, func(v *Vault) error {
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

// Accept turns userID's invitation active. An ownerless vault cannot be joined.
func (s *Store) Accept(id, userID string, now time.Time) error {
	return s.update(id, "", func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if m.State != StateInvited {
			return ErrState
		}
		if activeOwners(*v) == 0 {
			return fmt.Errorf("%w: the vault has no owner", ErrState)
		}
		at := now.UTC()
		m.State, m.AcceptedAt = StateActive, &at
		v.Members[userID] = m
		return nil
	})
}

// Remove deletes userID's row. actorID "" is an admin, who may remove the last owner;
// a member may always remove their own row (leave, decline), under the last-owner rule;
// anyone else must be an active owner.
func (s *Store) Remove(id, actorID, userID string) error {
	authActor := actorID
	if actorID == userID {
		authActor = ""
	}
	return s.update(id, authActor, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if actorID != "" && m.Role == RoleOwner && m.State == StateActive && activeOwners(*v) == 1 {
			return ErrLastOwner
		}
		delete(v.Members, userID)
		return nil
	})
}

// Delete moves the record and, through moveVaultDir, the vault directory into the deleted
// area. moveVaultDir receives the destination and must rename the vault directory there;
// a missing vault directory (never uploaded) is not an error for the caller to raise.
// actorID "" is an admin; anyone else must be an active owner.
func (s *Store) Delete(id, actorID string, moveVaultDir func(dst string) error, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.loadLocked(id)
	if err != nil {
		return err
	}
	if err := authorize(v, actorID); err != nil {
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
			if m.SuspendedFrom == "" {
				// No recorded prior state (a corrupt or pre-validation record):
				// resume as a fresh seal would, never straight to active.
				m.State = freshState(m)
			} else {
				m.State = m.SuspendedFrom
			}
			m.SuspendedFrom = ""
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
