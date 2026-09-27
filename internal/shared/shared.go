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
	"log"
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
	// ErrCorrupt is a record on disk that fails to parse or validate; never shown to callers.
	ErrCorrupt   = errors.New("shared vault record is corrupt")
	ErrState     = errors.New("member is not in the required state")
	ErrForbidden = errors.New("only an active owner may do that")
	ErrEpoch     = errors.New("the shared vault key was rotated")
)

// RotationReason records what departure left the vault needing a new key.
type RotationReason string

const (
	ReasonRemoved  RotationReason = "removed"
	ReasonLeft     RotationReason = "left"
	ReasonDeclined RotationReason = "declined"
)

func validReason(r RotationReason) bool {
	return r == ReasonRemoved || r == ReasonLeft || r == ReasonDeclined
}

// Pending marks a vault whose key a departed member still holds a working copy of.
type Pending struct {
	Since  time.Time      `json:"since"`
	UserID string         `json:"userId"`
	Reason RotationReason `json:"reason"`
}

// SealedFor is one member's copy of a new vault key, sealed to the key fingerprint the
// caller sealed against; it overwrites the row's, and only the route can check it against
// the member's current published key.
type SealedFor struct {
	UserID         string `json:"userId"`
	SealedKey      string `json:"sealedKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

type Member struct {
	Role                Role       `json:"role"`
	State               State      `json:"state"`
	SuspendedFrom       State      `json:"suspendedFrom,omitempty"`
	SealedKey           string     `json:"sealedKey"`
	SealedBy            string     `json:"sealedBy"`
	SealedByFingerprint string     `json:"sealedByFingerprint"` // sealer's fingerprint at seal time
	KeyFingerprint      string     `json:"keyFingerprint"`
	KeyEpoch            int        `json:"keyEpoch"`
	AddedAt             time.Time  `json:"addedAt"`
	AcceptedAt          *time.Time `json:"acceptedAt,omitempty"`
}

type Vault struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	CreatedBy string            `json:"createdBy"`
	CreatedAt time.Time         `json:"createdAt"`
	KeyEpoch  int               `json:"keyEpoch"`
	Members   map[string]Member `json:"members"`
	DeletedAt *time.Time        `json:"deletedAt,omitempty"`
	// RotationPending is set by the departure that made the key stale and cleared by Rotate.
	RotationPending *Pending `json:"rotationPending,omitempty"`
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
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
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

// landOn moves a row to state s, except that a suspended row keeps suspended and records s
// as the state it will resume to. Every re-seal (Reseal, Rotate) and every stale-marking
// (MarkStale, the members a Rotate leaves behind) goes through it.
func landOn(m Member, s State) Member {
	if m.State == StateSuspended {
		m.SuspendedFrom = s
	} else {
		m.State = s
	}
	return m
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

// VaultMover renames the live vault directory of shared vault id to dst. A missing
// directory is not an error. The API passes vault.Store.MoveOut.
type VaultMover func(id, dst string) error

type Store struct {
	dir           string
	retentionDays int
	moveVault     VaultMover
	mu            sync.Mutex
}

// NewStore opens the store and finishes any Delete a crash interrupted. moveVault may be
// nil for read-only use (offline backup); Delete then fails and nothing is reconciled.
func NewStore(dir string, retentionDays int, moveVault VaultMover) (*Store, error) {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if err := os.MkdirAll(filepath.Join(dir, "deleted"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, retentionDays: retentionDays, moveVault: moveVault}
	if moveVault != nil {
		if err := s.reconcileDeleted(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// reconcileDeleted moves the vault data of every deleted record whose live record is gone:
// Delete removes the live record before moving the data, so a crash between the two leaves
// the data behind with nothing to admit a member.
func (s *Store) reconcileDeleted() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "deleted"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		id := e.Name()
		dir := filepath.Join(s.dir, "deleted", id)
		if !e.IsDir() || !ValidID(id) {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "record.json")); err != nil {
			continue
		}
		if _, err := os.Stat(s.path(id)); !os.IsNotExist(err) {
			continue // still live: Delete stopped before removing it and can simply run again
		}
		if err := s.moveVault(id, filepath.Join(dir, "vault")); err != nil {
			log.Printf("shared vault %s: finishing an interrupted delete: %v", id, err)
		}
	}
	return nil
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
		return Vault{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, id, err)
	}
	if v.ID != id || v.Members == nil {
		return Vault{}, fmt.Errorf("%w: %s is inconsistent", ErrCorrupt, id)
	}
	for uid, m := range v.Members {
		if !validRole(m.Role) || !validState(m.State) || !validSuspendedFrom(m) {
			return Vault{}, fmt.Errorf("%w: %s member %s has an unknown role or state", ErrCorrupt, id, uid)
		}
	}
	if p := v.RotationPending; p != nil && (p.UserID == "" || !validReason(p.Reason)) {
		return Vault{}, fmt.Errorf("%w: %s has an invalid rotationPending", ErrCorrupt, id)
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
		if errors.Is(err, ErrCorrupt) {
			// One bad record must not block every member of every other vault.
			log.Printf("shared vault list skips a record: %v", err)
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
		ownerID: {Role: RoleOwner, State: StateActive, SealedKey: sealedKey, SealedBy: ownerID, SealedByFingerprint: fingerprint, KeyFingerprint: fingerprint, KeyEpoch: 1, AddedAt: at, AcceptedAt: &at},
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

// Invite adds an invited row sealed by sealedBy, who must be an active owner and whose
// current fingerprint is sealerFP.
func (s *Store) Invite(id, userID string, role Role, sealedKey, fingerprint, sealedBy, sealerFP string, now time.Time) error {
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
		v.Members[userID] = Member{Role: role, State: StateInvited, SealedKey: sealedKey, SealedBy: sealedBy, SealedByFingerprint: sealerFP, KeyFingerprint: fingerprint, KeyEpoch: v.KeyEpoch, AddedAt: now.UTC()}
		return nil
	})
}

// Reseal replaces a member's sealed key, e.g. after a user key rotation. A stale row
// (sealed to a retired user key) returns to active if it had been accepted, else invited.
// A suspended row stays suspended, but SuspendedFrom is refreshed to the state the fresh
// seal would land on, so unsuspending later resumes from the new seal rather than from
// whatever the row was suspended from before the reseal. sealedBy must be an active owner,
// or the member themselves on their own stale row, so a sole owner who replaced their user
// key can recover the vault. sealerFP is sealedBy's current fingerprint.
func (s *Store) Reseal(id, userID, sealedKey, fingerprint, sealedBy, sealerFP string) error {
	if err := ValidSealedKey(sealedKey); err != nil {
		return err
	}
	self := sealedBy != "" && sealedBy == userID
	actor := sealedBy
	if self {
		actor = "" // checked below, once the row's state is known
	}
	return s.update(id, actor, func(v *Vault) error {
		m, ok := v.Members[userID]
		if !ok {
			return ErrNotMember
		}
		if self && m.State != StateStale {
			if err := authorize(*v, sealedBy); err != nil {
				return err
			}
		}
		m.SealedKey, m.KeyFingerprint, m.SealedBy, m.SealedByFingerprint, m.KeyEpoch = sealedKey, fingerprint, sealedBy, sealerFP, v.KeyEpoch
		v.Members[userID] = landOn(m, freshState(m))
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
// anyone else must be an active owner. Every departure flags a pending rotation: the row
// is gone, but the copy of the vault key it held is not, and only Rotate retires that.
func (s *Store) Remove(id, actorID, userID string, now time.Time) error {
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
		reason := ReasonRemoved // an admin removal ("" != userID) is a removal too
		if actorID == userID {
			reason = ReasonLeft
			if m.State == StateInvited {
				reason = ReasonDeclined
			}
		}
		v.RotationPending = &Pending{Since: now.UTC(), UserID: userID, Reason: reason}
		return nil
	})
}

// Rotate re-keys a shared vault: it takes one sealed copy of the new key per member the
// caller could seal for, writes the re-encrypted vault through writeVault, bumps the epoch
// and leaves everyone else at the old epoch as stale. It is the only thing that stops a
// departed member's copy of the key from opening what the vault saves next, so it clears
// the pending flag a departure set.
//
// The caller must name their own row: a rotation that locked the last active owner out of
// their own vault would leave nobody who could invite, accept or re-seal. Each SealedFor
// needs a non-empty KeyFingerprint, which overwrites the row's, exactly as Reseal does;
// checking it against the member's current published key is the route's job, because only
// the route can read published keys. epoch must be the vault's current one.
//
// writeVault (nil to skip it) writes the re-encrypted vault and runs under the store lock,
// so it must never re-enter this store: it would deadlock on a lock it already holds.
// Nothing here is written unless it succeeds, so a refused vault write leaves the record,
// the sealed keys and the flag exactly as they were and the rotation can be retried.
func (s *Store) Rotate(id, actorID string, epoch int, sealed []SealedFor, writeVault func() error) (Vault, error) {
	var out Vault
	err := s.update(id, actorID, func(v *Vault) error {
		if activeOwners(*v) == 0 {
			return fmt.Errorf("%w: the vault has no owner", ErrState)
		}
		if v.KeyEpoch != epoch {
			return fmt.Errorf("%w: at epoch %d", ErrEpoch, v.KeyEpoch)
		}
		named := map[string]bool{}
		for _, sf := range sealed {
			if _, ok := v.Members[sf.UserID]; !ok {
				return fmt.Errorf("%w: %s is not a member", ErrShape, sf.UserID)
			}
			if err := ValidSealedKey(sf.SealedKey); err != nil {
				return err
			}
			if sf.KeyFingerprint == "" {
				return fmt.Errorf("%w: %s has no keyFingerprint", ErrShape, sf.UserID)
			}
			named[sf.UserID] = true
		}
		if !named[actorID] {
			return fmt.Errorf("%w: a rotation must seal the new key for the caller's own row", ErrShape)
		}
		if postRotationOwners(*v, named) == 0 {
			return ErrLastOwner
		}
		if writeVault != nil {
			if err := writeVault(); err != nil {
				return err
			}
		}
		actorFP := v.Members[actorID].KeyFingerprint
		next := v.KeyEpoch + 1
		for _, sf := range sealed {
			m := v.Members[sf.UserID]
			m.SealedKey, m.KeyFingerprint = sf.SealedKey, sf.KeyFingerprint
			m.SealedBy, m.SealedByFingerprint = actorID, actorFP
			m.KeyEpoch = next
			// A fresh seal lands where a Reseal would: a member left behind by an earlier
			// rotation, or stale from a user key replacement, comes back.
			v.Members[sf.UserID] = landOn(m, freshState(m))
		}
		for uid, m := range v.Members {
			if !named[uid] {
				v.Members[uid] = landOn(m, StateStale)
			}
		}
		v.KeyEpoch = next
		v.RotationPending = nil
		out = *v
		return nil
	})
	if err != nil {
		return Vault{}, err
	}
	return out, nil
}

// postRotationOwners counts the active owners a rotation sealing for named would leave:
// every unnamed row goes stale, and a named row lands on freshState.
func postRotationOwners(v Vault, named map[string]bool) int {
	n := 0
	for uid, m := range v.Members {
		if named[uid] && m.Role == RoleOwner && m.State != StateSuspended && freshState(m) == StateActive {
			n++
		}
	}
	return n
}

// WithWriter runs fn, the vault write, under the store lock once userID's row is an active
// owner or editor and the vault is still at epoch, so a removal, a demotion or a rotation
// cannot land between the route's check and the write: a write prepared under a retired key
// would otherwise land as ciphertext no remaining member can open. fn takes vault.mu: lock
// order shared.mu then vault.mu.
func (s *Store) WithWriter(id, userID string, epoch int, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.loadLocked(id)
	if err != nil {
		return err
	}
	m, ok := v.Members[userID]
	if !ok {
		return ErrNotMember
	}
	if m.State != StateActive || (m.Role != RoleOwner && m.Role != RoleEditor) {
		return ErrForbidden
	}
	if v.KeyEpoch != epoch {
		return fmt.Errorf("%w: at epoch %d", ErrEpoch, v.KeyEpoch)
	}
	return fn()
}

// Delete writes deleted/<id>/record.json, removes the live record, then moves the vault
// directory there. A crash after the live record is gone leaves data nobody can reach;
// NewStore's reconcileDeleted finishes the move. actorID "" is an admin; anyone else must
// be an active owner.
func (s *Store) Delete(id, actorID string, now time.Time) error {
	if s.moveVault == nil {
		return errors.New("shared store opened without a vault mover")
	}
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
	if err := os.Remove(s.path(id)); err != nil {
		return err
	}
	return s.moveVault(id, filepath.Join(dst, "vault"))
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
		// Active and invited both need a re-seal before the key is usable.
		v.Members[userID] = landOn(m, StateStale)
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
