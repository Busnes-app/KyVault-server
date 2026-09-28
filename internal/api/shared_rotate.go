package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"sort"

	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

// Part limits for a rotation body: the re-encrypted vault, and the JSON holding one sealed
// copy of the new key per member (100 members at ~1.6 KiB of base64 each). Variables, not
// constants, so the refusal tests need not build a 50 MiB request.
var (
	rotateKdbxLimit int64 = 50 << 20
	rotateKeysLimit int64 = 1 << 20
)

// errRotateVersion refuses a rotation whose If-Match is not the vault's current version.
// It is checked inside the commit, before the write, so the re-encrypted bytes are never
// preserved as a conflict file that nobody left in the vault could open.
var errRotateVersion = errors.New("the shared vault changed since this rotation was prepared")

type rotateKeys struct {
	Epoch  int                `json:"epoch"`
	Sealed []shared.SealedFor `json:"sealed"`
}

// POST /api/shared/{id}/rotate. The re-encrypted vault and one sealed copy of the new key
// per remaining member commit together: split them and the vault's contents would be under
// a key its members do not hold. Active owners only, and a fresh sign-in, because this is
// the action that locks a departed member out and it destroys the vault's history.
func (s *Server) handleSharedRotate(w http.ResponseWriter, r *http.Request, u users.User) {
	if !s.sharedCSRF(w, r) {
		return
	}
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can rotate a shared vault key", http.StatusForbidden)
		return
	}
	if !s.requireFresh(w, c.session) {
		return
	}
	kdbx, keys, ok := readRotateBody(w, r)
	if !ok {
		return
	}
	// The store checks each sealed copy's shape and membership; only the route can compare
	// the fingerprint with the member's current published key, as invite and re-seal do.
	for _, sf := range keys.Sealed {
		if fp, has := s.currentFingerprint(sf.UserID); !has || fp != sf.KeyFingerprint {
			http.Error(w, "keyFingerprint does not match that user's current key", http.StatusBadRequest)
			return
		}
	}

	key := shared.StoreKey(c.vault.ID)
	want := ifMatchVersion(r)
	var meta vault.Metadata
	// Rotate validates under the membership lock, runs this write, and only then commits
	// the record: lock order shared.mu then vault.mu, and any refusal writes nothing. No
	// other shared write can land between the version check and the save.
	next, err := s.shared.Rotate(c.vault.ID, u.ID, keys.Epoch, keys.Sealed, func() error {
		current, err := s.vault.GetMetadata(key)
		if err != nil {
			return err
		}
		if current.Version != want {
			return fmt.Errorf("%w: it is at version %d", errRotateVersion, current.Version)
		}
		// An ordinary save, and deliberately not the epoch mark: marking it here would
		// leave a crash between this write and the record commit with new ciphertext, the
		// old sealed keys and no rollback — a vault nobody can open. MarkKeyEpoch runs
		// below instead, once every member holds the new key.
		meta, err = s.vault.SaveRekeyed(key, want, kdbx, c.session.DeviceID)
		return err
	})
	var conflict *vault.ConflictError
	switch {
	case errors.Is(err, vault.ErrArchive):
		// The re-key refused rather than leave the vault with no way back from a crash, so
		// nothing changed. It is the host's disk, not the owner's request: say which.
		log.Printf("shared vault %s: rotation refused, %v", c.vault.ID, err)
		http.Error(w, "the vault's current version could not be archived, so the rotation was refused and nothing was changed; this is a problem with the server's storage", http.StatusServiceUnavailable)
		return
	case errors.Is(err, shared.ErrEpoch), errors.Is(err, errRotateVersion):
		http.Error(w, "the shared vault changed; reload it and rotate again", http.StatusConflict)
		return
	case errors.As(err, &conflict):
		// Unreachable: the version is compared under the same lock that admits the write.
		// Kept so the invariant defends itself rather than resting on that argument.
		writeJSON(w, http.StatusConflict, conflict)
		return
	case err != nil:
		if !sharedRefused(w, err) {
			sharedErr(w, err)
		}
		return
	}
	// The record is committed, so every remaining member holds the new key and the
	// pre-rotation snapshot is nobody's way back in any more: mark the epoch, which refuses
	// it for rollback even if the clear below fails. Both run after the commit, and neither
	// failing is a failed rotation — the vault is correctly re-keyed — so both are logged,
	// audited and reported instead.
	epochMarked := true
	// meta.Version, not whatever the vault is on now: a member this rotation re-sealed may
	// already have saved over it, and that save is under the new key and must stay restorable.
	if err := s.vault.MarkKeyEpoch(key, meta.Version); err != nil {
		epochMarked = false
		log.Printf("shared vault %s: marking the key epoch after a rotation: %v", c.vault.ID, err)
		s.record(r, "shared.hook_failed", u.ID, c.session.DeviceID, clientIP(r),
			c.vault.ID+": the new key epoch was not marked: "+err.Error())
	}
	// Snapshots and preserved conflicts are ciphertext under the retired key: unreadable to
	// everyone still in the vault, and readable by the member this rotation locked out.
	cleared := true
	if err := s.vault.ClearHistory(key); err != nil {
		cleared = false
		log.Printf("shared vault %s: clearing history after a rotation: %v", c.vault.ID, err)
		s.record(r, "shared.hook_failed", u.ID, c.session.DeviceID, clientIP(r),
			c.vault.ID+": history under the retired key was not cleared: "+err.Error())
	}

	left := []string{}
	for uid, m := range next.Members {
		if m.KeyEpoch != next.KeyEpoch {
			left = append(left, uid)
		}
	}
	sort.Strings(left)
	s.record(r, "shared.key_rotated", u.ID, c.session.DeviceID, clientIP(r),
		fmt.Sprintf("%s: rotated to epoch %d, sealed to %d members, %d left behind", c.vault.ID, next.KeyEpoch, len(keys.Sealed), len(left)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metadata": meta, "keyEpoch": next.KeyEpoch,
		"leftBehind": left, "historyCleared": cleared, "epochMarked": epochMarked})
}

// readRotateBody reads the two parts as a stream, in order, each bounded on its own and
// the whole body bounded too.
func readRotateBody(w http.ResponseWriter, r *http.Request) ([]byte, rotateKeys, bool) {
	var keys rotateKeys
	r.Body = http.MaxBytesReader(w, r.Body, rotateKdbxLimit+rotateKeysLimit)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "rotate needs a multipart/form-data body", http.StatusBadRequest)
		return nil, keys, false
	}
	kdbx, ok := rotatePart(w, mr, "kdbx", rotateKdbxLimit)
	if !ok {
		return nil, keys, false
	}
	raw, ok := rotatePart(w, mr, "keys", rotateKeysLimit)
	if !ok {
		return nil, keys, false
	}
	if len(kdbx) == 0 {
		http.Error(w, "empty vault payload", http.StatusBadRequest)
		return nil, keys, false
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		http.Error(w, "invalid keys part", http.StatusBadRequest)
		return nil, keys, false
	}
	if len(keys.Sealed) == 0 {
		http.Error(w, "a rotation must seal the new key for at least the caller", http.StatusBadRequest)
		return nil, keys, false
	}
	// Exactly two parts: a third would be something the route never reads and never checked.
	switch _, err := mr.NextPart(); {
	case errors.Is(err, io.EOF):
	case err == nil:
		http.Error(w, `rotate takes exactly two parts, "kdbx" then "keys"`, http.StatusBadRequest)
		return nil, keys, false
	default:
		rotateReadErr(w, err, "unreadable multipart body")
		return nil, keys, false
	}
	return kdbx, keys, true
}

// rotatePart reads the next part, which must be the one named want, and refuses anything
// over limit rather than truncating it: a truncated keys part would silently drop a
// member's copy of the new key.
func rotatePart(w http.ResponseWriter, mr *multipart.Reader, want string, limit int64) ([]byte, bool) {
	part, err := mr.NextPart()
	if err != nil {
		rotateReadErr(w, err, fmt.Sprintf("the %q part is missing or unreadable", want))
		return nil, false
	}
	defer part.Close()
	if part.FormName() != want {
		http.Error(w, fmt.Sprintf("expected the %q part, got %q", want, part.FormName()), http.StatusBadRequest)
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(part, limit+1))
	if err != nil {
		rotateReadErr(w, err, fmt.Sprintf("failed to read the %q part", want))
		return nil, false
	}
	if int64(len(data)) > limit {
		http.Error(w, fmt.Sprintf("the %q part is too large", want), http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return data, true
}

func rotateReadErr(w http.ResponseWriter, err error, msg string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "the rotation body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, msg, http.StatusBadRequest)
}
