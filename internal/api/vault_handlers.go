package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

// vaultTarget names which store entry a data handler acts on and who is acting.
type vaultTarget struct {
	key       string     // vault.Store key: u.ID or shared.StoreKey(id)
	user      users.User // acting user, for audit
	deviceID  string     // session DeviceID, for audit and conflict filenames
	shared    bool       // true → envelopes/rotation headers refused/ignored, audit prefix "shared."
	filename  string     // Content-Disposition base name
	fileParam string     // PathValue name of a history/conflict id: "id" personal, "hid"/"cid" shared
}

// auditAction maps a personal audit action to its shared equivalent.
func (t vaultTarget) auditAction(personal string) string {
	if !t.shared {
		return personal
	}
	switch personal {
	case "vault.download":
		return "shared.downloaded"
	case "vault.restored_snapshot":
		return "shared.rolled_back"
	case "vault.conflict_download":
		return "shared.conflict_downloaded"
	}
	return "shared." + strings.TrimPrefix(personal, "vault.")
}

// detail prefixes an audit detail with the shared vault id when acting on a shared vault.
func (t vaultTarget) detail(msg string) string {
	if !t.shared {
		return msg
	}
	return t.key + ": " + msg
}

// personalTarget builds the vaultTarget for a user's own vault.
func (s *Server) personalTarget(r *http.Request, u users.User) vaultTarget {
	sess, _ := s.currentSession(r)
	return vaultTarget{
		key:       u.ID,
		user:      u,
		deviceID:  sess.DeviceID,
		filename:  u.Username + "-vault.kdbx",
		fileParam: "id",
	}
}

func (s *Server) handleVaultMetadata(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultMetadata(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultMetadata(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	meta, err := s.vault.GetMetadata(t.key)
	if err != nil {
		http.Error(w, "failed to get vault metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleVaultDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultDownload(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultDownload(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	rc, meta, err := s.vault.OpenVault(t.key)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			http.Error(w, "vault does not exist yet", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to open vault: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/x-keepass2")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", t.filename))
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", meta.Version))
	w.Header().Set("X-Vault-Version", strconv.FormatInt(meta.Version, 10))
	w.Header().Set("X-Vault-Checksum", meta.Checksum)

	_, _ = io.Copy(w, rc)
	s.record(r, t.auditAction("vault.download"), t.user.ID, "", clientIP(r), t.detail(fmt.Sprintf("downloaded vault v%d", meta.Version)))
}

type VaultUploadRequest struct {
	ExpectedVersion  int64  `json:"expectedVersion"`
	KdbxBase64       string `json:"kdbxBase64"`
	PasswordEnvelope string `json:"passwordEnvelope,omitempty"`
	RecoveryEnvelope string `json:"recoveryEnvelope,omitempty"`
}

func (s *Server) handleVaultUpload(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultUpload(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultUpload(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 50<<20))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "vault upload exceeds the 50 MiB limit", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "failed to read upload body", http.StatusBadRequest)
		}
		return
	}
	if t.shared && r.Header.Get("X-Vault-Key-Rotated") == "1" {
		http.Error(w, "shared vaults do not rotate through this route", http.StatusBadRequest)
		return
	}
	// Support both the existing JSON payload and raw binary with headers.
	var expectedVersion int64
	var kdbxData []byte
	var pwEnv string
	var recEnv string
	// The device that saved is what the session proves, never what the body or a header
	// claims: the id is audited and becomes part of a conflict filename.
	devID := t.deviceID

	expectedVersion = ifMatchVersion(r)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req VaultUploadRequest
		if err := json.Unmarshal(data, &req); err != nil {
			http.Error(w, "invalid json payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.ExpectedVersion != 0 {
			expectedVersion = req.ExpectedVersion
		}
		pwEnv = req.PasswordEnvelope
		recEnv = req.RecoveryEnvelope
		decoded, err := base64.StdEncoding.DecodeString(req.KdbxBase64)
		if err != nil || len(decoded) == 0 {
			http.Error(w, "kdbxBase64 must be non-empty standard base64", http.StatusBadRequest)
			return
		}
		kdbxData = decoded
	} else {
		// Raw binary stream
		pwEnv = r.Header.Get("X-Password-Envelope")
		recEnv = r.Header.Get("X-Recovery-Envelope")
		kdbxData = data
	}

	if len(kdbxData) == 0 {
		http.Error(w, "empty vault payload", http.StatusBadRequest)
		return
	}

	if t.shared {
		pwEnv = ""
		recEnv = ""
	}

	rotated := r.Header.Get("X-Vault-Key-Rotated") == "1"
	var meta vault.Metadata
	if rotated {
		var userKey *userkey.Record
		userKey, err = userKeyHeader(r)
		if err != nil {
			http.Error(w, "X-User-Key: "+err.Error(), http.StatusBadRequest)
			return
		}
		meta, err = s.vault.RotateVault(t.key, expectedVersion, kdbxData, pwEnv, recEnv, devID, userKey)
	} else {
		meta, err = s.vault.SaveVault(t.key, expectedVersion, kdbxData, pwEnv, recEnv, devID)
	}
	if errors.Is(err, vault.ErrRotationEnvelopes) || errors.Is(err, vault.ErrRotationUserKey) || errors.Is(err, userkey.ErrShape) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		var confErr *vault.ConflictError
		if errors.As(err, &confErr) {
			s.record(r, t.auditAction("vault.conflict_rejected"), t.user.ID, devID, clientIP(r), t.detail(confErr.Error()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(confErr)
			return
		}
		http.Error(w, "failed to save vault: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, t.auditAction("vault.saved"), t.user.ID, devID, clientIP(r), t.detail(fmt.Sprintf("saved vault v%d", meta.Version)))
	if rotated {
		s.record(r, "vault.key_rotated", t.user.ID, devID, clientIP(r), fmt.Sprintf("rotated vault key at v%d", meta.Version))
		// Every device holds the retired key, and a pending pairing code could mint a
		// fresh 90-day session for one; end them all here, not in the browser's loop.
		s.revokeAllDevices(r, t.user.ID, "key_rotated")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"metadata": meta,
	})
}

// ifMatchVersion reads the vault version a write was based on; absent means 0, a new vault.
func ifMatchVersion(r *http.Request) int64 {
	v, _ := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), "\""), 10, 64)
	return v
}

func (s *Server) handleVaultEnvelopes(w http.ResponseWriter, r *http.Request, u users.User) {
	var req struct {
		PasswordEnvelope string                          `json:"passwordEnvelope"`
		RecoveryEnvelope string                          `json:"recoveryEnvelope"`
		DeviceEnvelopes  map[string]vault.DeviceEnvelope `json:"deviceEnvelopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	err := s.vault.SaveEnvelopes(u.ID, ifMatchVersion(r), req.PasswordEnvelope, req.RecoveryEnvelope, req.DeviceEnvelopes)
	if errors.Is(err, vault.ErrConflict) {
		http.Error(w, "The vault changed on the server since this key was checked. Reload the vault and try again.", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "failed to save envelopes: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "vault.envelopes_updated", u.ID, "", clientIP(r), "updated key envelopes")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleVaultHistory(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultHistory(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultHistory(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	history, err := s.vault.ListHistory(t.key)
	if err != nil {
		http.Error(w, "failed to list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func (s *Server) handleVaultHistoryRestore(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultHistoryRestore(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultHistoryRestore(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	id := r.PathValue(t.fileParam)
	if id == "" {
		http.Error(w, "missing snapshot id", http.StatusBadRequest)
		return
	}

	meta, err := s.vault.RestoreHistory(t.key, id)
	if errors.Is(err, vault.ErrStaleKey) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "This snapshot was saved under a previous vault key. The current key cannot open it, so it cannot be rolled back to."})
		return
	}
	if errors.Is(err, vault.ErrNotFound) {
		http.Error(w, "snapshot not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "failed to restore history: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, t.auditAction("vault.restored_snapshot"), t.user.ID, "", clientIP(r), t.detail(fmt.Sprintf("restored snapshot %s to v%d", id, meta.Version)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"metadata": meta,
	})
}

func (s *Server) handleVaultHistoryDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultHistoryDownload(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultHistoryDownload(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	id := r.PathValue(t.fileParam)
	rc, err := s.vault.OpenHistory(t.key, id)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			http.Error(w, "snapshot not found", http.StatusNotFound)
		} else {
			http.Error(w, "failed to open snapshot", http.StatusInternalServerError)
		}
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/x-keepass2")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, rc)
	s.record(r, t.auditAction("vault.snapshot_downloaded"), t.user.ID, "", clientIP(r), t.detail("downloaded snapshot "+id))
}

func (s *Server) handleVaultConflicts(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultConflicts(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultConflicts(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	conflicts, err := s.vault.ListConflicts(t.key)
	if err != nil {
		http.Error(w, "failed to list conflicts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, conflicts)
}

func (s *Server) handleVaultConflictDiscard(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultConflictDiscard(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultConflictDiscard(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	id := r.PathValue(t.fileParam)
	if id == "" {
		http.Error(w, "missing conflict id", http.StatusBadRequest)
		return
	}

	if err := s.vault.DiscardConflict(t.key, id); err != nil {
		http.Error(w, "failed to discard conflict: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, t.auditAction("vault.conflict_discarded"), t.user.ID, "", clientIP(r), t.detail("discarded conflict "+id))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleVaultConflictDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	s.vaultConflictDownload(w, r, s.personalTarget(r, u))
}

func (s *Server) vaultConflictDownload(w http.ResponseWriter, r *http.Request, t vaultTarget) {
	id := r.PathValue(t.fileParam)
	rc, err := s.vault.OpenConflict(t.key, id)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			http.Error(w, "conflict not found", http.StatusNotFound)
		} else {
			http.Error(w, "failed to open conflict", http.StatusInternalServerError)
		}
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/x-keepass2")
	w.Header().Set("Content-Disposition", `attachment; filename="conflict.kdbx"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, rc)
	s.record(r, t.auditAction("vault.conflict_download"), t.user.ID, "", clientIP(r), t.detail("downloaded preserved conflict "+id))
}
