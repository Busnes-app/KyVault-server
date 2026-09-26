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

	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

func (s *Server) handleVaultMetadata(w http.ResponseWriter, r *http.Request, u users.User) {
	meta, err := s.vault.GetMetadata(u.ID)
	if err != nil {
		http.Error(w, "failed to get vault metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleVaultDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	rc, meta, err := s.vault.OpenVault(u.ID)
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
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-vault.kdbx\"", u.Username))
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", meta.Version))
	w.Header().Set("X-Vault-Version", strconv.FormatInt(meta.Version, 10))
	w.Header().Set("X-Vault-Checksum", meta.Checksum)

	_, _ = io.Copy(w, rc)
	s.record(r, "vault.download", u.ID, "", clientIP(r), fmt.Sprintf("downloaded vault v%d", meta.Version))
}

type VaultUploadRequest struct {
	ExpectedVersion  int64  `json:"expectedVersion"`
	KdbxBase64       string `json:"kdbxBase64"`
	PasswordEnvelope string `json:"passwordEnvelope,omitempty"`
	RecoveryEnvelope string `json:"recoveryEnvelope,omitempty"`
	DeviceID         string `json:"deviceId,omitempty"`
}

func (s *Server) handleVaultUpload(w http.ResponseWriter, r *http.Request, u users.User) {
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
	// Support both the existing JSON payload and raw binary with headers.
	var expectedVersion int64
	var kdbxData []byte
	var pwEnv string
	var recEnv string
	var devID string

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
		devID = req.DeviceID
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
		devID = r.Header.Get("X-Device-ID")
		kdbxData = data
	}

	if len(kdbxData) == 0 {
		http.Error(w, "empty vault payload", http.StatusBadRequest)
		return
	}

	save := s.vault.SaveVault
	rotated := r.Header.Get("X-Vault-Key-Rotated") == "1"
	if rotated {
		save = s.vault.RotateVault
	}
	meta, err := save(u.ID, expectedVersion, kdbxData, pwEnv, recEnv, devID)
	if errors.Is(err, vault.ErrRotationEnvelopes) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		var confErr *vault.ConflictError
		if errors.As(err, &confErr) {
			s.record(r, "vault.conflict_rejected", u.ID, devID, clientIP(r), confErr.Error())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(confErr)
			return
		}
		http.Error(w, "failed to save vault: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "vault.saved", u.ID, devID, clientIP(r), fmt.Sprintf("saved vault v%d", meta.Version))
	if rotated {
		s.record(r, "vault.key_rotated", u.ID, devID, clientIP(r), fmt.Sprintf("rotated vault key at v%d", meta.Version))
		// Every device holds the retired key; end them here, not in the browser's loop.
		for _, dev := range s.devices.ListUserDevices(u.ID) {
			s.revokeDevice(r, dev, "revoked device "+dev.Name+": key_rotated")
		}
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
	history, err := s.vault.ListHistory(u.ID)
	if err != nil {
		http.Error(w, "failed to list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func (s *Server) handleVaultHistoryRestore(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing snapshot id", http.StatusBadRequest)
		return
	}

	meta, err := s.vault.RestoreHistory(u.ID, id)
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

	s.record(r, "vault.restored_snapshot", u.ID, "", clientIP(r), fmt.Sprintf("restored snapshot %s to v%d", id, meta.Version))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"metadata": meta,
	})
}

func (s *Server) handleVaultHistoryDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	rc, err := s.vault.OpenHistory(u.ID, id)
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
	s.record(r, "vault.snapshot_downloaded", u.ID, "", clientIP(r), "downloaded snapshot "+id)
}

func (s *Server) handleVaultConflicts(w http.ResponseWriter, r *http.Request, u users.User) {
	conflicts, err := s.vault.ListConflicts(u.ID)
	if err != nil {
		http.Error(w, "failed to list conflicts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, conflicts)
}

func (s *Server) handleVaultConflictDiscard(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing conflict id", http.StatusBadRequest)
		return
	}

	if err := s.vault.DiscardConflict(u.ID, id); err != nil {
		http.Error(w, "failed to discard conflict: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "vault.conflict_discarded", u.ID, "", clientIP(r), "discarded conflict "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleVaultConflictDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	rc, err := s.vault.OpenConflict(u.ID, id)
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
	s.record(r, "vault.conflict_download", u.ID, "", clientIP(r), "downloaded preserved conflict "+id)
}
