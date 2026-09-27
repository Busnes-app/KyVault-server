package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

// PUT /api/vault/user-key. The record is the caller's own; If-Match names the vault version
// it was wrapped against so a tab holding a retired vault key cannot publish a seed
// nobody can open.
func (s *Server) handleUserKeyPut(w http.ResponseWriter, r *http.Request, u users.User) {
	var rec userkey.Record
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&rec); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	createOnly := r.Header.Get("If-None-Match") == "*"
	created, err := s.vault.SaveUserKey(u.ID, ifMatchVersion(r), rec, createOnly)
	switch {
	case errors.Is(err, userkey.ErrShape):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, vault.ErrConflict):
		http.Error(w, "The vault changed on the server since this key was wrapped. Reload the vault and try again.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "failed to save user key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fp, _ := rec.Fingerprint()
	action := "user_key.replaced"
	if created {
		action = "user_key.published"
	}
	s.record(r, action, u.ID, "", clientIP(r), fp)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": fp})
}

// GET /api/users/{id}/key. Any signed-in user or paired device may read a public key;
// trust comes from the reader's own pin, not from this server.
func (s *Server) handleUserKeyGet(w http.ResponseWriter, r *http.Request, _ users.User) {
	id := r.PathValue("id")
	if _, err := s.users.Get(id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	meta, err := s.vault.GetMetadata(id)
	if err != nil || meta.UserKey == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pub, err := meta.UserKey.Public(id)
	if err != nil {
		http.Error(w, "stored key is malformed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, pub)
}

// userKeyHeader reads X-User-Key on a rotation upload: base64 of the JSON record.
func userKeyHeader(r *http.Request) (*userkey.Record, error) {
	h := r.Header.Get("X-User-Key")
	if h == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return nil, userkey.ErrShape
	}
	var rec userkey.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, userkey.ErrShape
	}
	return &rec, rec.Validate()
}
