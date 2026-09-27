package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

const (
	lookupMaxMisses = 20
	lookupLockout   = 15 * time.Minute
)

// GET /api/users/lookup?username=. Resolves a username to the id and fingerprint the
// invite flow needs. Unknown, inactive and key-less users all answer 404 so the route
// only confirms "an active user with that name has a key"; misses are rate limited per
// source like pairing codes.
func (s *Server) handleUserLookup(w http.ResponseWriter, r *http.Request, u users.User) {
	src := s.sourceKey(r)
	if !s.lookupLimit.allow(src) {
		s.record(r, "user.lookup_limited", u.ID, "", clientIP(r), "")
		http.Error(w, "too many lookups; try again later", http.StatusTooManyRequests)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("username"))
	s.record(r, "user.lookup", u.ID, "", clientIP(r), name)
	target, err := s.users.GetByUsername(name)
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if err != nil || name == "" || !target.Active {
		s.lookupLimit.fail(src)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	meta, err := s.vault.GetMetadata(target.ID)
	if err != nil || meta.UserKey == nil {
		s.lookupLimit.fail(src)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pub, err := meta.UserKey.Public(target.ID)
	if err != nil {
		http.Error(w, "stored key is malformed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"userId": target.ID, "username": target.Username, "fingerprint": pub.Fingerprint})
}
