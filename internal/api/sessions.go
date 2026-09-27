package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/devices"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

// Sessions are written through to DATA_DIR/sessions.json so a restart or deploy does not
// end every browser session and every 90-day device pairing. The file holds the SHA-256
// of each token, never the token: reading the data directory yields nothing a request
// can present. The map is keyed the same way, so a lookup hashes the presented token.
//
// The file is not in the sealed capsule: a restored instance starts with no sessions,
// the same as before, and the logout fence in sso-logout.json still applies.
const sessionsFile = "sessions.json"

// sessionKey is the map key for a token: its SHA-256, hex encoded.
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) loadSessions() error {
	data, err := os.ReadFile(filepath.Join(s.dataDir, sessionsFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored map[string]Session
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	// The file may predate a revocation whose write failed (saveSessionsLocked). The
	// two revocations that matter most are reconciled here against records that are
	// durable on their own: a device session whose device is gone, and a session a
	// retained logout fences. Directory deactivation needs nothing: currentUser
	// refuses an inactive account whatever the file says.
	now := time.Now().UTC()
	for key, sess := range stored {
		if !now.Before(sess.ExpiresAt) || s.logouts.Fenced(sess.SSO, now) {
			continue
		}
		if sess.DeviceID != "" {
			if _, err := s.devices.Get(sess.DeviceID); err != nil {
				continue
			}
		}
		s.sessions[key] = sess
	}
	return nil
}

// errSessionsNotDurable is what a revocation returns when it holds in memory but not on
// disk: the caller withholds its acknowledgement, and the periodic flush retries.
var errSessionsNotDurable = errors.New("session record could not be written; the server will retry")

// saveSessionsLocked needs sessMu held. On failure the map stays as it is (the running
// process already honours it), sessionsDirty is set so the flush and Close retry, and
// the error goes back so a revocation is not acknowledged as durable.
func (s *Server) saveSessionsLocked() error {
	data, err := json.Marshal(s.sessions)
	if err == nil {
		path := filepath.Join(s.dataDir, sessionsFile)
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, data, 0600); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		log.Printf("SESSION WRITE FAILED (will retry): %v", err)
		s.sessionsDirty = true
		return errSessionsNotDurable
	}
	s.sessionsDirty = false
	return nil
}

// retrySessionSave writes the file again if a previous write failed.
func (s *Server) retrySessionSave() error {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if !s.sessionsDirty {
		return nil
	}
	return s.saveSessionsLocked()
}

// pruneSessionsLocked needs sessMu held and reports whether anything was removed.
func (s *Server) pruneSessionsLocked(now time.Time) bool {
	removed := false
	for key, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, key)
			removed = true
		}
	}
	return removed
}

// pruneSessions runs with the periodic audit flush, so an idle server sheds expired
// sessions too, not only one that is minting new ones.
func (s *Server) pruneSessions() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.pruneSessionsLocked(time.Now().UTC()) || s.sessionsDirty {
		_ = s.saveSessionsLocked()
	}
}

// sessionView is what the inventory shows a user about one of their sessions. It never
// carries the token or its hash.
type sessionView struct {
	ID              string     `json:"id"`
	Kind            string     `json:"kind"` // "browser" or "device"
	DeviceID        string     `json:"deviceId,omitempty"`
	DeviceName      string     `json:"deviceName,omitempty"`
	IP              string     `json:"ip,omitempty"`
	IssuedAt        time.Time  `json:"issuedAt"`
	AuthenticatedAt *time.Time `json:"authenticatedAt,omitempty"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	Current         bool       `json:"current"`
}

func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request, u users.User) {
	current, _ := s.currentSession(r)
	now := time.Now().UTC()
	s.sessMu.RLock()
	views := make([]sessionView, 0)
	for _, sess := range s.sessions {
		if sess.UserID != u.ID || !now.Before(sess.ExpiresAt) {
			continue
		}
		v := sessionView{ID: sess.ID, Kind: "browser", IP: sess.IP, IssuedAt: sess.IssuedAt, ExpiresAt: sess.ExpiresAt, Current: sess.ID == current.ID}
		if !sess.AuthenticatedAt.IsZero() {
			at := sess.AuthenticatedAt
			v.AuthenticatedAt = &at
		}
		if sess.DeviceID != "" {
			v.Kind = "device"
			v.DeviceID = sess.DeviceID
			if dev, err := s.devices.Get(sess.DeviceID); err == nil {
				v.DeviceName = dev.Name
			}
		}
		views = append(views, v)
	}
	s.sessMu.RUnlock()
	sort.Slice(views, func(i, j int) bool { return views[i].IssuedAt.After(views[j].IssuedAt) })
	writeJSON(w, http.StatusOK, views)
}

// handleSessionEnd ends one of the caller's other sessions. A device session ends with
// its device, exactly as Revoke on the Devices list would, so the extension re-pairs
// rather than holding a device record with no way to use it. The current session is
// refused: logout is the way to end it.
func (s *Server) handleSessionEnd(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	current, _ := s.currentSession(r)
	if id == "" || id == current.ID {
		http.Error(w, "use logout to end the current session", http.StatusBadRequest)
		return
	}
	s.sessMu.Lock()
	found := false
	var dev devices.Device
	for key, sess := range s.sessions {
		if sess.ID != id || sess.UserID != u.ID {
			continue
		}
		found = true
		delete(s.sessions, key)
		if sess.DeviceID != "" {
			if d, err := s.devices.Get(sess.DeviceID); err == nil {
				dev = d
			}
		}
		break
	}
	var saveErr error
	if dev.ID != "" {
		s.revokeDeviceLocked(dev)
	}
	if found {
		saveErr = s.saveSessionsLocked()
	}
	s.sessMu.Unlock()
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if saveErr != nil {
		http.Error(w, saveErr.Error(), http.StatusInternalServerError)
		return
	}
	if dev.ID != "" {
		s.record(r, "device.revoked", u.ID, dev.ID, clientIP(r), "revoked device "+dev.Name+": session ended from inventory")
	} else {
		s.record(r, "auth.session_ended", u.ID, "", clientIP(r), "ended session "+id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
