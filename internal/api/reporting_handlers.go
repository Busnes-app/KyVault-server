package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/reporting"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

var errReportConflict = errors.New("report settings or vault changed; refresh and share again")
var errReportShape = errors.New("invalid report request")

// All reporting routes are browser-only, including reads. CSRF is explicit on writes.
func (s *Server) reportBrowser(next func(http.ResponseWriter, *http.Request, users.User)) func(http.ResponseWriter, *http.Request, users.User) {
	return func(w http.ResponseWriter, r *http.Request, u users.User) {
		sess, ok := s.currentSession(r)
		if !ok || sess.DeviceID != "" {
			s.recordAnonymousRejection(r, "reporting.rejected", clientIP(r), "browser session required")
			http.Error(w, "this action needs a browser session", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && !s.validCSRF(r) {
			s.recordAnonymousRejection(r, "reporting.rejected", clientIP(r), "invalid CSRF")
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		next(w, r, u)
	}
}
func (s *Server) reportRecipient(id string) (reporting.Config, error) {
	u, err := s.users.Get(id)
	if err != nil || !u.Active || u.Role != users.RoleAdmin {
		return reporting.Config{}, errReportShape
	}
	m, err := s.vault.GetMetadata(id)
	if err != nil {
		return reporting.Config{}, err
	}
	if m.UserKey == nil {
		return reporting.Config{}, errReportShape
	}
	if err = m.UserKey.Validate(); err != nil {
		return reporting.Config{}, err
	}
	b, _ := base64.StdEncoding.DecodeString(m.UserKey.PublicKey)
	digest := sha256.Sum256(b)
	return reporting.Config{Enabled: true, RecipientID: id, RecipientName: u.Username, PublicKey: m.UserKey.PublicKey, KeyDigest: hex.EncodeToString(digest[:])}, nil
}
func (s *Server) reportAccess(fn func(*reporting.State) (bool, error)) error {
	return s.reporting.Access(func(st *reporting.State) (bool, error) {
		dirty := false
		if st.Config.Enabled {
			c, err := s.reportRecipient(st.Config.RecipientID)
			if err != nil && !errors.Is(err, errReportShape) {
				return false, err
			}
			if errors.Is(err, errReportShape) || c.PublicKey != st.Config.PublicKey {
				st.Configure(reporting.Config{})
				dirty = true
			}
		}
		changed, err := fn(st)
		return dirty || changed, err
	})
}
func reportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errReportShape):
		http.Error(w, err.Error(), 400)
	case errors.Is(err, errReportConflict):
		http.Error(w, err.Error(), 409)
	default:
		http.Error(w, "report storage unavailable", 503)
	}
}

// Strict object decoding rejects duplicate keys as well as unknown/trailing fields.
func reportBody(w http.ResponseWriter, r *http.Request, out any) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		return errReportShape
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errReportShape
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return errReportShape
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return errReportShape
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return errReportShape
		}
	}
	if _, err = d.Token(); err != nil {
		return errReportShape
	}
	if _, err = d.Token(); err != io.EOF {
		return errReportShape
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errReportShape
	}
	return nil
}
func hexID(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s *Server) handleReportConfig(w http.ResponseWriter, r *http.Request, u users.User) {
	var c reporting.Config
	err := s.reportAccess(func(st *reporting.State) (bool, error) { c = st.Config; return false, nil })
	if err != nil {
		reportError(w, err)
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) handleReportConfigure(w http.ResponseWriter, r *http.Request, u users.User) {
	var body struct {
		Generation  string `json:"generation"`
		Enabled     bool   `json:"enabled"`
		RecipientID string `json:"recipientId"`
		KeyDigest   string `json:"keyDigest"`
	}
	if err := reportBody(w, r, &body); err != nil {
		reportError(w, err)
		return
	}
	var c reporting.Config
	var refused error
	err := s.reportAccess(func(st *reporting.State) (bool, error) {
		if body.Generation != st.Config.Generation {
			refused = errReportConflict
			return false, nil
		}
		next := reporting.Config{}
		if body.Enabled {
			var err error
			next, err = s.reportRecipient(body.RecipientID)
			if err != nil || next.KeyDigest != body.KeyDigest {
				refused = err
				if refused == nil {
					refused = errReportShape
				}
				return false, nil
			}
		}
		if next.Enabled != st.Config.Enabled || next.PublicKey != st.Config.PublicKey || next.RecipientID != st.Config.RecipientID {
			st.Configure(next)
			c = st.Config
			return true, nil
		}
		c = st.Config
		return false, nil
	})
	if err == nil {
		err = refused
	}
	if err != nil {
		reportError(w, err)
		return
	}
	s.record(r, "reporting.config_changed", u.ID, "", clientIP(r), c.Generation)
	writeJSON(w, 200, c)
}
func (s *Server) handleReportPut(w http.ResponseWriter, r *http.Request, u users.User) {
	var rec reporting.Record
	if err := reportBody(w, r, &rec); err != nil {
		reportError(w, err)
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(rec.Sealed)
	if err != nil || len(raw) != reporting.SealedBytes || base64.StdEncoding.EncodeToString(raw) != rec.Sealed || !hexID(rec.ReportID, 32) || rec.SourceID != u.ID || len(u.ID) > 128 || rec.Version < 1 || rec.Version > 9007199254740991 || !rec.ReceivedAt.IsZero() {
		reportError(w, errReportShape)
		return
	}
	if rec.Version != ifMatchVersion(r) {
		reportError(w, errReportConflict)
		return
	}
	var refused error
	err = s.reportAccess(func(st *reporting.State) (bool, error) {
		c := st.Config
		if !c.Enabled || rec.InstanceID != c.InstanceID || rec.Generation != c.Generation || rec.RecipientID != c.RecipientID || rec.KeyDigest != c.KeyDigest {
			refused = errReportConflict
			return false, nil
		}
		m, err := s.vault.GetMetadata(u.ID)
		if err != nil || m.Version != rec.Version {
			refused = errReportConflict
			return false, nil
		}
		if old, ok := st.Records[u.ID]; ok && old.ReportID == rec.ReportID {
			if old.Sealed != rec.Sealed || old.Version != rec.Version {
				refused = errReportConflict
			}
			return false, nil
		}
		rec.ReceivedAt = time.Now().UTC()
		st.Records[u.ID] = rec
		return true, nil
	})
	if err == nil {
		err = refused
	}
	if err != nil {
		reportError(w, err)
		return
	}
	s.record(r, "reporting.submitted", u.ID, "", clientIP(r), rec.ReportID)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handleReportDelete(w http.ResponseWriter, r *http.Request, u users.User) {
	err := s.reportAccess(func(st *reporting.State) (bool, error) {
		_, ok := st.Records[u.ID]
		delete(st.Records, u.ID)
		return ok, nil
	})
	if err != nil {
		reportError(w, err)
		return
	}
	s.record(r, "reporting.withdrawn", u.ID, "", clientIP(r), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

type reportRow struct {
	UserID   string            `json:"userId"`
	Username string            `json:"username"`
	Status   string            `json:"status"`
	Record   *reporting.Record `json:"record,omitempty"`
}

func (s *Server) handleReportList(w http.ResponseWriter, r *http.Request, u users.User) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			reportError(w, errReportShape)
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("after")
	if len(cursor) > 128 {
		reportError(w, errReportShape)
		return
	}
	var rows = []reportRow{}
	var cfg reporting.Config
	next := ""
	err := s.reportAccess(func(st *reporting.State) (bool, error) {
		cfg = st.Config
		list := s.users.List()
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		dirty := false
		active := map[string]bool{}
		for _, source := range list {
			if source.Active {
				active[source.ID] = true
			}
		}
		for id := range st.Records {
			if !active[id] {
				delete(st.Records, id)
				dirty = true
			}
		}
		for _, source := range list {
			if !source.Active || source.ID <= cursor {
				continue
			}
			if len(rows) == limit {
				next = rows[len(rows)-1].UserID
				break
			}
			row := reportRow{UserID: source.ID, Username: source.Username, Status: "not-submitted"}
			m, err := s.vault.GetMetadata(source.ID)
			if err != nil || m.Version == 0 {
				row.Status = "no-vault"
				if err != nil {
					row.Status = "unavailable"
				}
			}
			if rec, ok := st.Records[source.ID]; ok && cfg.Enabled {
				row.Status = "current"
				if err != nil || m.Version != rec.Version {
					row.Status = "stale-version"
				} else if time.Since(rec.ReceivedAt) > 24*time.Hour {
					row.Status = "stale-time"
				}
				if u.ID != cfg.RecipientID || row.Status != "current" {
					rec.Sealed = ""
				}
				row.Record = &rec
			}
			rows = append(rows, row)
		}
		return dirty, nil
	})
	if err != nil {
		reportError(w, err)
		return
	}
	s.record(r, "reporting.viewed", u.ID, "", clientIP(r), strings.TrimSpace(cfg.Generation))
	writeJSON(w, 200, map[string]any{"config": cfg, "rows": rows, "next": next})
}
