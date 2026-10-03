package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/Busnes-app/kyvault-server/internal/reporting"
	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reportCall(t *testing.T, s *Server, c *http.Cookie, method, path string, body any, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if raw, ok := body.(string); ok {
		b = []byte(raw)
	} else if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("If-Match", `"1"`)
	if c != nil {
		req.AddCookie(c)
		if csrf {
			sess, _ := s.currentSession(req)
			req.Header.Set("X-CSRF-Token", sess.CSRFToken)
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: sess.CSRFToken})
		}
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}
func TestReportingAdmissionPrivacyAndInvalidation(t *testing.T) {
	s := newTestServer(t)
	admin, ac := signedInUser(t, s, "report-admin", users.RoleAdmin)
	other, oc := signedInUser(t, s, "other-admin", users.RoleAdmin)
	source, sc := signedInUser(t, s, "source", users.RoleUser)
	for _, id := range []string{admin.ID, source.ID} {
		if _, err := s.vault.SaveVault(id, 0, []byte("encrypted"), "pw", "rec", ""); err != nil {
			t.Fatal(err)
		}
	}
	if r := putUserKey(s.Routes(), ac, `"1"`, userKeyBody(t, 1)); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	cfg, _ := s.reportRecipient(admin.ID)
	var initial reporting.Config
	r := reportCall(t, s, ac, "GET", "/api/reporting/config", nil, false)
	json.Unmarshal(r.Body.Bytes(), &initial)
	body := map[string]any{"generation": initial.Generation, "enabled": true, "recipientId": admin.ID, "keyDigest": cfg.KeyDigest}
	if r = reportCall(t, s, ac, "PUT", "/api/admin/reporting/config", body, false); r.Code != 403 {
		t.Fatal(r.Code)
	}
	if r = reportCall(t, s, sc, "PUT", "/api/admin/reporting/config", body, true); r.Code != 403 {
		t.Fatal(r.Code)
	}
	r = reportCall(t, s, ac, "PUT", "/api/admin/reporting/config", body, true)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	json.Unmarshal(r.Body.Bytes(), &cfg)
	rec := reporting.Record{InstanceID: cfg.InstanceID, Generation: cfg.Generation, SourceID: source.ID, Version: 1, ReportID: reporting.ID(), RecipientID: admin.ID, KeyDigest: cfg.KeyDigest, Sealed: base64.StdEncoding.EncodeToString(make([]byte, reporting.SealedBytes))}
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, false); r.Code != 403 {
		t.Fatal(r.Code)
	}
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, true); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var received time.Time
	s.reporting.Access(func(st *reporting.State) (bool, error) {
		received = st.Records[source.ID].ReceivedAt
		return false, nil
	})
	reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, true)
	s.reporting.Access(func(st *reporting.State) (bool, error) {
		if !st.Records[source.ID].ReceivedAt.Equal(received) {
			t.Fatal("retry refreshed age")
		}
		return false, nil
	})
	if r = reportCall(t, s, ac, "GET", "/api/admin/reporting", nil, false); !strings.Contains(r.Body.String(), rec.Sealed) {
		t.Fatal("recipient cannot read")
	}
	if r = reportCall(t, s, oc, "GET", "/api/admin/reporting", nil, false); strings.Contains(r.Body.String(), rec.Sealed) {
		t.Fatal("other admin read ciphertext")
	}
	spoof := rec
	spoof.SourceID = other.ID
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", spoof, true); r.Code != 400 {
		t.Fatal(r.Code)
	}
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", `{"reportId":"a","reportId":"b"}`, true); r.Code != 400 {
		t.Fatal("duplicate accepted", r.Code)
	}
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", `{"password":"secret"}`, true); r.Code != 400 {
		t.Fatal("unknown accepted")
	}
	s.vault.SaveVault(source.ID, 1, []byte("new encrypted"), "", "", "")
	if r = reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, true); r.Code != 409 {
		t.Fatal("stale accepted", r.Code)
	}
	if r = reportCall(t, s, ac, "GET", "/api/admin/reporting", nil, false); !strings.Contains(r.Body.String(), "stale-version") || strings.Contains(r.Body.String(), rec.Sealed) {
		t.Fatal(r.Body.String())
	}
	// Replacement invalidates settings and ciphertext on the next reporting request.
	var key userkey.Record
	json.Unmarshal(userKeyBody(t, 2), &key)
	s.vault.SaveUserKey(admin.ID, 1, key, false)
	r = reportCall(t, s, ac, "GET", "/api/reporting/config", nil, false)
	var disabled reporting.Config
	json.Unmarshal(r.Body.Bytes(), &disabled)
	if disabled.Enabled || disabled.Generation == cfg.Generation {
		t.Fatal("replacement followed silently")
	}
	s.reporting.Access(func(st *reporting.State) (bool, error) {
		if len(st.Records) != 0 {
			t.Fatal("cache survived replacement")
		}
		return false, nil
	})
}
func TestReportingDeviceAndFreshnessGates(t *testing.T) {
	s := newTestServer(t)
	u, c := signedInUser(t, s, "admin", users.RoleAdmin)
	// Turn a real persisted session into a paired-device session for the route matrix.
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	sess, _ := s.currentSession(req)
	s.sessMu.Lock()
	for k, v := range s.sessions {
		if v.ID == sess.ID {
			v.DeviceID = "device"
			s.sessions[k] = v
		}
	}
	s.sessMu.Unlock()
	for _, route := range []struct{ method, path string }{{"GET", "/api/reporting/config"}, {"PUT", "/api/reporting/report"}, {"DELETE", "/api/reporting/report"}, {"GET", "/api/admin/reporting"}, {"PUT", "/api/admin/reporting/config"}} {
		r := reportCall(t, s, c, route.method, route.path, nil, true)
		if r.Code != 403 {
			t.Fatal(u.ID, route, r.Code)
		}
	}
	s.sessMu.Lock()
	for k, v := range s.sessions {
		v.DeviceID = ""
		v.AuthenticatedAt = time.Now().Add(-time.Hour)
		s.sessions[k] = v
	}
	s.sessMu.Unlock()
	if r := reportCall(t, s, c, "PUT", "/api/admin/reporting/config", map[string]any{}, true); r.Code != 403 {
		t.Fatal(r.Code)
	}
}

func TestReportingLimitsCoverageAndRoleLifecycle(t *testing.T) {
	for _, change := range []string{"demote", "deactivate"} {
		t.Run(change, func(t *testing.T) {
			s := newTestServer(t)
			admin, ac := signedInUser(t, s, "recipient", users.RoleAdmin)
			_, otherCookie := signedInUser(t, s, "other", users.RoleAdmin)
			source, sc := signedInUser(t, s, "source", users.RoleUser)
			for _, id := range []string{admin.ID, source.ID} {
				s.vault.SaveVault(id, 0, []byte("opaque"), "pw", "rec", "")
			}
			if r := putUserKey(s.Routes(), ac, `"1"`, userKeyBody(t, 1)); r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			cfg, _ := s.reportRecipient(admin.ID)
			s.reporting.Access(func(st *reporting.State) (bool, error) { st.Configure(cfg); cfg = st.Config; return true, nil })
			rec := reporting.Record{InstanceID: cfg.InstanceID, Generation: cfg.Generation, SourceID: source.ID, Version: 1, ReportID: reporting.ID(), RecipientID: admin.ID, KeyDigest: cfg.KeyDigest, Sealed: base64.StdEncoding.EncodeToString(make([]byte, reporting.SealedBytes))}
			if r := reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, true); r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
			for _, body := range []any{strings.Repeat("x", 9<<10), `[]`, `{} {}`, map[string]any{"reportId": rec.ReportID, "sealed": "AAAA"}} {
				if r := reportCall(t, s, sc, "PUT", "/api/reporting/report", body, true); r.Code != 400 {
					t.Fatal("bad body admitted", r.Code)
				}
			}
			for _, query := range []string{"limit=0", "limit=101", "limit=oops"} {
				if r := reportCall(t, s, ac, "GET", "/api/admin/reporting?"+query, nil, false); r.Code != 400 {
					t.Fatal(r.Code)
				}
			}
			if r := reportCall(t, s, ac, "GET", "/api/admin/reporting?limit=1", nil, false); !strings.Contains(r.Body.String(), `"next":"`) {
				t.Fatal(r.Body.String())
			}
			s.reporting.Access(func(st *reporting.State) (bool, error) {
				v := st.Records[source.ID]
				v.ReceivedAt = time.Now().Add(-25 * time.Hour)
				st.Records[source.ID] = v
				return true, nil
			})
			if r := reportCall(t, s, ac, "GET", "/api/admin/reporting", nil, false); !strings.Contains(r.Body.String(), "stale-time") || strings.Contains(r.Body.String(), rec.Sealed) {
				t.Fatal(r.Body.String())
			}
			if change == "demote" {
				if err := s.users.SetRole(admin.ID, users.RoleUser); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.users.UpdateDirectory(admin.ID, users.RoleAdmin, false, admin.Username, "", false); err != nil {
					t.Fatal(err)
				}
			}
			r := reportCall(t, s, otherCookie, "GET", "/api/reporting/config", nil, false)
			var disabled reporting.Config
			json.Unmarshal(r.Body.Bytes(), &disabled)
			if disabled.Enabled || disabled.Generation == cfg.Generation {
				t.Fatal("recipient change did not disable")
			}
			if r := reportCall(t, s, sc, "PUT", "/api/reporting/report", rec, true); r.Code != 409 {
				t.Fatal("old generation accepted", r.Code)
			}
		})
	}
}

func TestReportingRecipientReadFailurePreservesCache(t *testing.T) {
	s := newTestServer(t)
	u, c := signedInUser(t, s, "admin", users.RoleAdmin)
	s.vault.SaveVault(u.ID, 0, []byte("encrypted"), "pw", "rec", "")
	putUserKey(s.Routes(), c, `"1"`, userKeyBody(t, 1))
	cfg, _ := s.reportRecipient(u.ID)
	s.reporting.Access(func(st *reporting.State) (bool, error) {
		st.Configure(cfg)
		cfg = st.Config
		st.Records[u.ID] = reporting.Record{Generation: cfg.Generation, ReceivedAt: time.Now(), Sealed: "opaque"}
		return true, nil
	})
	path := filepath.Join(s.dataDir, "vaults", u.ID, "metadata.json")
	if err := os.Rename(path, path+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if r := reportCall(t, s, c, "GET", "/api/reporting/config", nil, false); r.Code != 503 {
		t.Fatal(r.Code, r.Body.String())
	}
	s.reporting.Access(func(st *reporting.State) (bool, error) {
		if !st.Config.Enabled || st.Config.Generation != cfg.Generation || len(st.Records) != 1 {
			t.Fatal("read failure erased cache")
		}
		return false, nil
	})
}
