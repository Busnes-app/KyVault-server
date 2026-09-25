package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Busnes-app/kyvault-server/internal/sso"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

func (s *Server) handleAdminUsersList(w http.ResponseWriter, r *http.Request, admin users.User) {
	list := s.users.List()
	res := make([]users.Public, len(list))
	for i, u := range list {
		res[i] = u.Public()
	}
	writeJSON(w, http.StatusOK, res)
}

// Accounts are not created here. They arrive from KySignOn, by replication or by first
// sign-in, and are keyed on the OIDC subject. Role, deactivate and reactivate remain as
// local overrides.

func (s *Server) handleAdminUserRole(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	var req struct {
		Role users.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Role != users.RoleAdmin && req.Role != users.RoleUser) {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	if err := s.users.SetRole(id, req.Role); err != nil {
		if errors.Is(err, users.ErrLastAdmin) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "failed to update role: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "admin.user_role_updated", admin.ID, "", clientIP(r), "updated role for user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminUserDeactivate(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	if id == admin.ID {
		http.Error(w, "you cannot deactivate your own account", http.StatusBadRequest)
		return
	}
	if err := s.users.Deactivate(id); err != nil {
		if errors.Is(err, users.ErrLastAdmin) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "failed to deactivate user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.record(r, "admin.user_deactivated", admin.ID, "", clientIP(r), "deactivated user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminUserReactivate(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	if err := s.users.Reactivate(id); err != nil {
		http.Error(w, "failed to reactivate user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.record(r, "admin.user_reactivated", admin.ID, "", clientIP(r), "reactivated user "+id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type ssoView struct {
	sso.SSOSettings
	ClientSecretSet bool `json:"clientSecretSet"`
}

func (s *Server) handleAdminSSOGet(w http.ResponseWriter, r *http.Request, admin users.User) {
	settings := s.ssoStore.Load()
	view := ssoView{SSOSettings: settings, ClientSecretSet: settings.ClientSecret != ""}
	view.ClientSecret = ""
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleAdminSSOPut(w http.ResponseWriter, r *http.Request, admin users.User) {
	// Refuse rather than accept a write the next restart discards. Silently taking a
	// change that does not survive is worse than saying no.
	if s.ssoStore.EnvSourced() {
		s.record(r, "admin.sso_write_refused", admin.ID, "", clientIP(r), "SSO is configured by the environment")
		http.Error(w, "SSO is configured by the environment ("+sso.EnvIssuer+", "+sso.EnvClientID+", "+sso.EnvClientSecret+") and cannot be changed here. Edit the environment and restart.", http.StatusConflict)
		return
	}

	var req sso.SSOSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// KySignOn is the only way in. A disabled SSO is a server nobody can sign in to.
	if !req.Enabled {
		http.Error(w, "SSO cannot be disabled: KySignOn is the only way to sign in", http.StatusBadRequest)
		return
	}
	issuer, err := url.Parse(req.IssuerURL)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		http.Error(w, "issuerUrl must be an https URL", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ClientID) == "" {
		http.Error(w, "clientId is required", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == "" {
		req.ClientSecret = s.ssoStore.Load().ClientSecret
	}
	if err := s.ssoStore.Save(req); err != nil {
		http.Error(w, "failed to save SSO settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "admin.sso_configured", admin.ID, "", clientIP(r), "updated SSO configuration")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request, admin users.User) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	before := int64(math.MaxInt64)
	if b := r.URL.Query().Get("before"); b != "" {
		if val, err := strconv.ParseInt(b, 10, 64); err == nil {
			before = val
		}
	}

	entries, err := s.audit.ListBefore(before, limit)
	if err != nil {
		http.Error(w, "failed to read audit logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleAuditVerify checks the stored chain, and reports separately how many records
// never reached it. VerifyIntegrity only ever sees what was written: a log that lost a
// record to a full disk verifies perfectly, and "valid" alone would say the trail is
// complete when it is not. It is the only place the count is readable.
// TestFailedAuditWriteIsReportedOnlyToAnAdmin pins the count here.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, admin users.User) {
	ok, err := s.audit.VerifyIntegrity()
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":         ok,
		"writeFailures": s.auditFailures.Load(),
		"error": func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})
}
