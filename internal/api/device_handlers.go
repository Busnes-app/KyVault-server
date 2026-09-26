package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Busnes-app/kyvault-server/internal/devices"
	"github.com/Busnes-app/kyvault-server/internal/sso"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request, u users.User) {
	// withAuth resolved the session under its own lock; a logout can land between
	// that read and this one, and a pairing must not outlive the session it came from.
	current, ok := s.currentSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// A pairing remembers which device session issued it: a code issued by a device
	// that a key rotation later revokes must not mint a replacement session.
	origin, err := json.Marshal(pairingOrigin{SSO: current.SSO, IssuerDeviceID: current.DeviceID})
	if err != nil {
		http.Error(w, "failed to create pairing session", http.StatusInternalServerError)
		return
	}
	session, err := s.devices.CreatePairingSession(u.ID, string(origin))
	if err != nil {
		http.Error(w, "failed to create pairing session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.record(r, "device.pairing_initiated", u.ID, "", clientIP(r), "pairing code issued")
	writeJSON(w, http.StatusOK, map[string]any{
		"pin":       session.PIN,
		"secret":    session.Secret,
		"expiresAt": session.ExpiresAt,
	})
}

// pairingOrigin is what a pairing code carries from the session that started it.
type pairingOrigin struct {
	SSO            sso.Identity `json:"sso"`
	IssuerDeviceID string       `json:"issuerDeviceId,omitempty"`
}

type PairingRedeemRequest struct {
	CodeOrPIN      string `json:"codeOrPin"`
	DeviceName     string `json:"deviceName"`
	Platform       string `json:"platform"`
	DeviceEnvelope string `json:"deviceEnvelope,omitempty"`
}

func (s *Server) handlePairingRedeem(w http.ResponseWriter, r *http.Request) {
	var req PairingRedeemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CodeOrPIN == "" {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	dev, origin, err := s.devices.RedeemPairing(req.CodeOrPIN, req.DeviceName, req.Platform, ip)
	if err != nil {
		// Within the source's audit budget: redeem takes no credential, and a wrong
		// code costs the store nothing until this record. See audit_budget.go.
		s.recordAnonymousRejection(r, "device.pairing_failed", ip, "failed pairing redeem: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Mint only while the directory account is still active and the browser session
	// that started the pairing has not been logged out by KySignOn meanwhile.
	var po pairingOrigin
	if err := json.Unmarshal([]byte(origin), &po); err != nil {
		_ = s.devices.Revoke(dev.ID)
		http.Error(w, "invalid pairing origin", http.StatusBadRequest)
		return
	}
	tokBytes, err := s.startSessionWithToken(dev.UserID, dev.ID, po.IssuerDeviceID, po.SSO)
	if err != nil {
		_ = s.devices.Revoke(dev.ID)
		http.Error(w, "account is inactive or signed out", http.StatusUnauthorized)
		return
	}

	// If device envelope provided, save it to vault metadata
	if req.DeviceEnvelope != "" {
		_ = s.vault.SetDeviceEnvelope(dev.UserID, vault.DeviceEnvelope{
			DeviceID: dev.ID,
			Name:     dev.Name,
			Envelope: req.DeviceEnvelope,
		})
	}

	s.record(r, "device.paired", dev.UserID, dev.ID, ip, fmt.Sprintf("paired device %s (%s)", dev.Name, dev.Platform))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"deviceId":     dev.ID,
		"sessionToken": tokBytes,
		"user": map[string]any{
			"id": dev.UserID,
		},
	})
}

// startSessionWithToken mints a device session. issuerDeviceID names the device whose
// session started the pairing (empty for a browser session); if that device has been
// revoked meanwhile, for example by a key rotation, the pairing cannot mint anything.
// The check shares sessMu with revokeAllDevices, so no interleaving slips past it.
func (s *Server) startSessionWithToken(userID, deviceID, issuerDeviceID string, id sso.Identity) (string, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if u, err := s.users.Get(userID); err != nil || !u.Active {
		return "", fmt.Errorf("account is inactive")
	}
	if !id.Revocable() {
		return "", errors.New("device session needs a revocable identity")
	}
	if s.logouts.Fenced(id, time.Now().UTC()) {
		return "", errLoginFenced
	}
	if deviceID != "" {
		if _, err := s.devices.Get(deviceID); err != nil {
			return "", fmt.Errorf("device is gone: %w", err)
		}
	}
	if issuerDeviceID != "" {
		if _, err := s.devices.Get(issuerDeviceID); err != nil {
			return "", fmt.Errorf("the device that issued this pairing was revoked: %w", err)
		}
	}

	tokBytes := randomHex(24)
	csrfBytes := randomHex(24)

	now := time.Now().UTC()
	s.sessions[tokBytes] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(90 * 24 * time.Hour), // 90-day device session
		CSRFToken: csrfBytes,
		SSO:       id,
		DeviceID:  deviceID,
	}
	return tokBytes, nil
}

// deviceView adds whether the requesting session belongs to this device.
type deviceView struct {
	devices.Device
	Current bool `json:"current"`
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request, u users.User) {
	sess, _ := s.currentSession(r)
	devs := s.devices.ListUserDevices(u.ID)
	views := make([]deviceView, 0, len(devs))
	for _, d := range devs {
		views = append(views, deviceView{Device: d, Current: sess.DeviceID != "" && d.ID == sess.DeviceID})
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request, u users.User) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}

	dev, err := s.devices.Get(deviceID)
	if err != nil || dev.UserID != u.ID {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	s.revokeDevice(r, dev, "revoked device "+dev.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// revokeDevice deletes the device, its vault envelope and every session it holds.
func (s *Server) revokeDevice(r *http.Request, dev devices.Device, details string) {
	s.sessMu.Lock()
	s.revokeDeviceLocked(dev)
	s.sessMu.Unlock()
	s.record(r, "device.revoked", dev.UserID, dev.ID, clientIP(r), details)
}

// revokeDeviceLocked needs sessMu held.
func (s *Server) revokeDeviceLocked(dev devices.Device) {
	_ = s.devices.Revoke(dev.ID)
	_ = s.vault.RemoveDeviceEnvelope(dev.UserID, dev.ID)
	for tok, sess := range s.sessions {
		if sess.DeviceID == dev.ID {
			delete(s.sessions, tok)
		}
	}
}

// revokeAllDevices ends every device of the user in one critical section: pending
// pairing codes, device records, envelopes and sessions go together under sessMu, so a
// redeem or pairing start cannot interleave and leave a device or code behind.
func (s *Server) revokeAllDevices(r *http.Request, userID, reason string) {
	s.sessMu.Lock()
	s.devices.CancelUserPairings(userID)
	revoked := s.devices.ListUserDevices(userID)
	for _, dev := range revoked {
		s.revokeDeviceLocked(dev)
	}
	s.sessMu.Unlock()
	for _, dev := range revoked {
		s.record(r, "device.revoked", dev.UserID, dev.ID, clientIP(r), "revoked device "+dev.Name+": "+reason)
	}
}

func (s *Server) handleDeviceRename(w http.ResponseWriter, r *http.Request, u users.User) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}

	dev, err := s.devices.Get(deviceID)
	if err != nil || dev.UserID != u.ID {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || utf8.RuneCountInString(name) > 64 || strings.ContainsFunc(name, unicode.IsControl) {
		http.Error(w, "invalid device name", http.StatusBadRequest)
		return
	}

	if err := s.devices.Rename(deviceID, name); err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	dev.Name = name

	sess, _ := s.currentSession(r)
	s.record(r, "device.renamed", u.ID, deviceID, clientIP(r), "renamed device to "+name)
	writeJSON(w, http.StatusOK, deviceView{Device: dev, Current: sess.DeviceID != "" && dev.ID == sess.DeviceID})
}
