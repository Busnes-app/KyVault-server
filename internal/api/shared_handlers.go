package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

const sharedBodyLimit = 64 << 10

type sharedCtx struct {
	vault   shared.Vault
	me      shared.Member
	user    users.User
	session Session
}

// sharedMember resolves the caller's row. Anything short of membership is 404 so a
// vault's existence is never confirmed to outsiders.
func (s *Server) sharedMember(w http.ResponseWriter, r *http.Request, u users.User) (sharedCtx, bool) {
	v, err := s.shared.Get(r.PathValue("id")) // Get refuses an invalid id as ErrNotFound
	if err != nil {
		sharedErr(w, err)
		return sharedCtx{}, false
	}
	m, ok := v.Members[u.ID]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return sharedCtx{}, false
	}
	sess, _ := s.currentSession(r)
	return sharedCtx{vault: v, me: m, user: u, session: sess}, true
}

func (c sharedCtx) activeOwner() bool {
	return c.me.Role == shared.RoleOwner && c.me.State == shared.StateActive
}
func (c sharedCtx) canWrite() bool {
	return c.me.State == shared.StateActive && (c.me.Role == shared.RoleOwner || c.me.Role == shared.RoleEditor)
}
func (c sharedCtx) canRead() bool {
	return c.me.State == shared.StateActive || c.me.State == shared.StateStale
}

// targetRow answers 404 unless the {userId} path user has a row in the vault.
func targetRow(w http.ResponseWriter, r *http.Request, c sharedCtx) (string, shared.Member, bool) {
	target := r.PathValue("userId")
	m, ok := c.vault.Members[target]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
	}
	return target, m, ok
}

func ownerless(v shared.Vault) bool {
	for _, m := range v.Members {
		if m.Role == shared.RoleOwner && m.State == shared.StateActive {
			return false
		}
	}
	return true
}

// currentFingerprint is the fingerprint of userID's published user key, if any.
func (s *Server) currentFingerprint(userID string) (string, bool) {
	meta, err := s.vault.GetMetadata(userID)
	if err != nil || meta.UserKey == nil {
		return "", false
	}
	fp, err := meta.UserKey.Fingerprint()
	return fp, err == nil
}

func (s *Server) pruneShared() {
	if _, err := s.shared.PruneDeleted(time.Now()); err != nil {
		log.Printf("prune deleted shared vaults: %v", err)
	}
}

func decodeShared(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, sharedBodyLimit)).Decode(v); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func sharedErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound), errors.Is(err, shared.ErrNotMember):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, shared.ErrShape):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, shared.ErrAlreadyMember), errors.Is(err, shared.ErrLastOwner), errors.Is(err, shared.ErrMemberCap), errors.Is(err, shared.ErrOwnedCap), errors.Is(err, shared.ErrState):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		log.Printf("shared vault error: %v", err)
		http.Error(w, "shared vault error", http.StatusInternalServerError)
	}
}

type memberView struct {
	UserID         string       `json:"userId"`
	Username       string       `json:"username"`
	Role           shared.Role  `json:"role"`
	State          shared.State `json:"state"`
	KeyFingerprint string       `json:"keyFingerprint"`
	KeyEpoch       int          `json:"keyEpoch"`
	AddedAt        time.Time    `json:"addedAt"`
	AcceptedAt     *time.Time   `json:"acceptedAt,omitempty"`
}

func (s *Server) username(id string) string {
	if u, err := s.users.Get(id); err == nil {
		return u.Username
	}
	return ""
}

// memberViews lists members without sealed keys: owners first, then username, then id.
func (s *Server) memberViews(v shared.Vault) []memberView {
	out := make([]memberView, 0, len(v.Members))
	for uid, m := range v.Members {
		out = append(out, memberView{UserID: uid, Username: s.username(uid), Role: m.Role, State: m.State, KeyFingerprint: m.KeyFingerprint, KeyEpoch: m.KeyEpoch, AddedAt: m.AddedAt, AcceptedAt: m.AcceptedAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Role == shared.RoleOwner) != (out[j].Role == shared.RoleOwner) {
			return out[i].Role == shared.RoleOwner
		}
		if out[i].Username != out[j].Username {
			return out[i].Username < out[j].Username
		}
		return out[i].UserID < out[j].UserID
	})
	return out
}

func writeOK(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"ok": true}) }

// POST /api/shared. The owned-vault cap is checked here only (Store.Create).
func (s *Server) handleSharedCreate(w http.ResponseWriter, r *http.Request, u users.User) {
	var req struct {
		Name           string `json:"name"`
		SealedKey      string `json:"sealedKey"`
		KeyFingerprint string `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	settings, err := s.sharedSettings.Get()
	if err != nil {
		http.Error(w, "shared settings unreadable", http.StatusInternalServerError)
		return
	}
	if settings.CreateRestrictedToAdmins && u.Role != users.RoleAdmin {
		http.Error(w, "an administrator has restricted shared vault creation to administrators", http.StatusForbidden)
		return
	}
	fp, found := s.currentFingerprint(u.ID)
	if !found {
		http.Error(w, "publish a user key before creating a shared vault", http.StatusNotFound)
		return
	}
	if req.KeyFingerprint != fp {
		http.Error(w, "keyFingerprint does not match your current user key", http.StatusBadRequest)
		return
	}
	v, err := s.shared.Create(req.Name, u.ID, req.SealedKey, fp, time.Now())
	if err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.created", u.ID, "", clientIP(r), v.ID+" "+v.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"id": v.ID})
}

type myKeyView struct {
	SealedKey           string `json:"sealedKey"`
	KeyFingerprint      string `json:"keyFingerprint"`
	KeyEpoch            int    `json:"keyEpoch"`
	SealedBy            string `json:"sealedBy"`
	SealedByFingerprint string `json:"sealedByFingerprint"`
}

type inviterView struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
}

// GET /api/shared: every vault the caller has a row in, with only the caller's own sealed key.
func (s *Server) handleSharedList(w http.ResponseWriter, r *http.Request, u users.User) {
	vaults, err := s.shared.ListFor(u.ID)
	if err != nil {
		sharedErr(w, err)
		return
	}
	type row struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		Role      shared.Role  `json:"role"`
		State     shared.State `json:"state"`
		KeyEpoch  int          `json:"keyEpoch"`
		MyKey     myKeyView    `json:"myKey"`
		InvitedBy *inviterView `json:"invitedBy,omitempty"`
	}
	out := make([]row, 0, len(vaults))
	for _, v := range vaults {
		m := v.Members[u.ID]
		sealerFP, _ := s.currentFingerprint(m.SealedBy)
		rw := row{ID: v.ID, Name: v.Name, Role: m.Role, State: m.State, KeyEpoch: v.KeyEpoch,
			MyKey: myKeyView{SealedKey: m.SealedKey, KeyFingerprint: m.KeyFingerprint, KeyEpoch: m.KeyEpoch, SealedBy: m.SealedBy, SealedByFingerprint: sealerFP}}
		if m.State == shared.StateInvited {
			rw.InvitedBy = &inviterView{UserID: m.SealedBy, Username: s.username(m.SealedBy), Fingerprint: sealerFP}
		}
		out = append(out, rw)
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/shared/{id}
func (s *Server) handleSharedGet(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if c.me.State == shared.StateInvited {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": c.vault.ID, "name": c.vault.Name, "createdBy": c.vault.CreatedBy, "createdAt": c.vault.CreatedAt,
		"keyEpoch": c.vault.KeyEpoch, "members": s.memberViews(c.vault),
	})
}

// PATCH /api/shared/{id}
func (s *Server) handleSharedRename(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can rename a shared vault", http.StatusForbidden)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	if err := s.shared.Rename(c.vault.ID, req.Name); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.renamed", u.ID, "", clientIP(r), c.vault.ID+" "+req.Name)
	writeOK(w)
}

// deleteShared moves the record and, under the vault store lock, the vault data to the
// deleted area.
func (s *Server) deleteShared(id string) error {
	return s.shared.Delete(id, func(dst string) error {
		return s.vault.MoveOut(shared.StoreKey(id), dst)
	}, time.Now())
}

// DELETE /api/shared/{id}
func (s *Server) handleSharedDelete(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can delete a shared vault", http.StatusForbidden)
		return
	}
	if !s.requireFresh(w, c.session) {
		return
	}
	if err := s.deleteShared(c.vault.ID); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.deleted", u.ID, "", clientIP(r), c.vault.ID+" "+c.vault.Name)
	writeOK(w)
}

// POST /api/shared/{id}/members. Only an active owner invites, so an ownerless vault
// (after an admin removed its last owner) can gain no one: the caller gets 403.
func (s *Server) handleSharedInvite(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can add members", http.StatusForbidden)
		return
	}
	var req struct {
		UserID         string      `json:"userId"`
		Role           shared.Role `json:"role"`
		SealedKey      string      `json:"sealedKey"`
		KeyFingerprint string      `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	target, err := s.users.Get(req.UserID)
	if err != nil || !target.Active {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	fp, found := s.currentFingerprint(target.ID)
	if !found {
		http.Error(w, "that user has not published a key yet", http.StatusNotFound)
		return
	}
	if req.KeyFingerprint != fp {
		http.Error(w, "keyFingerprint does not match that user's current key", http.StatusBadRequest)
		return
	}
	if err := s.shared.Invite(c.vault.ID, target.ID, req.Role, req.SealedKey, fp, u.ID, time.Now()); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_invited", u.ID, "", clientIP(r), c.vault.ID+" "+target.ID+" "+string(req.Role))
	writeOK(w)
}

// PUT /api/shared/{id}/members/{userId}: validate everything, then role (the only write
// that can refuse, ErrLastOwner), then seal, so a refusal writes nothing.
func (s *Server) handleSharedMemberUpdate(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	target, _, found := targetRow(w, r, c)
	if !found {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an owner can change members", http.StatusForbidden)
		return
	}
	var req struct {
		Role           *shared.Role `json:"role"`
		SealedKey      string       `json:"sealedKey"`
		KeyFingerprint string       `json:"keyFingerprint"`
	}
	if !decodeShared(w, r, &req) {
		return
	}
	if req.Role != nil && *req.Role != shared.RoleOwner && *req.Role != shared.RoleEditor && *req.Role != shared.RoleReader {
		http.Error(w, "unknown role", http.StatusBadRequest)
		return
	}
	if (req.SealedKey == "") != (req.KeyFingerprint == "") {
		http.Error(w, "sealedKey and keyFingerprint come together", http.StatusBadRequest)
		return
	}
	if req.SealedKey != "" {
		if err := shared.ValidSealedKey(req.SealedKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if fp, has := s.currentFingerprint(target); !has || fp != req.KeyFingerprint {
			http.Error(w, "keyFingerprint does not match that user's current key", http.StatusBadRequest)
			return
		}
	}
	if req.Role != nil {
		if err := s.shared.SetRole(c.vault.ID, target, *req.Role); err != nil {
			sharedErr(w, err)
			return
		}
		s.record(r, "shared.member_role_changed", u.ID, "", clientIP(r), c.vault.ID+" "+target+" "+string(*req.Role))
	}
	if req.SealedKey != "" {
		if err := s.shared.Reseal(c.vault.ID, target, req.SealedKey, req.KeyFingerprint, u.ID); err != nil {
			sharedErr(w, err)
			return
		}
		s.record(r, "shared.member_resealed", u.ID, "", clientIP(r), c.vault.ID+" "+target)
	}
	writeOK(w)
}

// DELETE /api/shared/{id}/members/{userId}: owners remove anyone; anyone removes
// themselves (an invited row doing so is a decline).
func (s *Server) handleSharedMemberRemove(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	target, row, found := targetRow(w, r, c)
	if !found {
		return
	}
	self := target == u.ID
	if !self && !c.activeOwner() {
		http.Error(w, "only an owner can remove members", http.StatusForbidden)
		return
	}
	if err := s.shared.Remove(c.vault.ID, target, false); err != nil {
		sharedErr(w, err)
		return
	}
	action := "shared.member_removed"
	switch {
	case self && row.State == shared.StateInvited:
		action = "shared.member_declined"
	case self:
		action = "shared.member_left"
	}
	s.record(r, action, u.ID, "", clientIP(r), c.vault.ID+" "+target)
	writeOK(w)
}

// POST /api/shared/{id}/accept. An ownerless vault cannot be joined: 409.
func (s *Server) handleSharedAccept(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if ownerless(c.vault) {
		http.Error(w, "this shared vault has no owner and cannot be joined", http.StatusConflict)
		return
	}
	if err := s.shared.Accept(c.vault.ID, u.ID, time.Now()); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_accepted", u.ID, "", clientIP(r), c.vault.ID)
	writeOK(w)
}

// POST /api/shared/{id}/decline
func (s *Server) handleSharedDecline(w http.ResponseWriter, r *http.Request, u users.User) {
	c, found := s.sharedMember(w, r, u)
	if !found {
		return
	}
	if c.me.State != shared.StateInvited {
		http.Error(w, "only an invitation can be declined", http.StatusConflict)
		return
	}
	if err := s.shared.Remove(c.vault.ID, u.ID, false); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "shared.member_declined", u.ID, "", clientIP(r), c.vault.ID)
	writeOK(w)
}

// GET /api/admin/shared
func (s *Server) handleAdminSharedList(w http.ResponseWriter, r *http.Request, _ users.User) {
	vaults, err := s.shared.List()
	if err != nil {
		sharedErr(w, err)
		return
	}
	type row struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		CreatedBy string       `json:"createdBy"`
		CreatedAt time.Time    `json:"createdAt"`
		KeyEpoch  int          `json:"keyEpoch"`
		Ownerless bool         `json:"ownerless"`
		Members   []memberView `json:"members"`
	}
	out := make([]row, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, row{ID: v.ID, Name: v.Name, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, KeyEpoch: v.KeyEpoch, Ownerless: ownerless(v), Members: s.memberViews(v)})
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /api/admin/shared/{id}
func (s *Server) handleAdminSharedDelete(w http.ResponseWriter, r *http.Request, admin users.User) {
	id := r.PathValue("id")
	v, err := s.shared.Get(id)
	if err != nil {
		sharedErr(w, err)
		return
	}
	if err := s.deleteShared(id); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "admin.shared_deleted", admin.ID, "", clientIP(r), id+" "+v.Name)
	writeOK(w)
}

// DELETE /api/admin/shared/{id}/members/{userId}: the last owner included.
func (s *Server) handleAdminSharedMemberRemove(w http.ResponseWriter, r *http.Request, admin users.User) {
	id, target := r.PathValue("id"), r.PathValue("userId")
	if err := s.shared.Remove(id, target, true); err != nil {
		sharedErr(w, err)
		return
	}
	s.record(r, "admin.shared_member_removed", admin.ID, "", clientIP(r), id+" "+target)
	writeOK(w)
}

// GET /api/admin/shared/settings
func (s *Server) handleAdminSharedSettingsGet(w http.ResponseWriter, r *http.Request, _ users.User) {
	v, err := s.sharedSettings.Get()
	if err != nil {
		http.Error(w, "shared settings unreadable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// PUT /api/admin/shared/settings
func (s *Server) handleAdminSharedSettingsPut(w http.ResponseWriter, r *http.Request, admin users.User) {
	var v SharedSettings
	if !decodeShared(w, r, &v) {
		return
	}
	if err := s.sharedSettings.Put(v); err != nil {
		http.Error(w, "failed to save shared settings", http.StatusInternalServerError)
		return
	}
	s.record(r, "admin.shared_settings_updated", admin.ID, "", clientIP(r), fmt.Sprintf("createRestrictedToAdmins=%t", v.CreateRestrictedToAdmins))
	writeJSON(w, http.StatusOK, v)
}
