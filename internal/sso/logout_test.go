package sso

import (
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
)

func TestLogoutEventMatches(t *testing.T) {
	now := time.Now()
	base := Identity{Issuer: "https://idp", ClientID: "app", Subject: "u1", SessionID: "s1", IssuedAt: now}
	sid := LogoutEvent{Issuer: "https://idp", ClientID: "app", Subject: "u1", SessionID: "s1", IssuedAt: now}
	subject := LogoutEvent{Issuer: "https://idp", ClientID: "app", Subject: "u1", IssuedAt: now}
	cases := []struct {
		name  string
		event LogoutEvent
		id    Identity
		want  bool
	}{
		{"named session", sid, base, true},
		{"other session of same subject", sid, with(base, func(i *Identity) { i.SessionID = "s2" }), false},
		{"same sid, other subject", sid, with(base, func(i *Identity) { i.Subject = "u2" }), false},
		{"sid-only token matches by sid", LogoutEvent{Issuer: "https://idp", ClientID: "app", SessionID: "s1", IssuedAt: now}, base, true},
		{"subject-wide covers every session", subject, with(base, func(i *Identity) { i.SessionID = "s2" }), true},
		{"subject-wide covers sid-less session", subject, with(base, func(i *Identity) { i.SessionID = "" }), true},
		{"subject-wide spares later login", subject, with(base, func(i *Identity) { i.IssuedAt = now.Add(time.Second) }), false},
		{"other issuer", sid, with(base, func(i *Identity) { i.Issuer = "https://other" }), false},
		{"other client", sid, with(base, func(i *Identity) { i.ClientID = "other" }), false},
		{"session without identity", subject, Identity{}, false},
	}
	for _, tc := range cases {
		if got := tc.event.Matches(tc.id); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func with(id Identity, f func(*Identity)) Identity { f(&id); return id }

func TestLogoutLogDurableReplayAndFence(t *testing.T) {
	dir := t.TempDir()
	log, err := NewLogoutLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := oidcverify.LogoutClaims{Issuer: "https://idp", Subject: "u1", SessionID: "s1", JWTID: "j1", IssuedAt: now, ReplayUntil: now.Add(5 * time.Minute)}
	if _, err := log.Admit(claims, "app", now); err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	if _, err := log.Admit(claims, "app", now); !errors.Is(err, ErrLogoutReplayed) {
		t.Fatalf("replay err = %v, want ErrLogoutReplayed", err)
	}
	if _, err := log.Admit(claims, "other-client", now); err != nil {
		t.Fatalf("same jti for another client must be its own event: %v", err)
	}

	id := Identity{Issuer: "https://idp", ClientID: "app", Subject: "u1", SessionID: "s1", IssuedAt: now}
	if !log.Fenced(id, now) {
		t.Fatal("logged-out session is not fenced")
	}
	if log.Fenced(with(id, func(i *Identity) { i.SessionID = "s2" }), now) {
		t.Fatal("unrelated session fenced")
	}

	// Restart: the file is the record.
	reloaded, err := NewLogoutLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Admit(claims, "app", now); !errors.Is(err, ErrLogoutReplayed) {
		t.Fatalf("replay after restart err = %v, want ErrLogoutReplayed", err)
	}
	if !reloaded.Fenced(id, now) {
		t.Fatal("fence lost across restart")
	}

	// Past retention the event is forgotten, and a fresh admission prunes it from disk.
	later := now.Add(6 * time.Minute)
	if reloaded.Fenced(id, later) {
		t.Fatal("expired event still fences")
	}
	other := claims
	other.JWTID = "j2"
	other.ReplayUntil = later.Add(time.Minute)
	if _, err := reloaded.Admit(other, "app", later); err != nil {
		t.Fatal(err)
	}
	pruned, err := NewLogoutLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.events) != 1 {
		t.Fatalf("events on disk after prune = %d, want 1", len(pruned.events))
	}
}

func TestLogoutLogCapacity(t *testing.T) {
	log, err := NewLogoutLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < logoutCapacity; i++ {
		log.events[string(rune(i))+"x"] = LogoutEvent{RetainUntil: now.Add(time.Hour)}
	}
	_, err = log.Admit(oidcverify.LogoutClaims{Issuer: "https://idp", JWTID: "j", Subject: "u", ReplayUntil: now.Add(time.Minute)}, "app", now)
	if !errors.Is(err, ErrLogoutCapacity) {
		t.Fatalf("err = %v, want ErrLogoutCapacity", err)
	}
}
