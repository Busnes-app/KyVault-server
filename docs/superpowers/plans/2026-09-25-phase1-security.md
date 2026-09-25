# Phase 1: Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the eight security findings from the 2026-09-25 audit without changing any wire format a mobile client or KyAuth depends on.

**Architecture:** Server-side fixes are small, tested Go changes in `internal/api`, `internal/users` and `internal/sso`. Client-side fixes add three tiny pure helpers under `frontend/src/lib` with `node --test` coverage and wire them into existing pages. No new dependencies.

**Tech Stack:** Go 1.2x stdlib `net/http`, React 18 + TypeScript, WebCrypto, `tsx --test`.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md` (Phase 1 table).

## Global Constraints

- Branch `fix/phase1-security` from `master`. One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`.
- The server never receives a master password or vault key. Nothing in this plan sends one.
- No wire-format change to `POST /api/vault/upload`, `/api/devices/pairing/*`, `/api/sync/webhook`, `/scim/v2`.
- Copy rules: sentences, no em-dashes, no "successfully".
- DOX: update `AGENTS.md` where a task changes a contract (Tasks 1, 3, 4, 5, 7, 8 do).

## Review Focus

Inputs the spec implies but no task below exercises directly. Each has been pinned to a test in the owning task.

1. A production build of the frontend loaded under the new CSP must show zero `Content-Security-Policy` console violations on login, unlock, pairing QR, CSV import and attachment download. Pinned: Task 1 step 12 (manual browser check, recorded in the PR).
2. `POST /api/vault/upload` with `Content-Type: application/json` and a body whose `kdbxBase64` is not base64 must return 400 and leave the current vault untouched. Pinned: Task 2.
3. `PUT /api/admin/sso` with a blank `clientSecret` must keep the secret that is on disk; a response body must never contain the secret. Pinned: Task 3.
4. Two admins: deactivating one succeeds, deactivating the remaining one returns 409, reactivating the first then deactivating the second succeeds. Pinned: Task 4.
5. A legacy IndexedDB record with a plain `keyHex` field must be ignored (user types the password once) and replaced by a wrapped record on the next unlock. Pinned: Task 5 step 7 (manual browser check).

---

### Task 1: Security headers, no wildcard CORS, no source maps, no directory listings

**Files:**
- Create: `internal/api/headers.go`
- Create: `internal/api/headers_test.go`
- Create: `internal/api/static.go`
- Create: `internal/api/static_test.go`
- Modify: `internal/api/server.go:158-241` (delete `corsMiddleware`, wrap with `SecurityHeaders`)
- Modify: `cmd/server/main.go:104-135` (use `api.SPAHandler`)
- Modify: `frontend/vite.config.ts:20-23`
- Modify: `AGENTS.md` (Verification / Core Capabilities note)

**Interfaces:**
- Produces: `func SecurityHeaders(next http.Handler) http.Handler` and `func SPAHandler(webDir string) http.Handler` in package `api`.

- [ ] **Step 1: Write the failing headers test**

```go
// internal/api/headers_test.go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	want := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "script-src 'self' 'wasm-unsafe-eval'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q: %s", directive, csp)
		}
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("wildcard CORS is back: Access-Control-Allow-Origin = %q", got)
	}
}

func TestPreflightIsNotAnsweredForForeignOrigins(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/vault/metadata", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("preflight granted cross-origin access: %v", rec.Header())
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/api -run 'TestSecurityHeaders|TestPreflight' -v`
Expected: FAIL, `Access-Control-Allow-Origin = "*"` and missing headers.

- [ ] **Step 3: Write `headers.go` and remove `corsMiddleware`**

```go
// internal/api/headers.go
package api

import "net/http"

// contentSecurityPolicy is the strictest policy the built frontend runs under.
// 'wasm-unsafe-eval' is for hash-wasm (Argon2). data: and blob: images are the pairing
// QR code. Inline React style props go through CSSOM and are not governed by style-src.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
	"style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

// SecurityHeaders applies browser hardening to every response, API and static alike.
// There is no CORS: the web app is same-origin and native clients use Bearer tokens
// from a non-browser context, which CORS does not gate. Browser extensions reach the
// API through their host permissions, which also bypass CORS.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000") // ignored by browsers over plain HTTP
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
```

In `internal/api/server.go` replace the tail of `Routes()`:

```go
	return SecurityHeaders(mux)
}
```

and delete the whole `corsMiddleware` function (`server.go:228-241`).

- [ ] **Step 4: Run the headers tests and the whole package**

Run: `go test ./internal/api -race`
Expected: PASS. If any existing test asserted `Access-Control-*`, delete that assertion; it was asserting the bug.

- [ ] **Step 5: Write the failing static-handler test**

```go
// internal/api/static_test.go
package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSPAHandlerNeverListsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets", "fonts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>app"), 0o644)
	os.WriteFile(filepath.Join(dir, "assets", "fonts", "a.woff2"), []byte("font"), 0o644)
	h := SPAHandler(dir)

	for _, path := range []string{"/", "/assets/", "/assets/fonts/", "/vault", "/assets/fonts"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app") {
			t.Errorf("%s: code %d body %q, want index.html", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "a.woff2") {
			t.Errorf("%s: directory listing leaked", path)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/fonts/a.woff2", nil))
	if rec.Body.String() != "font" {
		t.Errorf("real file not served: %q", rec.Body.String())
	}
}
```

- [ ] **Step 6: Run it to see it fail**

Run: `go test ./internal/api -run TestSPAHandler -v`
Expected: FAIL, `SPAHandler` undefined.

- [ ] **Step 7: Write `static.go`**

```go
// internal/api/static.go
package api

import (
	"net/http"
	"os"
	"path/filepath"
)

// SPAHandler serves the built frontend. Every directory and every unknown path gets
// index.html so the client router can take over; http.FileServer's directory listing
// is never reachable.
func SPAHandler(webDir string) http.Handler {
	files := http.FileServer(http.Dir(webDir))
	index := filepath.Join(webDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := filepath.Join(webDir, filepath.Clean("/"+r.URL.Path))
		info, err := os.Stat(target)
		if err != nil || info.IsDir() {
			http.ServeFile(w, r, index)
			return
		}
		files.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 8: Wire it in `cmd/server/main.go`**

Replace lines 115-124 (the `if webDir != ""` block body) with:

```go
	if webDir != "" {
		rootMux.Handle("/", api.SPAHandler(webDir))
	} else {
```

Then wrap the whole mux so static responses get headers too. Change the `http.Server` literal:

```go
		Handler:      api.SecurityHeaders(rootMux),
```

Remove the now-unused `filepath` import from `main.go` if nothing else uses it (`go build` tells you).

- [ ] **Step 9: Run tests and build**

Run: `go test ./... -race && go build -o ./kyvault-server ./cmd/server`
Expected: PASS, binary builds.

- [ ] **Step 10: Turn off production source maps**

`frontend/vite.config.ts`:

```ts
  build: {
    outDir: "dist",
    sourcemap: false,
  },
```

- [ ] **Step 11: Build the frontend**

Run: `cd frontend && npm run build && ls dist/assets | grep -c '\.map$'`
Expected: build succeeds, count is `0`.

- [ ] **Step 12: Browser check of the CSP (record in PR)**

Run the Go binary against `frontend/dist` with a working KySignOn (or the `impeccable`-free path: `WEB_DIR=frontend/dist ./kyvault-server` and open the login page). Open DevTools console. Expected: no `Refused to ...` CSP messages on the login page. If the built CSS is inlined as a `<style>` tag instead of a linked file, add `build.cssCodeSplit: false` and confirm a `.css` link in `dist/index.html`. Note the outcome in the PR description; the full unlock, QR and import paths are re-checked at the end of the phase in Task 8 step 9.

- [ ] **Step 13: DOX and commit**

In `AGENTS.md` under "Core Capabilities & Architecture" item 8 append: `The Go server sets a strict CSP (script-src 'self' 'wasm-unsafe-eval', frame-ancestors 'none'), nosniff, no-referrer and HSTS on every response and serves no CORS headers; native and extension clients use Bearer tokens from non-browser or host-permitted contexts. Production builds ship no source maps.`

```bash
git add internal/api/headers.go internal/api/headers_test.go internal/api/static.go internal/api/static_test.go internal/api/server.go cmd/server/main.go frontend/vite.config.ts AGENTS.md
git commit -m "harden HTTP responses: CSP, no CORS, no listings, no source maps"
```

---

### Task 2: Decode the JSON upload body

**Files:**
- Modify: `internal/api/vault_handlers.go:80-91`
- Test: `internal/api/vault_upload_limit_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/api/vault_upload_limit_test.go`:

```go
func TestJSONUploadDecodesBase64(t *testing.T) {
	srv := newTestServer(t)
	user, cookie := signedInUser(t, srv, "json-client", users.RoleUser)
	if _, err := srv.vault.SaveVault(user.ID, 0, []byte("current"), "", "", "web"); err != nil {
		t.Fatal(err)
	}
	handler := srv.Routes()
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/vault/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("If-Match", `"1"`)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(`{"kdbxBase64":"not base64!!"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad base64 = %d, want 400", rec.Code)
	}
	if rec := post(`{"kdbxBase64":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d, want 400", rec.Code)
	}
	if rec := post(`{"kdbxBase64":"` + base64.StdEncoding.EncodeToString([]byte("new bytes")) + `"}`); rec.Code != http.StatusOK {
		t.Fatalf("good upload = %d: %s", rec.Code, rec.Body)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != "new bytes" {
		t.Fatalf("stored %q, want the decoded bytes", rec.Body.String())
	}
}
```

Add `"encoding/base64"` to the test imports.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/api -run TestJSONUploadDecodesBase64 -v`
Expected: FAIL, stored body equals the base64 text.

- [ ] **Step 3: Decode in the handler**

Replace `vault_handlers.go:90` (`kdbxData = []byte(req.KdbxBase64)`) with:

```go
		decoded, err := base64.StdEncoding.DecodeString(req.KdbxBase64)
		if err != nil || len(decoded) == 0 {
			http.Error(w, "kdbxBase64 must be non-empty standard base64", http.StatusBadRequest)
			return
		}
		kdbxData = decoded
```

Add `"encoding/base64"` to the imports.

- [ ] **Step 4: Run the package**

Run: `go test ./internal/api -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/vault_handlers.go internal/api/vault_upload_limit_test.go
git commit -m "decode base64 on JSON vault uploads"
```

---

### Task 3: SSO settings never leak the secret and cannot disable sign-in

**Files:**
- Modify: `internal/api/admin_handlers.go:64-96`
- Test: `internal/api/retired_routes_test.go` (append)
- Modify: `frontend/src/pages/AdminPanel.tsx:34-70, 236-262`
- Modify: `AGENTS.md` Authentication section

**Interfaces:**
- Produces: `GET /api/admin/sso` → `{enabled, issuerUrl, clientId, redirectUri, autoProvision, clientSecretSet: bool}`; `PUT /api/admin/sso` accepts the same shape, blank `clientSecret` keeps the stored one, `enabled:false` is 400, non-https `issuerUrl` or empty `clientId` is 400. Response `{"ok":true}`.

- [ ] **Step 1: Write the failing server tests**

Append to `internal/api/retired_routes_test.go`:

```go
func TestAdminSSOGetNeverReturnsTheSecret(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	for _, k := range []string{sso.EnvIssuer, sso.EnvClientID, sso.EnvClientSecret} {
		t.Setenv(k, "")
	}
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://signon.example", ClientID: "kyvault", ClientSecret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/sso", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("secret in GET body: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"clientSecretSet":true`) {
		t.Fatalf("clientSecretSet missing: %s", rec.Body)
	}
}

func TestAdminSSOPutRules(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	for _, k := range []string{sso.EnvIssuer, sso.EnvClientID, sso.EnvClientSecret} {
		t.Setenv(k, "")
	}
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://signon.example", ClientID: "kyvault", ClientSecret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/admin/sso", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	cases := map[string]int{
		`{"enabled":false,"issuerUrl":"https://signon.example","clientId":"kyvault"}`: 400,
		`{"enabled":true,"issuerUrl":"http://signon.example","clientId":"kyvault"}`:   400,
		`{"enabled":true,"issuerUrl":"https://signon.example","clientId":""}`:         400,
		`{"enabled":true,"issuerUrl":"https://signon.example","clientId":"kyvault"}`:  200,
	}
	for body, want := range cases {
		if rec := put(body); rec.Code != want {
			t.Errorf("%s -> %d, want %d (%s)", body, rec.Code, want, rec.Body)
		}
	}
	if got := srv.ssoStore.Load(); got.ClientSecret != "s3cret" || !got.Enabled {
		t.Fatalf("blank secret must keep the stored one and SSO must stay enabled: %+v", got)
	}
	rec := put(`{"enabled":true,"issuerUrl":"https://signon.example","clientId":"kyvault","clientSecret":"new"}`)
	if strings.Contains(rec.Body.String(), "new") {
		t.Fatalf("PUT echoed the secret: %s", rec.Body)
	}
	if got := srv.ssoStore.Load(); got.ClientSecret != "new" {
		t.Fatalf("new secret not saved: %+v", got)
	}
}
```

- [ ] **Step 2: Run to see them fail**

Run: `go test ./internal/api -run 'TestAdminSSOGetNever|TestAdminSSOPutRules' -v`
Expected: FAIL on secret leak and on 200 for `enabled:false`.

- [ ] **Step 3: Rewrite the two handlers**

In `internal/api/admin_handlers.go` replace `handleAdminSSOGet` and the body of `handleAdminSSOPut` after the env check:

```go
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
```

```go
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
```

Add `"net/url"` and `"strings"` to imports if absent.

- [ ] **Step 4: Run the package**

Run: `go test ./internal/api -race`
Expected: PASS.

- [ ] **Step 5: Fix the admin panel load and form**

In `frontend/src/pages/AdminPanel.tsx`:

Type and state (around line 34):

```tsx
type SSOSettings = { enabled: boolean; issuerUrl: string; clientId: string; clientSecret?: string; redirectUri?: string; autoProvision: boolean; clientSecretSet?: boolean };
const [ssoSettings, setSsoSettings] = useState<SSOSettings | null>(null);
```

Replace `loadData` (lines 52-69):

```tsx
  const loadData = async () => {
    const [u, s, a, v, p] = await Promise.allSettled([
      getJSON<User[]>("/api/admin/users"),
      getJSON<SSOSettings>("/api/admin/sso"),
      getJSON<AuditEntry[]>("/api/audit?limit=50"),
      getJSON<{ valid: boolean }>("/api/audit/verify"),
      getJSON<{ configured: boolean; basePath: string }>("/api/admin/provisioning"),
    ]);
    if (u.status === "fulfilled") setUsersList(u.value || []);
    if (s.status === "fulfilled") setSsoSettings(s.value);
    if (a.status === "fulfilled") setAuditLogs(a.value || []);
    if (v.status === "fulfilled") setAuditValid(v.value.valid);
    if (p.status === "fulfilled") setProvisioning(p.value);
    const failed = [u, s, a, v, p].filter((r): r is PromiseRejectedResult => r.status === "rejected");
    if (failed.length) setError(toErrorMessage(failed[0].reason, "Some admin data could not be loaded"));
  };
```

Wrap the SSO form so it renders only when `ssoSettings` is non-null: `{ssoSettings ? (<form …>) : <p>Loading SSO settings…</p>}`. Every `setSsoSettings({ ...ssoSettings, x })` inside the form is already safe because the form is inside the null check; TypeScript will confirm. Remove the `enabled` checkbox if one exists; it is always true.

Client secret field (lines 236-247):

```tsx
              <label className="input-label">Client Secret</label>
              <input
                type="password"
                className="input font-mono"
                autoComplete="off"
                placeholder={ssoSettings.clientSecretSet ? "Unchanged. Type a new value to replace it." : "Required unless the client uses PKCE only"}
                value={ssoSettings.clientSecret || ""}
                onChange={(e) => setSsoSettings({ ...ssoSettings, clientSecret: e.target.value })}
              />
```

- [ ] **Step 6: Typecheck and build**

Run: `cd frontend && npm test && npm run build`
Expected: PASS, build succeeds.

- [ ] **Step 7: DOX and commit**

In `AGENTS.md` Authentication bullets, after the `PUT /api/admin/sso` sentence add: `GET /api/admin/sso never returns the client secret, only clientSecretSet; a PUT with a blank secret keeps the stored one, and enabled:false, a non-https issuer or an empty clientId is refused with 400.`

```bash
git add internal/api/admin_handlers.go internal/api/retired_routes_test.go frontend/src/pages/AdminPanel.tsx AGENTS.md
git commit -m "keep the OIDC client secret server-side and refuse disabling SSO"
```

---

### Task 4: Protect the last admin and refuse self-deactivation

**Files:**
- Modify: `internal/users/users.go:287-333`
- Test: `internal/users/users_test.go` (append)
- Modify: `internal/api/admin_handlers.go:25-52`
- Test: `internal/api/api_test.go` (append)
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `users.ErrLastAdmin`; `Deactivate` and `SetRole` return it when the change would leave zero active admins. Handlers map it to 409; deactivating your own ID is 400.

- [ ] **Step 1: Write the failing store test**

Append to `internal/users/users_test.go` (use the same constructor the file already uses to build a store in a temp dir; the existing tests show the call):

```go
func TestLastActiveAdminCannotBeRemoved(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	a, _ := s.CreateSSOUser("a", RoleAdmin, "sub-a", "a", "a@x")
	b, _ := s.CreateSSOUser("b", RoleAdmin, "sub-b", "b", "b@x")

	if err := s.Deactivate(a.ID); err != nil {
		t.Fatalf("first admin deactivate: %v", err)
	}
	if err := s.Deactivate(b.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin deactivate = %v, want ErrLastAdmin", err)
	}
	if err := s.SetRole(b.ID, RoleUser); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demote = %v, want ErrLastAdmin", err)
	}
	if err := s.Reactivate(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Deactivate(b.ID); err != nil {
		t.Fatalf("with two admins deactivate = %v", err)
	}
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test ./internal/users -run TestLastActiveAdminCannotBeRemoved -v`
Expected: FAIL, `ErrLastAdmin` undefined.

- [ ] **Step 3: Implement the guard**

In `internal/users/users.go` next to `ErrNotFound`:

```go
// ErrLastAdmin: the change would leave no active admin, and there is no local login to fix that.
var ErrLastAdmin = errors.New("the last active admin cannot be removed")

func (s *Store) activeAdminsLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Active && u.Role == RoleAdmin {
			n++
		}
	}
	return n
}
```

In `SetRole`, after the `exists` check:

```go
	if u.Active && u.Role == RoleAdmin && role != RoleAdmin && s.activeAdminsLocked() <= 1 {
		return ErrLastAdmin
	}
```

In `Deactivate`, after the `exists` check:

```go
	if u.Active && u.Role == RoleAdmin && s.activeAdminsLocked() <= 1 {
		return ErrLastAdmin
	}
```

`UpdateDirectory` is untouched: the directory owns directory-driven deactivation.

- [ ] **Step 4: Run the store tests**

Run: `go test ./internal/users -race`
Expected: PASS.

- [ ] **Step 5: Write the failing handler test**

Append to `internal/api/api_test.go`:

```go
func TestAdminCannotDeactivateSelfOrLastAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, cookie := signedInUser(t, srv, "root", users.RoleAdmin)
	post := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post("/api/admin/users/" + admin.ID + "/deactivate"); code != http.StatusBadRequest {
		t.Fatalf("self deactivate = %d, want 400", code)
	}
	other, err := srv.users.CreateSSOUser("second", users.RoleAdmin, "sub-second", "second", "s@x")
	if err != nil {
		t.Fatal(err)
	}
	if code := post("/api/admin/users/" + other.ID + "/deactivate"); code != http.StatusOK {
		t.Fatalf("deactivate other admin = %d, want 200", code)
	}
	// root is now the last active admin; a second admin session trying to remove it must get 409.
	if err := srv.users.Reactivate(other.ID); err != nil {
		t.Fatal(err)
	}
	if err := srv.users.Deactivate(admin.ID); err != nil {
		t.Fatal(err)
	}
	_, otherCookie := signedInUser(t, srv, "third", users.RoleAdmin)
	if err := srv.users.Deactivate(other.ID); err != nil {
		t.Fatal(err)
	}
	third, _ := srv.users.GetByUsername("third")
	req := httptest.NewRequest(http.MethodPut, "/api/admin/users/"+third.ID+"/role", strings.NewReader(`{"role":"user"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(otherCookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("demote last admin = %d, want 409", rec.Code)
	}
}
```

Admin user routes do not check `validCSRF` today (the existing `TestAdminSSOPutStillWorksWithoutTheEnvironment` passes with only the session cookie), so the session cookie is enough here. Adding CSRF checks to admin routes is a Phase 2 item, not this task.

- [ ] **Step 6: Run to see it fail**

Run: `go test ./internal/api -run TestAdminCannotDeactivateSelfOrLastAdmin -v`
Expected: FAIL, self deactivate returns 200.

- [ ] **Step 7: Map errors in the handlers**

`handleAdminUserDeactivate`:

```go
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
```

`handleAdminUserRole`, the `SetRole` error branch:

```go
	if err := s.users.SetRole(id, req.Role); err != nil {
		if errors.Is(err, users.ErrLastAdmin) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "failed to update role: "+err.Error(), http.StatusInternalServerError)
		return
	}
```

Add `"errors"` to imports if absent.

- [ ] **Step 8: Run everything**

Run: `go test ./... -race`
Expected: PASS.

- [ ] **Step 9: Hide the button in the UI**

In `frontend/src/pages/AdminPanel.tsx` the deactivate button for a row: add `disabled={u.id === currentUserId}` where `currentUserId` comes from a new prop `currentUserId: string` passed from `App.tsx` (`<AdminPanel currentUserId={user.id} />`), with `title="You cannot deactivate your own account"`. The 409 for the last admin already surfaces through `toErrorMessage`.

- [ ] **Step 10: DOX and commit**

`AGENTS.md` Authentication: add `Local admin actions cannot deactivate the caller (400) or leave zero active admins (409, users.ErrLastAdmin); directory-driven deactivation via SCIM or the webhook is not guarded, the directory is authoritative.`

```bash
git add internal/users/users.go internal/users/users_test.go internal/api/admin_handlers.go internal/api/api_test.go frontend/src/pages/AdminPanel.tsx frontend/src/App.tsx AGENTS.md
git commit -m "refuse removing the last admin or yourself"
```

---

### Task 5: Wrap the cached device key with a non-extractable CryptoKey

**Files:**
- Create: `frontend/src/lib/deviceKey.ts`
- Create: `frontend/src/lib/deviceKey.test.ts`
- Modify: `frontend/src/lib/storage.ts`
- Modify: `frontend/src/pages/SecuritySettings.tsx:352` (copy)
- Modify: `AGENTS.md` (`storage.ts` bullet)

**Interfaces:**
- Produces: `newWrappingKey(): Promise<CryptoKey>`, `sealKeyHex(wrapping, keyHex): Promise<SealedKey>`, `openKeyHex(wrapping, sealed): Promise<string>` where `type SealedKey = { iv: Uint8Array; ciphertext: Uint8Array }`.
- `storage.ts` keeps its exported signatures unchanged.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/deviceKey.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { newWrappingKey, sealKeyHex, openKeyHex } from "./deviceKey";

test("device key round-trips under a non-extractable wrapping key", async () => {
  const wrapping = await newWrappingKey();
  assert.equal(wrapping.extractable, false);
  const sealed = await sealKeyHex(wrapping, "ab".repeat(32));
  assert.equal(await openKeyHex(wrapping, sealed), "ab".repeat(32));
});

test("tampered ciphertext and a different wrapping key both fail", async () => {
  const wrapping = await newWrappingKey();
  const sealed = await sealKeyHex(wrapping, "cd".repeat(32));
  const tampered = { ...sealed, ciphertext: sealed.ciphertext.map((b, i) => (i === 3 ? b ^ 1 : b)) };
  await assert.rejects(openKeyHex(wrapping, tampered));
  await assert.rejects(openKeyHex(await newWrappingKey(), sealed));
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/deviceKey.test.ts`
Expected: FAIL, cannot find module `./deviceKey`.

- [ ] **Step 3: Write the helper**

```ts
// frontend/src/lib/deviceKey.ts
// The cached vault key is encrypted at rest under a per-browser AES-GCM key that
// WebCrypto refuses to export. A copy of the IndexedDB files alone no longer yields the
// vault key; a script running on this origin still can, which is what the CSP is for.
export type SealedKey = { iv: Uint8Array; ciphertext: Uint8Array };

export function newWrappingKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function sealKeyHex(wrapping: CryptoKey, keyHex: string): Promise<SealedKey> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(keyHex);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapping, plain));
  plain.fill(0);
  return { iv, ciphertext };
}

export async function openKeyHex(wrapping: CryptoKey, sealed: SealedKey): Promise<string> {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.iv }, wrapping, sealed.ciphertext);
  return new TextDecoder().decode(plain);
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/deviceKey.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Use it in `storage.ts`**

Replace the bodies of `storeDeviceVaultKey` and `getDeviceVaultKey`; keep `clearDeviceVaultKey` and `clearAllDeviceVaultKeys` as they are. Add a small transaction helper so every promise settles on `oncomplete`:

```ts
import { newWrappingKey, sealKeyHex, openKeyHex, type SealedKey } from "./deviceKey";

// ponytail: the wrapping CryptoKey lives in the same "keys" store under a reserved
// username so the database version stays 1 for tabs still running the old client.
// Upgrade path: a second object store behind a version bump once every client is current.
const WRAPPING_RECORD = "\u0000device-wrapping-key";

type KeyRecord = { username: string; sealed?: SealedKey; keyHex?: string; updatedAt: string };
type WrappingRecord = { username: typeof WRAPPING_RECORD; cryptoKey: CryptoKey };

function run<T>(db: IDBDatabase, mode: IDBTransactionMode, op: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const req = op(tx.objectStore(STORE_NAME));
    tx.oncomplete = () => resolve(req.result);
    tx.onerror = () => reject(tx.error ?? new Error("Local key store transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("Local key store transaction aborted"));
  });
}

async function wrappingKey(db: IDBDatabase): Promise<CryptoKey> {
  const existing = await run<WrappingRecord | undefined>(db, "readonly", (s) => s.get(WRAPPING_RECORD));
  if (existing?.cryptoKey) return existing.cryptoKey;
  const cryptoKey = await newWrappingKey();
  await run(db, "readwrite", (s) => s.put({ username: WRAPPING_RECORD, cryptoKey } satisfies WrappingRecord));
  return cryptoKey;
}

export async function storeDeviceVaultKey(username: string, keyHex: string): Promise<void> {
  const db = await openDatabase();
  try {
    const sealed = await sealKeyHex(await wrappingKey(db), keyHex);
    await run(db, "readwrite", (s) => s.put({ username, sealed, updatedAt: new Date().toISOString() } satisfies KeyRecord));
  } finally { db.close(); }
}

export async function getDeviceVaultKey(username: string): Promise<string | undefined> {
  const db = await openDatabase();
  try {
    const record = await run<KeyRecord | undefined>(db, "readonly", (s) => s.get(username));
    // A legacy plain-hex record is ignored and replaced on the next password unlock.
    if (!record?.sealed) return undefined;
    return await openKeyHex(await wrappingKey(db), record.sealed);
  } finally { db.close(); }
}
```

Also convert `clearDeviceVaultKey` and `clearAllDeviceVaultKeys` to `run(db, "readwrite", s => s.delete(username))` / `s.clear()` so they settle on `oncomplete` too. `clearAllDeviceVaultKeys` removing the wrapping record is fine: a new one is generated on demand.

- [ ] **Step 6: Typecheck and unit tests**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

- [ ] **Step 7: Browser check (record in PR)**

With the previous build still holding a plain `keyHex` record: reload, expect the unlock dialog once; unlock; in DevTools → Application → IndexedDB → `kypasswords-device-vault/keys` expect the user record to hold `sealed.iv` and `sealed.ciphertext`, no `keyHex`, plus the `\u0000device-wrapping-key` record with a `CryptoKey`. Reload again: one-click unlock works.

- [ ] **Step 8: Fix the copy and DOX, commit**

`SecuritySettings.tsx` line 352 area: replace the "secure storage vault" wording with: `The vault key is kept in this browser, encrypted under a key the browser will not export. Forget This Device removes it.`

`AGENTS.md` `storage.ts` bullet: replace with `manages the IndexedDB keys store on trusted devices for 1-click unlock. The vault key is sealed (AES-GCM) under a non-extractable per-browser CryptoKey held in the same store; legacy plain-hex records are ignored and replaced on the next password unlock. Forget This Device clears it.`

```bash
git add frontend/src/lib/deviceKey.ts frontend/src/lib/deviceKey.test.ts frontend/src/lib/storage.ts frontend/src/pages/SecuritySettings.tsx AGENTS.md
git commit -m "seal the cached device key under a non-extractable browser key"
```

---

### Task 6: Safe entry links and an anchored CSRF cookie match

**Files:**
- Create: `frontend/src/lib/safeHref.ts`
- Create: `frontend/src/lib/safeHref.test.ts`
- Modify: `frontend/src/pages/VaultPage.tsx:664-676`
- Modify: `frontend/src/lib/api.ts:15`

**Interfaces:**
- Produces: `safeHref(raw: string): string | null`.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/safeHref.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { safeHref } from "./safeHref";

test("only http(s) links open", () => {
  assert.equal(safeHref("https://example.com/login"), "https://example.com/login");
  assert.equal(safeHref("http://intranet/"), "http://intranet/");
  assert.equal(safeHref("example.com"), "https://example.com/");
  assert.equal(safeHref("javascript:alert(1)"), null);
  assert.equal(safeHref("data:text/html,hi"), null);
  assert.equal(safeHref("file:///etc/passwd"), null);
  assert.equal(safeHref("  "), null);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/safeHref.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Write the helper**

```ts
// frontend/src/lib/safeHref.ts
// Entry URLs come from imports and other clients. Only http(s) may become a clickable link.
export function safeHref(raw: string): string | null {
  const text = raw.trim();
  if (!text) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`;
  try {
    const url = new URL(candidate);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/safeHref.test.ts`
Expected: PASS.

- [ ] **Step 5: Use it in the vault page**

`VaultPage.tsx` around line 664: compute `const href = safeHref(selectedEntry.url);` before the JSX and render the `<a …>` only when `href` is non-null, with `href={href}` and `rel="noopener noreferrer"`. The Copy button keeps copying the raw `selectedEntry.url`.

- [ ] **Step 6: Anchor the cookie regex**

`api.ts` line 15:

```ts
  const csrfMatch = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
```

- [ ] **Step 7: Typecheck and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/lib/safeHref.ts frontend/src/lib/safeHref.test.ts frontend/src/pages/VaultPage.tsx frontend/src/lib/api.ts
git commit -m "open only http(s) entry links; anchor the CSRF cookie match"
```

---

### Task 7: Minimum master password length

**Files:**
- Create: `frontend/src/lib/masterPassword.ts`
- Create: `frontend/src/lib/masterPassword.test.ts`
- Modify: `frontend/src/App.tsx:131-136` (create-vault path)
- Modify: `frontend/src/pages/SecuritySettings.tsx:55-58, 213-229`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `MIN_MASTER_PASSWORD_LENGTH = 12`, `checkMasterPassword(password: string): string | null` (message when unacceptable).

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/masterPassword.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkMasterPassword, MIN_MASTER_PASSWORD_LENGTH } from "./masterPassword";

test("master password floor", () => {
  assert.equal(MIN_MASTER_PASSWORD_LENGTH, 12);
  assert.match(checkMasterPassword("short") ?? "", /12/);
  assert.match(checkMasterPassword("            ") ?? "", /space/);
  assert.equal(checkMasterPassword("correct horse battery"), null);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/masterPassword.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write the helper**

```ts
// frontend/src/lib/masterPassword.ts
// The master password is the only thing between a stolen envelope and the vault key
// (see vaultCrypto.ts). Length is the one rule that survives every composition policy.
export const MIN_MASTER_PASSWORD_LENGTH = 12;

export function checkMasterPassword(password: string): string | null {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters. A short sentence works well.`;
  if (password.trim().length === 0) return "A master password cannot be only spaces.";
  return null;
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/masterPassword.test.ts`
Expected: PASS.

- [ ] **Step 5: Enforce on vault creation**

`App.tsx`, inside `initVault` Case 1 right after `if (!masterPassword) { … return; }`:

```ts
        const problem = checkMasterPassword(masterPassword);
        if (problem) throw new Error(problem);
```

Import `checkMasterPassword` from `./lib/masterPassword`. The existing `catch` shows the message in the unlock dialog.

- [ ] **Step 6: Enforce on change**

`SecuritySettings.tsx` `handleChangePassword`, before the mismatch check:

```ts
    const problem = checkMasterPassword(newPassword);
    if (problem) { setError(problem); return; }
```

Add `autoComplete="new-password"` and `minLength={MIN_MASTER_PASSWORD_LENGTH}` to both password inputs, and `id`/`htmlFor` pairs (`new-master-password`, `confirm-master-password`). Import both symbols.

- [ ] **Step 7: Typecheck, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md` `vaultCrypto.ts` bullet: add one sentence `The client refuses master passwords under 12 characters (lib/masterPassword.ts) on create and change; the server never sees one so it cannot enforce this.`

```bash
git add frontend/src/lib/masterPassword.ts frontend/src/lib/masterPassword.test.ts frontend/src/App.tsx frontend/src/pages/SecuritySettings.tsx AGENTS.md
git commit -m "require 12-character master passwords"
```

---

### Task 8: Prove the current master password before changing it, generating a paper code or revealing the key

**Files:**
- Modify: `frontend/src/lib/vaultCrypto.ts` (append `verifyMasterPassword`)
- Modify: `frontend/src/lib/vaultCrypto.test.ts` (append)
- Modify: `frontend/src/pages/SecuritySettings.tsx:26-120, 200-312`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `verifyMasterPassword(envelopeJSON: string, password: string, vaultKey: Uint8Array): Promise<boolean>`.

- [ ] **Step 1: Write the failing test**

Append to `frontend/src/lib/vaultCrypto.test.ts` (reuse the file's existing import style):

```ts
test("verifyMasterPassword accepts only the password that wraps this key", async () => {
  const key = generateVaultMasterKey();
  const envelope = await wrapVaultKey(key, "correct horse battery");
  assert.equal(await verifyMasterPassword(envelope, "correct horse battery", key), true);
  assert.equal(await verifyMasterPassword(envelope, "wrong horse", key), false);
  assert.equal(await verifyMasterPassword(envelope, "correct horse battery", generateVaultMasterKey()), false);
  assert.equal(await verifyMasterPassword("not json", "correct horse battery", key), false);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/vaultCrypto.test.ts`
Expected: FAIL, `verifyMasterPassword` is not exported.

- [ ] **Step 3: Implement**

Append to `vaultCrypto.ts`:

```ts
// True only when password opens envelopeJSON to exactly vaultKey. Used as a step-up
// before re-wrapping or showing the key; nothing leaves the browser.
export async function verifyMasterPassword(envelopeJSON: string, password: string, vaultKey: Uint8Array): Promise<boolean> {
  try {
    const opened = await unwrapVaultKey(envelopeJSON, password);
    return bytesToHex(opened) === bytesToHex(vaultKey);
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/vaultCrypto.test.ts`
Expected: PASS.

- [ ] **Step 5: Add the current-password gate to the page**

In `SecuritySettings.tsx`:

State: `const [currentPassword, setCurrentPassword] = useState("");`

Helper inside the component:

```ts
  // Every action below either changes what protects the vault key or shows it.
  // Prove the current master password first; it never leaves the browser.
  const proveCurrentPassword = async (): Promise<boolean> => {
    const meta = await getJSON<{ passwordEnvelope?: string }>("/api/vault/metadata");
    if (!meta.passwordEnvelope) { setError("No master password envelope is stored for this vault."); return false; }
    if (!(await verifyMasterPassword(meta.passwordEnvelope, currentPassword, vaultKey))) {
      setError("The current master password is incorrect.");
      return false;
    }
    return true;
  };
```

Call it at the top of `handleChangePassword` (after `setBusy(true)`, inside the `try`), of `handleGeneratePaperRecovery` (same place), and of `handleRevealVaultKey` when revealing (not when hiding). After a successful change, `setCurrentPassword("")`.

Render one input above the three sections, inside the Master Password section:

```tsx
          <div className="input-group">
            <label className="input-label" htmlFor="current-master-password">Current Master Password</label>
            <input id="current-master-password" type="password" className="input" autoComplete="current-password"
              value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
            <p style={{ fontSize: "0.8rem", color: "var(--ink-muted)" }}>Needed to change the password, generate a paper code or show the vault key. Checked in this browser only.</p>
          </div>
```

Disable the three action buttons while `!currentPassword`.

Import `verifyMasterPassword` from `../lib/vaultCrypto`.

- [ ] **Step 6: Typecheck**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

- [ ] **Step 7: DOX**

`AGENTS.md` Authentication bullet "The master password is not a credential…" add: `Changing it, generating a paper code and showing the offline vault key each require the current master password, verified in the browser against the stored envelope (verifyMasterPassword).`

- [ ] **Step 8: Commit**

```bash
git add frontend/src/lib/vaultCrypto.ts frontend/src/lib/vaultCrypto.test.ts frontend/src/pages/SecuritySettings.tsx AGENTS.md
git commit -m "step up with the current master password before re-wrapping or revealing the key"
```

- [ ] **Step 9: End-of-phase verification (record every output in the PR)**

```bash
gofmt -l . ; go vet ./... ; go test -race ./...
cd frontend && npm test && npm run build && cd ..
go build -o ./kyvault-server ./cmd/server
docker build -t kyvault-server:latest .
```

Then the browser pass under the built CSP with a real KySignOn: sign in, create or unlock a vault, open Pair Extension / Mobile (QR renders), import a CSV, download an attachment, change the master password with a wrong then a right current password. Expected: zero CSP violations in the console, every action behaves as described. If a violation appears, widen only that one directive in `headers.go` and say so in the PR.

- [ ] **Step 10: Open the PR**

Use the `pull-request` skill. Title: `Phase 1 security fixes from the 2026-09-25 audit`. Body lists the eight findings, the verification output, and the CSP browser-check note.
