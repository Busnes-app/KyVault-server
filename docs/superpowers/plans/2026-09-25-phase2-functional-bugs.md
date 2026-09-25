# Phase 2: Functional Bugs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every functional bug from the 2026-09-25 audit's Phase 2 list so the web app behaves the way its own copy promises.

**Architecture:** Mostly frontend. New pure helpers live in `frontend/src/lib` with `node --test` coverage (`totp`, `vaultCrypto`, `format`, `clipboard`, `download`, `api`); page and component edits wire them in. One Go change: the SSO callback redirects user-facing failures to the login page with a fixed error code instead of a bare text response.

**Tech Stack:** React 18 + TypeScript, WebCrypto, `tsx --test`; Go stdlib `net/http`.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md` (Phase 2 list).

## Global Constraints

- Branch `fix/phase2-functional` from `fix/phase1-security` (Phase 1 is PR #56; rebase onto `master` once it merges). One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`.
- The server never receives a master password, paper code or vault key.
- No wire-format change to `POST /api/vault/upload`, `/api/devices/pairing/*`, `/api/sync/webhook`, `/scim/v2`.
- No new dependencies. Copy rules: sentences, no em-dashes, no "successfully".
- Every `confirm()`, `prompt()` and `alert()` stays as it is; replacing them is Phase 3. Do not add new ones.
- DOX: update `AGENTS.md` where a task changes a contract (Tasks 1, 2, 5, 6, 7 do).

## Review Focus

1. A TOTP URI with `algorithm=SHA256` or `SHA512` and `digits=8` must produce the RFC 6238 Appendix B code. Pinned: Task 1.
2. Unlocking with the paper code when a password envelope also exists must open the vault. Pinned: Task 2.
3. After a 409, "Overwrite server copy" must upload with the server's current version and "Reload server copy" must never upload. Pinned: Task 5.
4. A session that expires mid-use must land the user on the login page with a notice, not a raw "unauthorized" string, and the anonymous first load must not trigger that notice. Pinned: Task 7.
5. A copied password must be cleared from the clipboard after the timeout only if the clipboard still holds it, and copying something else in between must not be clobbered. Pinned: Task 11.

---

### Task 1: TOTP honours algorithm, digits and period

**Files:**
- Modify: `frontend/src/lib/totp.ts`
- Create: `frontend/src/lib/totp.test.ts`
- Modify: `AGENTS.md` (Child DOX Index, new bullet)

**Interfaces:**
- Produces: `generateTOTP(secretOrURI: string, timeStep = 30, digits = 6, algorithm: TotpAlgorithm = "SHA-1", nowMs = Date.now()): Promise<{ code: string; secondsRemaining: number }>` and `type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512"`. URI parameters override the defaults.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/totp.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateTOTP } from "./totp";

// RFC 4648 base32, only what the test needs to turn the RFC 6238 ASCII seeds into secrets.
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  if (bits.length % 5) out += alphabet[parseInt(bits.slice(-(bits.length % 5)).padEnd(5, "0"), 2)];
  return out;
}
const seed = (n: number) => base32(new TextEncoder().encode("1234567890".repeat(7).slice(0, n)));

// RFC 6238 Appendix B, T = 59 seconds, 8 digits.
test("RFC 6238 vectors for SHA-1, SHA-256 and SHA-512", async () => {
  const at = 59_000;
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&digits=8`, 30, 6, "SHA-1", at)).code, "94287082");
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(32)}&digits=8&algorithm=SHA256`, 30, 6, "SHA-1", at)).code, "46119246");
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(64)}&digits=8&algorithm=SHA512`, 30, 6, "SHA-1", at)).code, "90693936");
});

test("period and remaining seconds come from the URI", async () => {
  const res = await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&period=60`, 30, 6, "SHA-1", 59_000);
  assert.equal(res.secondsRemaining, 1);
  assert.equal(res.code.length, 6);
});

test("unknown algorithm falls back to SHA-1 and an empty secret yields dashes", async () => {
  const a = await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&algorithm=MD5`, 30, 6, "SHA-1", 59_000);
  const b = await generateTOTP(seed(20), 30, 6, "SHA-1", 59_000);
  assert.equal(a.code, b.code);
  assert.equal((await generateTOTP("", 30, 6, "SHA-1", 59_000)).code, "------");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/totp.test.ts`
Expected: FAIL (SHA-256 and SHA-512 vectors wrong; extra arguments ignored).

- [ ] **Step 3: Implement**

In `totp.ts` change the signature and the URI parsing:

```ts
export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

function parseAlgorithm(value: string | null): TotpAlgorithm | undefined {
  const v = (value ?? "").toUpperCase().replace("-", "");
  return v === "SHA1" ? "SHA-1" : v === "SHA256" ? "SHA-256" : v === "SHA512" ? "SHA-512" : undefined;
}

export async function generateTOTP(secretOrURI: string, timeStep = 30, digits = 6, algorithm: TotpAlgorithm = "SHA-1", nowMs = Date.now()): Promise<{ code: string; secondsRemaining: number }> {
  let secret = secretOrURI.trim();
  if (secret.startsWith("otpauth://")) {
    try {
      const url = new URL(secret);
      const s = url.searchParams.get("secret");
      if (s) secret = s;
      const d = parseInt(url.searchParams.get("digits") ?? "", 10);
      if (d >= 6 && d <= 10) digits = d;
      const p = parseInt(url.searchParams.get("period") ?? "", 10);
      if (p > 0) timeStep = p;
      algorithm = parseAlgorithm(url.searchParams.get("algorithm")) ?? algorithm;
    } catch {
      // Fallback to raw string
    }
  }
```

Replace `const epoch = Math.floor(Date.now() / 1000);` with `const epoch = Math.floor(nowMs / 1000);` and `{ name: "HMAC", hash: "SHA-1" }` with `{ name: "HMAC", hash: algorithm }`. The truncation code already handles any digest length.

- [ ] **Step 4: Run the test and the suite**

Run: `cd frontend && npx tsx --test src/lib/totp.test.ts && npm test && npm run build`
Expected: PASS.

- [ ] **Step 5: DOX and commit**

`AGENTS.md` Child DOX Index, add: `- \`frontend/src/lib/totp.ts\`: RFC 6238 TOTP in the browser. otpauth URIs may set secret, digits (6 to 10), period and algorithm (SHA1, SHA256, SHA512; anything else falls back to SHA-1). \`totp.test.ts\` pins the RFC 6238 Appendix B vectors for all three algorithms.`

```bash
git add frontend/src/lib/totp.ts frontend/src/lib/totp.test.ts AGENTS.md
git commit -m "honour TOTP algorithm, digits and period"
```

---

### Task 2: Paper code unlocks a vault that also has a password envelope

**Files:**
- Modify: `frontend/src/lib/vaultCrypto.ts` (append)
- Modify: `frontend/src/lib/vaultCrypto.test.ts` (append)
- Modify: `frontend/src/App.tsx:163-171`
- Modify: `AGENTS.md` Authentication bullet "Paper recovery unlocks the vault, not the site."

**Interfaces:**
- Produces: `unwrapVaultKeyFromEnvelopes(envelopes: Array<string | undefined>, secret: string): Promise<Uint8Array>`; throws `Error("Incorrect master password or paper code")` when no envelope opens, `Error("No key envelopes found on server metadata")` when none is given.

- [ ] **Step 1: Write the failing test**

Append to `vaultCrypto.test.ts`:

```ts
test("either envelope unlocks with its own secret", async () => {
  const key = generateVaultMasterKey();
  const password = await wrapVaultKey(key, "correct horse battery");
  const paper = await wrapVaultKey(key, "KYPASS-AAAA-BBBB-CCCC-DDDD");
  assert.equal(bytesToHex(await unwrapVaultKeyFromEnvelopes([password, paper], "correct horse battery")), bytesToHex(key));
  assert.equal(bytesToHex(await unwrapVaultKeyFromEnvelopes([password, paper], "KYPASS-AAAA-BBBB-CCCC-DDDD")), bytesToHex(key));
  assert.equal(bytesToHex(await unwrapVaultKeyFromEnvelopes([undefined, paper], "KYPASS-AAAA-BBBB-CCCC-DDDD")), bytesToHex(key));
  await assert.rejects(unwrapVaultKeyFromEnvelopes([password, paper], "wrong"), /Incorrect master password or paper code/);
  await assert.rejects(unwrapVaultKeyFromEnvelopes([undefined, undefined], "x"), /No key envelopes/);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/vaultCrypto.test.ts`
Expected: FAIL, not exported.

- [ ] **Step 3: Implement**

Append to `vaultCrypto.ts`:

```ts
// The unlock dialog accepts a master password or a paper code; each has its own envelope.
export async function unwrapVaultKeyFromEnvelopes(envelopes: Array<string | undefined>, secret: string): Promise<Uint8Array> {
  const present = envelopes.filter((e): e is string => !!e);
  if (present.length === 0) throw new Error("No key envelopes found on server metadata");
  for (const envelope of present) {
    try { return await unwrapVaultKey(envelope, secret); } catch { /* try the next envelope */ }
  }
  throw new Error("Incorrect master password or paper code");
}
```

In `App.tsx` replace the block

```ts
        if (meta.passwordEnvelope) {
          key = await unwrapVaultKey(meta.passwordEnvelope, masterPassword);
        } else if (meta.recoveryEnvelope) {
          key = await unwrapVaultKey(meta.recoveryEnvelope, masterPassword);
        } else {
          throw new Error("No key envelopes found on server metadata");
        }
```

with

```ts
        key = await unwrapVaultKeyFromEnvelopes([meta.passwordEnvelope, meta.recoveryEnvelope], masterPassword);
```

and update the import (drop `unwrapVaultKey` if unused).

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md`: after "Paper recovery unlocks the vault, not the site." add "The unlock dialog tries the password envelope and then the recovery envelope with whatever was typed (`unwrapVaultKeyFromEnvelopes`)."

```bash
git add frontend/src/lib/vaultCrypto.ts frontend/src/lib/vaultCrypto.test.ts frontend/src/App.tsx AGENTS.md
git commit -m "let the paper code unlock a vault that also has a password envelope"
```

---

### Task 3: Attachment "remove from history" checkbox resets per entry

**Files:**
- Modify: `frontend/src/components/EntryAttachments.tsx:18-24`

- [ ] **Step 1: Reset the checkbox in the per-entry effect**

In the `useEffect` keyed on `[vault, entryUuid, readOnly]`, add `setRemoveFromHistory(false);` after `setError("");`.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS. (No component harness exists; the change is a single state reset.)

```bash
git add frontend/src/components/EntryAttachments.tsx
git commit -m "reset the attachment history checkbox when the entry changes"
```

---

### Task 4: CSV import failure keeps partial changes saveable and reports inline

**Files:**
- Modify: `frontend/src/components/CsvImportModal.tsx:29-32, 118-137`
- Modify: `frontend/src/pages/VaultPage.tsx:750-765` and the import banner

**Interfaces:**
- Produces: new prop `onImportFailed: (message: string) => void` on `CsvImportModal`.

- [ ] **Step 1: Replace the alert with a callback**

In `CsvImportModal.tsx` add `onImportFailed: (message: string) => void;` to `Props` and destructure it. Replace the `catch` in `handleExecuteImport`:

```ts
    } catch (err: unknown) {
      // Entries and folders created before the failure are already in the vault; the
      // caller schedules a save so they are not lost with the next unrelated edit.
      onImportFailed(err instanceof Error ? err.message : String(err));
      onClose();
    } finally {
```

- [ ] **Step 2: Handle it in VaultPage**

Add state `const [importError, setImportError] = useState<string | null>(null);`. Pass to the modal:

```tsx
          onImportFailed={(message) => {
            onChanged();
            refreshVaultData();
            setImportMessage(null);
            setImportError(`Import stopped: ${message} Entries added before the failure are kept and saved automatically.`);
          }}
```

In `onImportComplete` add `setImportError(null);` and change the success copy from "Successfully imported" to "Imported". Render `importError` next to `importMessage` with `role="alert"`, `background: "var(--danger-soft)"`, `color: "var(--danger)"` and the same dismiss button.

- [ ] **Step 3: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/components/CsvImportModal.tsx frontend/src/pages/VaultPage.tsx
git commit -m "keep and save partial CSV imports; report failures inline"
```

---

### Task 5: Save conflicts offer overwrite or reload; network failures retry when back online

**Files:**
- Modify: `frontend/src/lib/vaultSave.ts`
- Modify: `frontend/src/lib/vaultSave.test.ts` (append)
- Modify: `frontend/src/pages/VaultPage.tsx` save status block (around the "Retry Save" button)
- Modify: `AGENTS.md` `vaultSave.ts` bullet

**Interfaces:**
- Produces: `SaveState` error variant gains `conflict?: boolean`; `VaultSaveQueue.save(options?: { overwrite?: boolean })`. With `overwrite`, the queue fetches `GET /api/vault/metadata` and uploads with that version. Without it, a conflict stays an error. A non-409 failure registers a one-shot `window` `online` listener that calls `save()`.

- [ ] **Step 1: Write the failing tests**

Append to `vaultSave.test.ts`:

```ts
test("a conflict is flagged and overwrite uploads with the server's current version", async (t) => {
  browserCookie(t);
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(5));
  const queue = new VaultSaveQueue(vault, 2);
  const seen: string[] = [];
  t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options: RequestInit = {}) => {
    const path = String(url);
    if (path.endsWith("/api/vault/metadata")) return Response.json({ version: 7 });
    seen.push(new Headers(options.headers).get("If-Match") ?? "");
    return seen.length === 1 ? new Response("conflict", { status: 409 }) : Response.json({ metadata: { version: 8 } });
  });
  const done = settled(queue);
  queue.changed();
  void queue.save();
  const result = await done;
  assert.equal(result.kind, "error");
  assert.equal(result.kind === "error" && result.conflict, true);
  await queue.save();
  assert.equal(queue.getSnapshot().kind, "error", "plain retry must not overwrite");
  await queue.save({ overwrite: true });
  assert.deepEqual(queue.getSnapshot(), { kind: "saved", version: 8 });
  assert.deepEqual(seen, ['"2"', '"7"']);
});

test("a network failure retries once when the browser comes back online", async (t) => {
  browserCookie(t);
  const listeners: Array<() => void> = [];
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    addEventListener: (type: string, fn: () => void) => { if (type === "online") listeners.push(fn); },
    removeEventListener: () => {},
  } });
  t.after(() => { Reflect.deleteProperty(globalThis, "window"); });
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(6));
  const queue = new VaultSaveQueue(vault, 1);
  let attempts = 0;
  t.mock.method(globalThis, "fetch", async () => {
    attempts++;
    if (attempts === 1) throw new TypeError("Network unavailable");
    return Response.json({ metadata: { version: 2 } });
  });
  const failed = settled(queue);
  queue.changed();
  void queue.save();
  assert.equal((await failed).kind, "error");
  assert.equal(listeners.length, 1);
  const recovered = settled(queue);
  listeners[0]();
  assert.deepEqual(await recovered, { kind: "saved", version: 2 });
});
```

- [ ] **Step 2: Run to see them fail**

Run: `cd frontend && npx tsx --test src/lib/vaultSave.test.ts`
Expected: FAIL (`conflict` undefined; no listener registered).

- [ ] **Step 3: Implement**

In `vaultSave.ts`:

```ts
export type SaveState =
  | { kind: "saved"; version: number }
  | { kind: "saving"; version: number }
  | { kind: "error"; version: number; message: string; conflict?: boolean };
```

Add to the class a field `private onlineRetry: (() => void) | undefined;` and change `save`:

```ts
  save = async (options: { overwrite?: boolean } = {}): Promise<void> => {
    clearTimeout(this.timer);
    this.clearOnlineRetry();
    if (this.controller.signal.aborted || this.running || this.revision === this.savedRevision) return;
    if (this.state.kind === "error" && this.state.conflict && !options.overwrite) return;
    this.running = true;
    this.publish({ kind: "saving", version: this.state.version });
    try {
      if (options.overwrite) {
        // The server's copy stays in version history; ours becomes the head.
        const meta = await requestJSON<{ version?: unknown }>("/api/vault/metadata", { method: "GET", signal: this.controller.signal });
        if (typeof meta.version !== "number" || !Number.isSafeInteger(meta.version)) throw new Error("The server did not report its vault version.");
        this.state = { ...this.state, version: meta.version };
      }
      while (this.savedRevision < this.revision) {
        ...unchanged...
      }
    } catch (err) {
      if (this.controller.signal.aborted) return;
      const conflict = err instanceof HttpError && err.status === 409;
      if (!conflict && typeof window !== "undefined") {
        this.onlineRetry = () => { this.clearOnlineRetry(); void this.save(); };
        window.addEventListener("online", this.onlineRetry);
      }
      this.publish({ kind: "error", version: this.state.version, conflict, message: conflict
        ? "A newer vault exists on the server. Overwrite it with this copy (the server copy stays in Version History) or reload the server copy and lose these edits."
        : toErrorMessage(err, "Unable to save vault. Your edits are still here.") });
    } finally {
      this.running = false;
    }
  };

  private clearOnlineRetry() {
    if (this.onlineRetry && typeof window !== "undefined") window.removeEventListener("online", this.onlineRetry);
    this.onlineRetry = undefined;
  }
```

Call `this.clearOnlineRetry()` in `discard` too.

- [ ] **Step 4: Wire the buttons**

In `VaultPage.tsx` the error block: when `saveState.conflict`, render "Overwrite server copy" (`onClick={() => void onSave({ overwrite: true })}`, `btn-danger`) and "Reload server copy" (`onClick={() => { if (confirm("Discard the unsaved edits in this tab and reload the server copy?")) void onReload(); }}`); otherwise keep "Retry Save". Change the `onSave` prop type to `(options?: { overwrite?: boolean }) => Promise<void>` in `VaultPage` `Props` and pass `saveQueue.save` from `App.tsx` unchanged (its signature now matches).

- [ ] **Step 5: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md` `vaultSave.ts` bullet: replace "Failures (including 409) remain unsaved and require explicit retry." with "Failures remain unsaved. A network failure retries once when the browser reports online. A 409 is flagged as a conflict: Retry does nothing, Overwrite server copy re-reads the server version and uploads over it (the server copy stays in history), Reload server copy discards local edits."

```bash
git add frontend/src/lib/vaultSave.ts frontend/src/lib/vaultSave.test.ts frontend/src/pages/VaultPage.tsx frontend/src/App.tsx AGENTS.md
git commit -m "offer overwrite or reload on save conflicts; retry when back online"
```

---

### Task 6: Login page tells the truth about what failed

**Files:**
- Modify: `internal/api/auth_handlers.go:224-268`
- Modify: `internal/api/sso_callback_test.go:216-219, 252-255`; `internal/api/sso_logout_test.go:235`
- Modify: `frontend/src/pages/LoginPage.tsx`
- Modify: `AGENTS.md` Authentication

**Interfaces:**
- Produces: user-facing callback failures redirect (302) to `/?sso_error=<code>` with `code` in `not_linked | deactivated | signed_out`; no session cookie is set. Verification, exchange and server failures keep their existing status codes. `LoginPage` shows a message per code and distinguishes an unreachable backend from a disabled SSO.

- [ ] **Step 1: Update the Go tests first**

In `sso_callback_test.go` both `rec.Code != http.StatusForbidden` checks become:

```go
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=not_linked" {
			t.Fatalf("callback = %d %q, want 302 to /?sso_error=not_linked", rec.Code, rec.Header().Get("Location"))
		}
```

In `sso_logout_test.go:235` the fenced login check becomes `rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=signed_out" || hasSessionCookie(rec)`.

Add to `sso_callback_test.go`:

```go
func TestSSOCallbackDeactivatedAccountRedirectsToLogin(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.CreateSSOUser("dora", users.RoleUser, "dora-sub", "dora", "dora@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.users.CreateSSOUser("admin", users.RoleAdmin, "admin-sub", "admin", "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := srv.users.Deactivate(u.ID); err != nil {
		t.Fatal(err)
	}
	idp := mockIdP(t, map[string]any{"sub": "dora-sub", "preferred_username": "dora"})
	srv.oidcHTTP = idp.Client()
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app"}); err != nil {
		t.Fatal(err)
	}
	rec := driveSSOCallback(t, srv)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=deactivated" || hasSessionCookie(rec) {
		t.Fatalf("callback = %d %q cookie=%v", rec.Code, rec.Header().Get("Location"), hasSessionCookie(rec))
	}
}
```

Run: `go test ./internal/api -run 'TestSSOCallback|TestSSOLogout' -v`
Expected: FAIL (403 instead of 302).

- [ ] **Step 2: Implement the redirects**

In `auth_handlers.go` add:

```go
// loginFailure sends the browser back to the login page with a fixed code the page can
// explain. The codes are an enum, never free text from the request.
func loginFailure(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/?sso_error="+code, http.StatusFound)
}
```

Replace `http.Error(w, "Access denied: SSO identity not linked to any KyVault account.", http.StatusForbidden)` with `loginFailure(w, r, "not_linked")`, `http.Error(w, "Account deactivated", http.StatusForbidden)` with `loginFailure(w, r, "deactivated")`, and the fenced branch's `http.Error(w, "signed out by KySignOn; sign in again", http.StatusForbidden)` with `loginFailure(w, r, "signed_out")` (keep its `s.record` line).

Run: `go test -race ./internal/api`
Expected: PASS.

- [ ] **Step 3: Rewrite the login page state**

In `LoginPage.tsx`:

```tsx
type SsoState = "loading" | "ready" | "disabled" | "unreachable";
const ERRORS: Record<string, string> = {
  not_linked: "Your KySignOn identity is not linked to a KyVault account. Ask your administrator to provision it.",
  deactivated: "This account is deactivated. Ask your administrator to reactivate it.",
  signed_out: "KySignOn signed you out. Sign in again.",
};

export function LoginPage({ notice }: { notice?: string }) {
  const [sso, setSso] = useState<SsoState>("loading");
  const ssoError = ERRORS[new URLSearchParams(window.location.search).get("sso_error") ?? ""];
  const load = () => {
    setSso("loading");
    getJSON<{ enabled: boolean }>("/api/auth/sso-config")
      .then((res) => setSso(res.enabled ? "ready" : "disabled"))
      .catch(() => setSso("unreachable"));
  };
  useEffect(load, []);
```

Render: `notice` or `ssoError` in a status box above the button (danger style for `ssoError`, neutral for `notice`). The existing red box copy applies only to `sso === "disabled"`. For `sso === "unreachable"` show: "KyVault's server could not be reached. Your passwords are not lost; any copy of your vault opens in a standard KeePass client." with a "Retry" button calling `load`. The sign-in control is the link only when `sso === "ready"`; otherwise the disabled button (label "Checking sign-in…" while loading).

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md` Authentication: add "User-facing callback failures (identity not linked, account deactivated, login fenced by a logout) redirect to `/?sso_error=<code>`; the login page explains the code. Token and configuration failures keep their status codes."

```bash
git add internal/api/auth_handlers.go internal/api/sso_callback_test.go internal/api/sso_logout_test.go frontend/src/pages/LoginPage.tsx AGENTS.md
git commit -m "explain SSO login failures on the login page; distinguish an unreachable server"
```

---

### Task 7: An expired session returns to the login page with a notice

**Files:**
- Modify: `frontend/src/lib/api.ts:26-29`
- Create: `frontend/src/lib/api.test.ts`
- Modify: `frontend/src/App.tsx` (listener, `sessionNotice`, `LoginPage` prop)
- Modify: `AGENTS.md` Authentication

**Interfaces:**
- Produces: `api.ts` dispatches `new Event("kyvault:unauthorized")` on `window` for any 401 except `GET /api/auth/me`; `App` listens while a user is signed in.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/api.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { getJSON, HttpError } from "./api";

test("a 401 dispatches kyvault:unauthorized except for the session probe", async (t) => {
  const events: string[] = [];
  Object.defineProperty(globalThis, "window", { configurable: true, value: { dispatchEvent: (e: Event) => { events.push(e.type); return true; } } });
  Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
  t.after(() => { Reflect.deleteProperty(globalThis, "window"); Reflect.deleteProperty(globalThis, "document"); });
  t.mock.method(globalThis, "fetch", async () => new Response("unauthorized", { status: 401 }));
  await assert.rejects(getJSON("/api/vault/metadata"), HttpError);
  await assert.rejects(getJSON("/api/auth/me"), HttpError);
  assert.deepEqual(events, ["kyvault:unauthorized"]);
});
```

Run: `cd frontend && npx tsx --test src/lib/api.test.ts`
Expected: FAIL (no event).

- [ ] **Step 2: Implement**

In `api.ts` inside `request`, before throwing:

```ts
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/auth/me" && typeof window !== "undefined") {
      window.dispatchEvent(new Event("kyvault:unauthorized"));
    }
    const text = await res.text();
    throw new HttpError(res.status, text || res.statusText);
  }
```

In `App.tsx` add `const [sessionNotice, setSessionNotice] = useState("");` and:

```ts
  useEffect(() => {
    if (!user) return;
    const ended = () => { closeVault(); setUser(null); setSessionNotice("Your session ended. Sign in again."); };
    window.addEventListener("kyvault:unauthorized", ended);
    return () => window.removeEventListener("kyvault:unauthorized", ended);
  }, [user?.id]);
```

Render `<LoginPage notice={sessionNotice} />`. Clear the notice inside `checkAuth` when a user is found.

- [ ] **Step 3: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md` Authentication: add "A 401 from any API call except the session probe raises `kyvault:unauthorized`; the app locks the vault and shows the login page with a notice."

```bash
git add frontend/src/lib/api.ts frontend/src/lib/api.test.ts frontend/src/App.tsx AGENTS.md
git commit -m "return to the login page when the session ends"
```

---

### Task 8: Audit integrity badge has three states and reports write failures

**Files:**
- Modify: `frontend/src/pages/AdminPanel.tsx:40, 46-60, 332-340`

- [ ] **Step 1: Implement**

Replace the state:

```ts
type AuditVerify = { valid: boolean; writeFailures: number; error: string };
const [auditVerify, setAuditVerify] = useState<AuditVerify | "loading" | "unavailable">("loading");
```

In `loadData`, type the verify request as `getJSON<AuditVerify>("/api/audit/verify")`, set `setAuditVerify(v.value)` on fulfilment and `setAuditVerify("unavailable")` on rejection.

Badge:

```tsx
{auditVerify === "loading" ? <span className="badge">Checking chain…</span>
 : auditVerify === "unavailable" ? <span className="badge">Could not verify</span>
 : auditVerify.valid && auditVerify.writeFailures === 0 ? <span className="badge badge-green" ...><ShieldCheck size={12} /> Chain Verified</span>
 : <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }} title={auditVerify.error || undefined}><AlertCircle size={12} /> {auditVerify.valid ? `${auditVerify.writeFailures} audit writes failed` : "Integrity Warning"}</span>}
```

Guard `log.hash.slice(...)` with `(log.hash ?? "").slice(...)`.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/pages/AdminPanel.tsx
git commit -m "show audit verification as loading, unavailable, verified or failed"
```

---

### Task 9: Backup panel state is honest

**Files:**
- Create: `frontend/src/lib/format.ts`
- Create: `frontend/src/lib/format.test.ts`
- Modify: `frontend/src/components/AdminBackup.tsx`

**Interfaces:**
- Produces: `formatInterval(seconds: number): string` ("Off", "Every 15 minutes", "Hourly", "Every 6 hours", "Daily", "Every 3 days") and `formatWhen(iso: string | undefined): string` ("Unknown" for missing or invalid input, otherwise `toLocaleString()`).

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/format.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatInterval, formatWhen } from "./format";

test("intervals read as humans say them", () => {
  assert.equal(formatInterval(0), "Off");
  assert.equal(formatInterval(900), "Every 15 minutes");
  assert.equal(formatInterval(3600), "Hourly");
  assert.equal(formatInterval(21600), "Every 6 hours");
  assert.equal(formatInterval(86400), "Daily");
  assert.equal(formatInterval(259200), "Every 3 days");
  assert.equal(formatInterval(Number.NaN), "Unknown");
});

test("timestamps never render Invalid Date", () => {
  assert.equal(formatWhen(undefined), "Unknown");
  assert.equal(formatWhen("not a date"), "Unknown");
  assert.equal(formatWhen("2026-09-25T12:00:00Z"), new Date("2026-09-25T12:00:00Z").toLocaleString());
});
```

Run: `cd frontend && npx tsx --test src/lib/format.test.ts`
Expected: FAIL.

- [ ] **Step 2: Implement**

```ts
// frontend/src/lib/format.ts
export function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "Unknown";
  if (seconds === 0) return "Off";
  const minutes = Math.round(seconds / 60);
  if (minutes % 1440 === 0) return minutes === 1440 ? "Daily" : `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? "Hourly" : `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

export function formatWhen(iso: string | undefined): string {
  if (!iso) return "Unknown";
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? "Unknown" : t.toLocaleString();
}
```

- [ ] **Step 3: Fix the panel**

In `AdminBackup.tsx`:
- Replace `intervalMinutes` number state with `intervalInput` string state (`useState("1440")`) and `scheduleDirty` boolean. `refresh` sets `intervalInput` only when `!scheduleDirty`: `if (!scheduleDirty) setIntervalInput(Number.isFinite(next.intervalSec) ? String(Math.round(next.intervalSec / 60)) : "")`. The input's `onChange` sets both. Submit: `const minutes = Number(intervalInput); if (intervalInput.trim() === "" || !Number.isInteger(minutes) || (minutes > 0 && minutes < 15)) { setError("Enter 0 to turn the schedule off, or 15 or more minutes."); return; }` then PUT and `setScheduleDirty(false)`.
- `act` also does `setDrill(undefined)`.
- `runDrill`: `result.passed ? setMessage("Restore drill passed.") : setError("Restore drill found a problem. See the checks below.")`.
- Status line: `!status ? "Loading…" : status.error ? "Recovery configuration needs attention" : !status.keyHealthy ? "No recovery key" : status.paired ? "Paired and healthy" : "Key pinned; remote not paired"`.
- Schedule line uses `formatInterval(status.intervalSec)`; every `new Date(x).toLocaleString()` in the file becomes `formatWhen(x)`.
- "Run restore drill" button gets the same `disabled` condition as "Back up now" (busy or `!status?.keyHealthy`).
- Replace "KyRecovery pairing pinned successfully." with "KyRecovery pairing pinned."

- [ ] **Step 4: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/lib/format.ts frontend/src/lib/format.test.ts frontend/src/components/AdminBackup.tsx
git commit -m "make the backup panel state honest"
```

---

### Task 10: Pairing modal: scannable QR, server-driven countdown, recoverable errors

**Files:**
- Modify: `frontend/src/components/DevicePairingModal.tsx`

- [ ] **Step 1: Implement**

- Remove the `secret` state; keep `res.secret` as a local inside `fetchPairingCode`.
- Add `const [expiresAt, setExpiresAt] = useState<number | null>(null);`. In `fetchPairingCode`: `setPin(""); setQrUrl(""); setExpiresAt(null);` first, then after the response `setExpiresAt(new Date(res.expiresAt).getTime())`.
- Replace the `secondsRemaining` state and its effect with a derived value from a 1-second ticker:

```ts
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const secondsRemaining = expiresAt === null ? null : Math.max(0, Math.ceil((expiresAt - now) / 1000));
```

- QR colours: `dark: "#111111", light: "#ffffff"` and the wrapping div background `#ffffff` (a QR must be dark on light regardless of theme).
- Render: `error` branch gains a "Try again" button calling `fetchPairingCode`; `secondsRemaining === null` renders "Requesting a pairing code…"; `> 0` renders the code; `0` renders the expired branch.
- `copyPIN` uses the shared clipboard helper once Task 11 lands; for now `await navigator.clipboard.writeText(pin)` inside a try/catch that sets `error` on failure.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/components/DevicePairingModal.tsx
git commit -m "pairing modal: scannable QR, server expiry, retry on error"
```

---

### Task 11: Clipboard copies are confirmed and secrets are cleared

**Files:**
- Create: `frontend/src/lib/clipboard.ts`
- Create: `frontend/src/lib/clipboard.test.ts`
- Modify: `frontend/src/pages/VaultPage.tsx:166-171`, `frontend/src/components/PasswordGenerator.tsx:43`, `frontend/src/components/DevicePairingModal.tsx` (`copyPIN`)
- Modify: `AGENTS.md` (Child DOX Index, new bullet)

**Interfaces:**
- Produces: `copyText(text: string, options?: { clearAfterMs?: number; clipboard?: Clipboard; setTimer?: typeof setTimeout }): Promise<boolean>`. Resolves false when the write is rejected. With `clearAfterMs`, after the delay it reads the clipboard; if it still equals `text` it writes an empty string. If reading is not permitted (Firefox), it writes the empty string only if no later `copyText` call has happened.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/clipboard.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyText } from "./clipboard";

function fakeClipboard(opts: { readable: boolean }) {
  let value = "";
  return {
    value: () => value,
    clipboard: {
      writeText: async (t: string) => { value = t; },
      readText: async () => { if (!opts.readable) throw new Error("denied"); return value; },
    } as unknown as Clipboard,
  };
}

test("clears a secret after the delay only if the clipboard still holds it", async () => {
  const timers: Array<() => void> = [];
  const setTimer = ((fn: () => void) => { timers.push(fn); return 0; }) as unknown as typeof setTimeout;
  const fake = fakeClipboard({ readable: true });
  assert.equal(await copyText("hunter2", { clearAfterMs: 30_000, clipboard: fake.clipboard, setTimer }), true);
  await fake.clipboard.writeText("something else");
  timers[0]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "something else");
  await copyText("hunter3", { clearAfterMs: 30_000, clipboard: fake.clipboard, setTimer });
  timers[1]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "");
});

test("without read permission it clears unless a newer copy happened", async () => {
  const timers: Array<() => void> = [];
  const setTimer = ((fn: () => void) => { timers.push(fn); return 0; }) as unknown as typeof setTimeout;
  const fake = fakeClipboard({ readable: false });
  await copyText("one", { clearAfterMs: 1, clipboard: fake.clipboard, setTimer });
  await copyText("two", { clearAfterMs: 1, clipboard: fake.clipboard, setTimer });
  timers[0]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "two");
  timers[1]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "");
});

test("a rejected write reports false", async () => {
  const clipboard = { writeText: async () => { throw new Error("no"); } } as unknown as Clipboard;
  assert.equal(await copyText("x", { clipboard }), false);
});
```

Run: `cd frontend && npx tsx --test src/lib/clipboard.test.ts`
Expected: FAIL.

- [ ] **Step 2: Implement**

```ts
// frontend/src/lib/clipboard.ts
// Secrets leave the clipboard after a delay. Reading the clipboard back needs a permission
// some browsers refuse; then we only clear if nothing newer was copied through this helper.
let generation = 0;

export async function copyText(text: string, options: { clearAfterMs?: number; clipboard?: Clipboard; setTimer?: typeof setTimeout } = {}): Promise<boolean> {
  const clipboard = options.clipboard ?? navigator.clipboard;
  const setTimer = options.setTimer ?? setTimeout;
  try { await clipboard.writeText(text); } catch { return false; }
  const mine = ++generation;
  if (options.clearAfterMs) {
    setTimer(() => { void (async () => {
      let current: string | undefined;
      try { current = await clipboard.readText(); } catch { current = undefined; }
      const stillOurs = current === undefined ? mine === generation : current === text;
      if (stillOurs) { try { await clipboard.writeText(""); } catch { /* nothing to clear */ } }
    })(); }, options.clearAfterMs);
  }
  return true;
}

export const SECRET_CLIPBOARD_MS = 30_000;
```

- [ ] **Step 3: Use it**

`VaultPage.tsx`:

```ts
  const copyToClipboard = async (text: string, field: string) => {
    const secret = field === "pass" || field === "totp";
    const ok = await copyText(text, secret ? { clearAfterMs: SECRET_CLIPBOARD_MS } : {});
    setCopiedField(ok ? field : null);
    if (!ok) setImportError("Could not copy. Your browser blocked clipboard access.");
    if (ok) setTimeout(() => setCopiedField(null), 2000);
  };
```

`PasswordGenerator.tsx`: `copyText(generated, { clearAfterMs: SECRET_CLIPBOARD_MS })` and set `copied` only on success. `DevicePairingModal.tsx`: `copyText(pin)` and set `copied` only on success. Under the password and TOTP copy buttons show the hint "Cleared from the clipboard after 30 seconds." once per field (small muted text next to the green tick).

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

`AGENTS.md` Child DOX Index add: `- \`frontend/src/lib/clipboard.ts\`: every copy goes through \`copyText\`; passwords, TOTP codes and generated passwords are cleared after 30 seconds if the clipboard still holds them (or, where reading is refused, if nothing newer was copied through the helper). \`clipboard.test.ts\` covers both.`

```bash
git add frontend/src/lib/clipboard.ts frontend/src/lib/clipboard.test.ts frontend/src/pages/VaultPage.tsx frontend/src/components/PasswordGenerator.tsx frontend/src/components/DevicePairingModal.tsx AGENTS.md
git commit -m "confirm clipboard copies and clear secrets after 30 seconds"
```

---

### Task 12: One download helper that works in every browser

**Files:**
- Create: `frontend/src/lib/download.ts`
- Modify: `frontend/src/App.tsx` (`handleExportKdbx`), `frontend/src/components/EntryAttachments.tsx` (`download`), `frontend/src/components/AdminBackup.tsx` (`download`)

- [ ] **Step 1: Implement**

```ts
// frontend/src/lib/download.ts
// Firefox and Safari can cancel a download whose object URL is revoked in the same tick.
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
```

Replace the three inline anchor sequences with `downloadBlob(new Blob([binary], { type: "application/x-keepass2" }), \`${user?.username || "vault"}.kdbx\`)`, `downloadBlob(new Blob([vault.getAttachment(entryUuid, name)], { type: "application/octet-stream" }), safeName)` and `downloadBlob(blob, "kyvault.kycap")`.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS. (DOM glue; no Node harness. Confirm one download by hand in the end-of-phase browser pass.)

```bash
git add frontend/src/lib/download.ts frontend/src/App.tsx frontend/src/components/EntryAttachments.tsx frontend/src/components/AdminBackup.tsx
git commit -m "share one download helper that survives Firefox and Safari"
```

---

### Task 13: Favicons, duplicate icon, dev proxy

**Files:**
- Modify: `frontend/index.html`
- Delete: `frontend/public/app-icon.png` (byte-identical to `logo.png`, no references)
- Modify: `frontend/vite.config.ts`

- [ ] **Step 1: Implement**

`index.html` head: replace the single icon link with

```html
    <link rel="icon" href="/favicon.ico" sizes="any" />
    <link rel="icon" type="image/png" href="/favicon.png" />
    <link rel="apple-touch-icon" href="/logo.png" />
```

`git rm frontend/public/app-icon.png` after `grep -rn app-icon frontend/src frontend/index.html` returns nothing.

`vite.config.ts` proxy: add `"/scim": { target: "http://localhost:5877", changeOrigin: true }`.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm run build && ls dist/favicon.ico dist/favicon.png`
Expected: build ok, both files present.

```bash
git add frontend/index.html frontend/vite.config.ts
git rm -q frontend/public/app-icon.png
git commit -m "wire the favicons, drop the duplicate icon, proxy /scim in dev"
```

---

### Task 14: Locked draft zeroes its plaintext and says what it holds

**Files:**
- Modify: `frontend/src/lib/lockedDraft.ts:1, 28-37`
- Modify: `frontend/src/lib/lockedDraft.test.ts` (append)

- [ ] **Step 1: Write the failing test**

Append (reuse the file's existing imports and any helper it has for building a draft):

```ts
test("openDraft returns copies and does not keep the decrypted buffer", async () => {
  const key = new Uint8Array(32).fill(1);
  const binary = new Uint8Array([9, 8, 7]).buffer;
  const draft = await sealDraft(binary, { version: 3, dirty: true, entry: null }, key, "acct");
  const opened = await openDraft(draft, key, "acct");
  assert.deepEqual(new Uint8Array(opened.binary), new Uint8Array([9, 8, 7]));
  assert.equal(opened.metadata.version, 3);
  // The returned buffers are slices, so zeroing the internal plaintext cannot touch them.
  assert.notEqual(opened.binary.byteLength, 0);
});
```

Run: `cd frontend && npx tsx --test src/lib/lockedDraft.test.ts`
Expected: PASS already (it pins behaviour); keep it as the regression guard for the next step.

- [ ] **Step 2: Implement**

Header comment becomes: `// A per-tab encrypted checkpoint of the vault bytes and unapplied entry fields (which can include an entry password). It never contains the master password or the vault key.`

In `openDraft`, wrap the body after `decrypt` in `try { ... } finally { new Uint8Array(plain).fill(0); }` so the returned `binary` (a `slice`, so a copy) and `metadata` survive and the working buffer is zeroed.

- [ ] **Step 3: Verify and commit**

Run: `cd frontend && npx tsx --test src/lib/lockedDraft.test.ts && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/lib/lockedDraft.ts frontend/src/lib/lockedDraft.test.ts
git commit -m "zero the decrypted draft buffer; describe what the checkpoint holds"
```

---

### Task 15: Stale messages, wrong loading text, unsafe dates, swallowed device errors

**Files:**
- Modify: `frontend/src/components/HistoryModal.tsx:78-90, 108-118, 138`
- Modify: `frontend/src/pages/SecuritySettings.tsx:41-46, 172-181, 444`

- [ ] **Step 1: HistoryModal**

- `discardConflict` starts with `setMessage(""); setError("");` after the confirm.
- Both tab buttons' `onClick` also call `setMessage(""); setError("");`.
- Line 138: `Loading {activeTab === "history" ? "snapshots" : "conflicts"}…`.
- The error paragraph gets a "Retry" button that calls `loadData`.

- [ ] **Step 2: SecuritySettings**

- `loadDevices` catch: `setError(toErrorMessage(err, "Could not load paired devices."))` instead of swallowing.
- `handleRevokeDevice`: add `const [revoking, setRevoking] = useState<string | null>(null);` guard: return if `revoking`; set it to `id` for the duration; `setError(""); setMessage("");` before the request; the Revoke button `disabled={revoking !== null}`.
- Line 444: `Last active: {formatWhen(d.lastSeenAt)}` importing `formatWhen` from `../lib/format`.

- [ ] **Step 3: Verify and commit**

Run: `cd frontend && npm test && npm run build`
Expected: PASS.

```bash
git add frontend/src/components/HistoryModal.tsx frontend/src/pages/SecuritySettings.tsx
git commit -m "clear stale notices, fix loading text, guard device revoke, format dates safely"
```

- [ ] **Step 4: End-of-phase verification (record in the PR)**

```bash
gofmt -l . ; go vet ./... ; go test -race ./...
cd frontend && npm test && npm run build && cd ..
go build -o ./kyvault-server ./cmd/server
```

Browser pass with the built bundle: login page with `?sso_error=not_linked` shows the message; with the backend stopped shows "could not be reached" and Retry works. With a KySignOn session: TOTP entry with `algorithm=SHA256` matches an authenticator app; copy a password and confirm the clipboard is empty 30 seconds later; download an attachment in Firefox; pairing modal countdown matches the server's expiry. Anything that needs KySignOn and cannot run is listed as unproven in the PR.

- [ ] **Step 5: Open the PR**

Use the `pull-request` skill. Title: `Phase 2 functional fixes from the 2026-09-25 audit`. Base: `fix/phase1-security` until PR #56 merges, then retarget to `master`.
