# Phase 3a: UI Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the web app the three things every later UI fix needs: a way to run it without KySignOn, one dialog system instead of native prompts and ad-hoc overlays, and routes and a layout that survive a refresh and a phone. Also stop the audit test flake.

**Architecture:** A Vite-only mock of the API (`frontend/mock/`) makes the app runnable and screenshot-able locally. A `Dialog` component on the native `<dialog>` element and a `DialogHost` context replace every `modal-overlay` div and every `confirm`/`prompt`/`alert`. A hash router (`lib/route.ts`) drives the top tabs, admin tabs and the selected entry. CSS media queries plus a pane state make the three-pane vault usable under 900px.

**Tech Stack:** React 18 + TypeScript, native `<dialog>`, Vite plugin API, `tsx --test`; Go test re-exec for the audit test.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md` (Phase 3 list, first half).

## Global Constraints

- Branch `fix/phase3a-foundation` from `fix/phase2-functional` (PR #59). One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`.
- The mock never ships: it lives under `frontend/mock/`, is loaded only by `npm run dev:mock`, and `vite build` must not include it.
- No new runtime dependencies. Copy rules: sentences, no em-dashes, no "successfully".
- After Task 4 there is no `confirm(`, `prompt(` or `alert(` left in `frontend/src` (grep must be empty). After Task 3 there is no `className="modal-overlay"` left.
- DOX: update `AGENTS.md` where a task changes a contract (Tasks 1, 3, 4, 5, 6 do).

## Review Focus

1. Pressing Escape in any dialog closes it and returns focus to the control that opened it; clicking the backdrop never discards typed state. Pinned: Task 3 (Dialog behaviour) and the Task 7 screenshot pass.
2. Refreshing on `#/admin/audit` lands on the audit tab; the back button after opening an entry returns to the list without a "discard edits" prompt when nothing was edited. Pinned: Task 5 tests plus the Task 7 pass.
3. At 390px wide the folder list, entry list and entry detail are each reachable and nothing overflows horizontally. Pinned: Task 7 screenshots.
4. A dialog asked while another is open queues rather than replacing it. Pinned: Task 3 `dialogQueue.test.ts`.
5. `go test -race -count=5 ./internal/audit` passes five times in a row. Pinned: Task 2.

---

### Task 1: Dev mock of the API so the app runs without KySignOn

**Files:**
- Create: `frontend/mock/api.ts`
- Modify: `frontend/vite.config.ts`
- Modify: `frontend/package.json` (script `dev:mock`)
- Modify: `AGENTS.md` (Verification section)

**Interfaces:**
- Produces: `npm run dev:mock` serves the app at the Vite port with `/api/*` answered in-process by `mockApi()`; a signed-in admin `mock-admin`, an empty vault (version 0) so the app creates one client-side, in-memory uploads, history, conflicts, devices, audit, SSO and backup status.

- [ ] **Step 1: Write the mock**

```ts
// frontend/mock/api.ts
// Dev-only stand-in for the Go API so the UI can run without KySignOn. Never built.
import type { Plugin } from "vite";
import { createHash } from "node:crypto";

type Store = {
  version: number; bytes: Buffer | null; passwordEnvelope?: string; recoveryEnvelope?: string;
  history: Array<{ id: string; version: number; sizeBytes: number; checksum: string; timestamp: string }>;
  devices: Array<{ id: string; name: string; platform: string; lastSeenAt: string; lastIp: string }>;
};

export function mockApi(): Plugin {
  const store: Store = { version: 0, bytes: null, history: [], devices: [
    { id: "dev-1", name: "Pixel 9", platform: "android", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.7" },
  ] };
  const user = { id: "u-1", username: "mock-admin", role: "admin", active: true, ssoSub: "sub-mock" };
  const json = (res: import("node:http").ServerResponse, status: number, body: unknown) => {
    res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(body));
  };
  const readBody = (req: import("node:http").IncomingMessage) => new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []; req.on("data", (c) => chunks.push(c)); req.on("end", () => resolve(Buffer.concat(chunks)));
  });
  const metadata = () => ({ version: store.version, checksum: store.bytes ? createHash("sha256").update(store.bytes).digest("hex") : "",
    sizeBytes: store.bytes?.length ?? 0, passwordEnvelope: store.passwordEnvelope, recoveryEnvelope: store.recoveryEnvelope });

  return { name: "kyvault-mock-api", configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const p = url.pathname; const m = req.method ?? "GET";
      if (!p.startsWith("/api/")) return next();
      res.setHeader("Set-Cookie", "csrf_token=mock-csrf; Path=/");
      if (p === "/api/auth/me") return json(res, 200, { authenticated: true, user });
      if (p === "/api/auth/sso-config") return json(res, 200, { enabled: true, issuerUrl: "https://signon.mock" });
      if (p === "/api/auth/logout") return json(res, 200, { ok: true });
      if (p === "/api/vault/metadata") return json(res, 200, metadata());
      if (p === "/api/vault/kdbx") {
        if (!store.bytes) return json(res, 404, { error: "vault does not exist yet" });
        res.setHeader("Content-Type", "application/x-keepass2"); res.setHeader("ETag", `"${store.version}"`); return res.end(store.bytes);
      }
      if (p === "/api/vault/upload" && m === "POST") {
        const expected = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
        if (expected !== store.version) return json(res, 409, { error: "conflict", currentVersion: store.version, expectedVersion: expected, conflictId: "c-1" });
        store.bytes = await readBody(req); store.version++;
        const env = req.headers["x-password-envelope"]; if (typeof env === "string" && env) store.passwordEnvelope = env;
        const meta = metadata();
        store.history.unshift({ id: `h-${store.version}`, version: store.version, sizeBytes: meta.sizeBytes, checksum: meta.checksum, timestamp: new Date().toISOString() });
        return json(res, 200, { ok: true, metadata: meta });
      }
      if (p === "/api/vault/envelopes" && m === "PUT") {
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        if (body.passwordEnvelope) store.passwordEnvelope = body.passwordEnvelope;
        if (body.recoveryEnvelope) store.recoveryEnvelope = body.recoveryEnvelope;
        return json(res, 200, { ok: true });
      }
      if (p === "/api/vault/history") return json(res, 200, store.history);
      if (p === "/api/vault/conflicts") return json(res, 200, []);
      if (p === "/api/devices" && m === "GET") return json(res, 200, store.devices);
      if (p.startsWith("/api/devices/") && m === "DELETE") { store.devices = store.devices.filter((d) => `/api/devices/${d.id}` !== p); return json(res, 200, { ok: true }); }
      if (p === "/api/devices/pairing/start") return json(res, 200, { pin: "483920", secret: "mock-secret", expiresAt: new Date(Date.now() + 90_000).toISOString() });
      if (p === "/api/admin/users") return json(res, 200, [user, { id: "u-2", username: "dana", role: "user", active: true, ssoSub: "sub-dana" }]);
      if (p === "/api/admin/sso" && m === "GET") return json(res, 200, { enabled: true, issuerUrl: "https://signon.mock", clientId: "kyvault", autoProvision: true, clientSecretSet: true });
      if (p === "/api/admin/sso" && m === "PUT") return json(res, 200, { ok: true });
      if (p === "/api/admin/provisioning") return json(res, 200, { configured: false, basePath: "/scim/v2" });
      if (p === "/api/audit/verify") return json(res, 200, { valid: true, writeFailures: 0, error: "" });
      if (p === "/api/audit") return json(res, 200, [{ index: 1, timestamp: new Date().toISOString(), action: "auth.sso_login", userId: "u-1", deviceId: "", ipAddress: "127.0.0.1", details: "signed in via SSO", hash: "abc123def456abc123def456" }]);
      if (p === "/api/backup/status") return json(res, 200, { paired: false, keyHealthy: false, backupDir: "", allowPrivate: false, intervalSec: 0, localCopies: [] });
      if (p.startsWith("/api/admin/users/")) return json(res, 200, { ok: true });
      return json(res, 404, { error: `mock: no handler for ${m} ${p}` });
    });
  } };
}
```

- [ ] **Step 2: Wire it behind an environment variable**

`frontend/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { mockApi } from "./mock/api";

export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(process.env.KYVAULT_MOCK_API === "1" ? [mockApi()] : [])],
  server: {
    port: 5878,
    proxy: process.env.KYVAULT_MOCK_API === "1" ? undefined : {
      "/api": { target: "http://localhost:5877", changeOrigin: true },
      "/auth": { target: "http://localhost:5877", changeOrigin: true },
      "/scim": { target: "http://localhost:5877", changeOrigin: true },
    },
  },
  build: { outDir: "dist", sourcemap: false },
}));
```

`package.json` scripts: add `"dev:mock": "KYVAULT_MOCK_API=1 vite"`.

- [ ] **Step 3: Verify**

Run: `cd frontend && npm run build && (npm run dev:mock -- --port 5199 --strictPort & sleep 3; curl -s http://localhost:5199/api/auth/me; fuser -k 5199/tcp)`
Expected: build has no `mock/` chunk (`grep -rl mock-admin dist` is empty); the curl prints the mock user JSON.

Open `http://localhost:5199/` in a browser: the unlock dialog appears; typing a 12-character master password creates a vault; Vault, Security and Admin all render without network errors.

- [ ] **Step 4: DOX and commit**

`AGENTS.md` Verification: add `- UI without KySignOn: \`npm run dev:mock\` in \`frontend/\` serves the app with an in-process mock of the API (\`frontend/mock/api.ts\`, dev only, never built) for manual and screenshot checks.`

```bash
git add frontend/mock/api.ts frontend/vite.config.ts frontend/package.json AGENTS.md
git commit -m "add a dev mock of the API so the UI runs without KySignOn"
```

---

### Task 2: Stop the audit short-write test from capping the whole test binary

**Files:**
- Modify: `internal/audit/shortwrite_linux_test.go`

The test lowers `RLIMIT_FSIZE` for the process; `go test`'s own `testlog.txt` write in that window fails with "file too large". Run the rlimit part in a child process.

- [ ] **Step 1: Re-exec into a child for the capped section**

At the top of `TestShortWriteLeavesNoTornLine`, before `dir, keyDir := ...`:

```go
	if os.Getenv("KYVAULT_SHORTWRITE_CHILD") != "1" {
		// RLIMIT_FSIZE is process-wide and also caps go test's own testlog.txt, which
		// made the parent binary fail at random. The capped part runs in a child.
		cmd := exec.Command(os.Args[0], "-test.run=^TestShortWriteLeavesNoTornLine$", "-test.v")
		cmd.Env = append(os.Environ(), "KYVAULT_SHORTWRITE_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child test failed: %v\n%s", err, out)
		}
		return
	}
```

Add `"os/exec"` to the imports. The rest of the test body is unchanged and runs only in the child.

- [ ] **Step 2: Verify**

Run: `go test -race -count=5 ./internal/audit && go vet ./internal/audit && gofmt -l internal/audit`
Expected: PASS five times, vet clean, gofmt empty.

- [ ] **Step 3: Commit**

```bash
git add internal/audit/shortwrite_linux_test.go
git commit -m "run the audit short-write test in a child process"
```

---

### Task 3: One Dialog component and a dialog host

**Files:**
- Create: `frontend/src/lib/dialogQueue.ts`
- Create: `frontend/src/lib/dialogQueue.test.ts`
- Create: `frontend/src/components/Dialog.tsx`
- Create: `frontend/src/components/DialogHost.tsx`
- Modify: `frontend/src/styles/styles.css` (dialog styles replace `.modal-overlay`)
- Modify: `frontend/src/main.tsx` (wrap `App` in `DialogHost`)
- Modify: `frontend/src/App.tsx` (unlock modal), `frontend/src/components/DevicePairingModal.tsx`, `HistoryModal.tsx`, `CsvImportModal.tsx`, `PasswordGenerator.tsx`, `EntryHistoryModal.tsx`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `<Dialog title onClose size?="md"|"lg" labelledBy?>children</Dialog>`: renders a native `<dialog>` opened with `showModal()`, Escape triggers `onClose`, backdrop clicks do nothing, focus returns to the previously focused element on close, a labelled close button in the header.
- `DialogQueue` (pure): `ask<T>(request: DialogRequest): Promise<T>`; `current(): DialogRequest | null`; `settle(value)`; `subscribe(listener)`. FIFO.
- `useDialogs()` from `DialogHost.tsx`: `{ confirm(opts): Promise<boolean>; prompt(opts): Promise<string | null>; notify(opts): Promise<void> }` with `opts = { title: string; message?: string; confirmLabel?: string; cancelLabel?: string; danger?: boolean; label?: string; defaultValue?: string; validate?: (v: string) => string | null }`.

- [ ] **Step 1: Write the failing queue test**

```ts
// frontend/src/lib/dialogQueue.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { DialogQueue } from "./dialogQueue";

test("dialogs are answered in order and one at a time", async () => {
  const q = new DialogQueue();
  const seen: Array<string | null> = [];
  q.subscribe(() => seen.push(q.current()?.title ?? null));
  const a = q.ask<boolean>({ kind: "confirm", title: "A" });
  const b = q.ask<string | null>({ kind: "prompt", title: "B" });
  assert.equal(q.current()?.title, "A");
  q.settle(true);
  assert.equal(await a, true);
  assert.equal(q.current()?.title, "B");
  q.settle("typed");
  assert.equal(await b, "typed");
  assert.equal(q.current(), null);
  assert.deepEqual(seen, ["A", "B", null]);
});

test("settle without a current dialog is a no-op", () => {
  const q = new DialogQueue();
  q.settle(true);
  assert.equal(q.current(), null);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/dialogQueue.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement the queue**

```ts
// frontend/src/lib/dialogQueue.ts
// Sequences modal questions so a second ask waits for the first answer instead of
// replacing it. Pure so it can be tested without React.
export type DialogRequest = {
  kind: "confirm" | "prompt" | "notify";
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  label?: string;
  defaultValue?: string;
  validate?: (value: string) => string | null;
};

type Pending = { id: number; request: DialogRequest; resolve: (value: unknown) => void };

export class DialogQueue {
  private pending: Pending[] = [];
  private listeners = new Set<() => void>();
  private seq = 0;

  ask<T>(request: DialogRequest): Promise<T> {
    return new Promise<T>((resolve) => {
      this.pending.push({ id: ++this.seq, request, resolve: resolve as (value: unknown) => void });
      if (this.pending.length === 1) this.notify();
    });
  }

  current(): DialogRequest | null { return this.pending[0]?.request ?? null; }
  // Distinct per question so two identical consecutive questions do not share form state.
  currentId(): number { return this.pending[0]?.id ?? 0; }

  settle(value: unknown): void {
    const head = this.pending.shift();
    if (!head) return;
    head.resolve(value);
    this.notify();
  }

  // Arrow property so React can hold a stable reference for useSyncExternalStore.
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private notify() { this.listeners.forEach((l) => l()); }
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/dialogQueue.test.ts`
Expected: PASS.

- [ ] **Step 5: Write the Dialog component**

```tsx
// frontend/src/components/Dialog.tsx
import { useEffect, useRef, type ReactNode } from "react";

type Props = { title: string; onClose: () => void; size?: "md" | "lg"; children: ReactNode; closeLabel?: string };

// Every modal in the app. Native <dialog> gives focus trapping, Escape and a backdrop for
// free; clicking the backdrop is deliberately not a close, so typed state is never lost.
export function Dialog({ title, onClose, size = "md", children, closeLabel = "Close" }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = ref.current;
    const opener = document.activeElement as HTMLElement | null;
    element?.showModal();
    return () => { element?.close(); opener?.focus?.(); };
  }, []);
  return (
    <dialog ref={ref} className={`modal-card dialog-${size}`} aria-labelledby="dialog-title"
      onCancel={(event) => { event.preventDefault(); onClose(); }}>
      <div className="modal-header">
        <h3 id="dialog-title">{title}</h3>
        <button type="button" className="btn btn-quiet btn-sm" aria-label={closeLabel} onClick={onClose}>✕</button>
      </div>
      {children}
    </dialog>
  );
}
```

- [ ] **Step 6: Write the host and hook**

```tsx
// frontend/src/components/DialogHost.tsx
import { createContext, useContext, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { DialogQueue, type DialogRequest } from "../lib/dialogQueue";
import { Dialog } from "./Dialog";

type Api = {
  confirm: (opts: Omit<DialogRequest, "kind">) => Promise<boolean>;
  prompt: (opts: Omit<DialogRequest, "kind">) => Promise<string | null>;
  notify: (opts: Omit<DialogRequest, "kind">) => Promise<void>;
};

const Context = createContext<Api | null>(null);

export function useDialogs(): Api {
  const api = useContext(Context);
  if (!api) throw new Error("useDialogs needs a DialogHost above it");
  return api;
}

export function DialogHost({ children }: { children: ReactNode }) {
  const [queue] = useState(() => new DialogQueue());
  const current = useSyncExternalStore(queue.subscribe, () => queue.current());
  const api = useMemo<Api>(() => ({
    confirm: (opts) => queue.ask<boolean>({ ...opts, kind: "confirm" }),
    prompt: (opts) => queue.ask<string | null>({ ...opts, kind: "prompt" }),
    notify: (opts) => queue.ask<void>({ ...opts, kind: "notify" }),
  }), [queue]);
  return (
    <Context.Provider value={api}>
      {children}
      {current ? <QuestionDialog key={queue.currentId()} request={current} settle={(v) => queue.settle(v)} /> : null}
    </Context.Provider>
  );
}

function QuestionDialog({ request, settle }: { request: DialogRequest; settle: (value: unknown) => void }) {
  const [value, setValue] = useState(request.defaultValue ?? "");
  const [problem, setProblem] = useState<string | null>(null);
  const cancelValue = request.kind === "confirm" ? false : request.kind === "prompt" ? null : undefined;
  const submit = () => {
    if (request.kind === "prompt") {
      const message = request.validate?.(value) ?? null;
      if (message) { setProblem(message); return; }
      settle(value);
    } else settle(request.kind === "confirm" ? true : undefined);
  };
  return (
    <Dialog title={request.title} onClose={() => settle(cancelValue)}>
      {request.message ? <p style={{ color: "var(--ink-muted)", whiteSpace: "pre-wrap" }}>{request.message}</p> : null}
      <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
        {request.kind === "prompt" ? (
          <div className="input-group">
            <label className="input-label" htmlFor="dialog-input">{request.label ?? request.title}</label>
            <input id="dialog-input" className="input" autoFocus value={value}
              onChange={(e) => { setValue(e.target.value); setProblem(null); }} />
            {problem ? <p role="alert" style={{ color: "var(--danger)" }}>{problem}</p> : null}
          </div>
        ) : null}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1rem" }}>
          {request.kind !== "notify" ? (
            <button type="button" className="btn btn-secondary" onClick={() => settle(cancelValue)}>{request.cancelLabel ?? "Cancel"}</button>
          ) : null}
          <button type="submit" className={`btn ${request.danger ? "btn-danger" : "btn-primary"}`} autoFocus={request.kind !== "prompt"}>
            {request.confirmLabel ?? (request.kind === "notify" ? "OK" : "Continue")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
```

`main.tsx`: wrap `<App />` in `<DialogHost>…</DialogHost>`.

- [ ] **Step 7: Styles**

In `styles.css` delete the `.modal-overlay` rule and change `.modal-card` to apply to the dialog element:

```css
dialog.modal-card { margin: auto; border: 1px solid var(--line); color: var(--ink-strong); }
dialog.modal-card::backdrop { background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(4px); }
dialog.dialog-lg { max-width: 760px; }
@media (max-width: 600px) { dialog.modal-card { width: 100vw; max-width: 100vw; max-height: 100dvh; border-radius: 0; padding: 1.25rem; } }
```

Keep the existing `.modal-card` properties (background, radius, padding, max-width 540px, width 90%, max-height 90vh, overflow, shadow). Remove `.entry-history-dialog::backdrop` (now covered) and keep its width override.

- [ ] **Step 8: Migrate the six modals**

For each of `App.tsx` unlock modal, `DevicePairingModal`, `HistoryModal` (size "lg"), `CsvImportModal` (size "lg"), `PasswordGenerator`, and `EntryHistoryModal`: replace the `<div className="modal-overlay" onClick=…><div className="modal-card" onClick=stopPropagation><div className="modal-header"><h3>…</h3><button…>✕</button></div>` shell with `<Dialog title="…" onClose={…}>` and delete the duplicated header. `EntryHistoryModal` drops its own `useRef`/`showModal` and `<dialog>`; it becomes `<Dialog title="Entry History" onClose={onClose} size="lg">`. The unlock modal's `onClose` is `() => setShowUnlockModal(false)` and its Cancel button stays.

- [ ] **Step 9: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build && grep -rn 'modal-overlay' src || echo none`
Expected: PASS, `none`.

With `npm run dev:mock`: open each modal, press Escape (closes), click the backdrop (stays open), Tab cycles inside the dialog.

`AGENTS.md` Child DOX Index add: `- \`frontend/src/components/Dialog.tsx\` and \`DialogHost.tsx\`: every modal uses \`Dialog\` (native \`<dialog>\`, Escape closes, backdrop click never closes, focus returns to the opener). Questions go through \`useDialogs().confirm/prompt/notify\`, sequenced by \`lib/dialogQueue.ts\` so a second question waits for the first. Native \`confirm\`, \`prompt\` and \`alert\` are banned in \`frontend/src\`.`

```bash
git add frontend/src/lib/dialogQueue.ts frontend/src/lib/dialogQueue.test.ts frontend/src/components/Dialog.tsx frontend/src/components/DialogHost.tsx frontend/src/styles/styles.css frontend/src/main.tsx frontend/src/App.tsx frontend/src/components/DevicePairingModal.tsx frontend/src/components/HistoryModal.tsx frontend/src/components/CsvImportModal.tsx frontend/src/components/PasswordGenerator.tsx frontend/src/components/EntryHistoryModal.tsx AGENTS.md
git commit -m "one Dialog component and a dialog host for every modal"
```

---

### Task 4: Replace every native confirm, prompt and alert

**Files:**
- Modify: `frontend/src/App.tsx` (7 sites), `frontend/src/pages/VaultPage.tsx` (8), `frontend/src/pages/SecuritySettings.tsx` (3), `frontend/src/pages/AdminPanel.tsx` (1), `frontend/src/components/HistoryModal.tsx` (2), `EntryAttachments.tsx` (2), `EntryHistoryModal.tsx` (1), `AdminBackup.tsx` (1)
- Modify: `frontend/src/lib/vaultSave.ts` (`canDiscardVault` takes an async confirmer)
- Modify: `frontend/src/lib/vaultSave.test.ts` (the `canDiscardVault` test becomes async)

**Interfaces:**
- `canDiscardVault(state, hasDraft, confirmDiscard: () => Promise<boolean>): Promise<boolean>`.
- In `VaultPage`, `canChangeEntry(): Promise<boolean>`; every caller awaits it.
- `App.tsx` `confirmDiscardVault(): Promise<boolean>`; `handleLogout`, `handleForgetDevice`, `handleLockVault`, `onUserUpdated` await it.

- [ ] **Step 1: Update the `canDiscardVault` test and helper**

In `vaultSave.test.ts` the test "security actions proceed in every save state unless the user declines discarding edits" becomes async: `await canDiscardVault(state, hasDraft, async () => false)` and `async () => true`. In `vaultSave.ts`:

```ts
export async function canDiscardVault(state: SaveState, hasDraft: boolean, confirmDiscard: () => Promise<boolean>): Promise<boolean> {
  return (!hasDraft && state.kind === "saved") || confirmDiscard();
}
```

Run: `cd frontend && npx tsx --test src/lib/vaultSave.test.ts` → PASS.

- [ ] **Step 2: Replace the sites**

Pattern for each file: `const dialogs = useDialogs();` at the top of the component, then:

- `confirm(msg)` → `await dialogs.confirm({ title: <short title>, message: msg, confirmLabel: <verb>, danger: <true for destructive> })`. Titles and verbs: "Discard unsaved edits?" / "Discard"; "Move to Recycle Bin?" / "Move" (or "Delete permanently?" / "Delete", danger); "Restore this version?" / "Restore"; "Roll back the vault?" / "Roll back" (danger); "Discard this conflict?" / "Discard" (danger); "Remove attachment?" / "Remove" (danger); "Clear attachment history?" / "Clear" (danger); "Generate a new paper code?" / "Generate"; "Show the vault key?" / "Show"; "Revoke device?" / "Revoke" (danger); "Deactivate user?" or "Reactivate user?" / matching verb (danger for deactivate); "Unpair KyRecovery?" / "Unpair" (danger); "Reload server copy?" / "Reload" (danger).
- `prompt(msg, default)` (folder create and rename) → `await dialogs.prompt({ title: "New folder" | "Rename folder", label: "Folder name", defaultValue, validate: (v) => v.trim() ? null : "Enter a folder name." })`.
- `alert(msg)` → `await dialogs.notify({ title: "Could not complete that", message: msg })` with a more specific title where obvious ("Sign-out did not reach the server", "Folder not created", "Entry not restored", "Setting not saved").
- Handlers that were sync become `async`; `onClick={handler}` still works. `canChangeEntry` is awaited by `handleCreateNewEntry`, the Recycle Bin button, entry clicks in the list and the `onReload` path.

- [ ] **Step 3: Verify and commit**

Run: `cd frontend && npm test && npm run build && grep -rnE '\b(confirm|prompt|alert)\(' src --include='*.tsx' || echo none`
Expected: PASS, `none`.

With `npm run dev:mock`: delete an entry (dialog), create a folder (prompt dialog with validation), lock with a dirty draft (confirm dialog).

```bash
git add frontend/src frontend/src/lib/vaultSave.ts frontend/src/lib/vaultSave.test.ts
git commit -m "replace every native confirm, prompt and alert with the dialog host"
```

---

### Task 5: Hash routes for tabs, admin tabs and the selected entry

**Files:**
- Create: `frontend/src/lib/route.ts`
- Create: `frontend/src/lib/route.test.ts`
- Modify: `frontend/src/App.tsx` (`navTab` from the route), `frontend/src/pages/AdminPanel.tsx` (`activeTab` from the route), `frontend/src/pages/VaultPage.tsx` (selected entry to and from the route)
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `type Route = { tab: "vault" | "security" | "admin"; admin?: "sso" | "users" | "audit" | "backup"; entry?: string }`; `parseRoute(hash: string): Route`; `formatRoute(route: Route): string`; `useRoute(): [Route, (next: Route) => void]` (hashchange via `useSyncExternalStore`; the setter writes `location.hash`).

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/route.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRoute, formatRoute } from "./route";

test("routes round-trip and unknown input falls back to the vault", () => {
  assert.deepEqual(parseRoute(""), { tab: "vault" });
  assert.deepEqual(parseRoute("#/"), { tab: "vault" });
  assert.deepEqual(parseRoute("#/vault/abc-123"), { tab: "vault", entry: "abc-123" });
  assert.deepEqual(parseRoute("#/security"), { tab: "security" });
  assert.deepEqual(parseRoute("#/admin/audit"), { tab: "admin", admin: "audit" });
  assert.deepEqual(parseRoute("#/admin"), { tab: "admin", admin: "sso" });
  assert.deepEqual(parseRoute("#/admin/nope"), { tab: "admin", admin: "sso" });
  assert.deepEqual(parseRoute("#/bogus"), { tab: "vault" });
  assert.equal(formatRoute({ tab: "vault" }), "#/vault");
  assert.equal(formatRoute({ tab: "vault", entry: "abc" }), "#/vault/abc");
  assert.equal(formatRoute({ tab: "admin", admin: "users" }), "#/admin/users");
  assert.equal(formatRoute(parseRoute("#/vault/x%20y")), "#/vault/x%20y");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/route.test.ts` → FAIL.

- [ ] **Step 3: Implement**

```ts
// frontend/src/lib/route.ts
import { useCallback, useSyncExternalStore } from "react";

export type AdminTab = "sso" | "users" | "audit" | "backup";
export type Route = { tab: "vault" | "security" | "admin"; admin?: AdminTab; entry?: string };
const ADMIN_TABS: AdminTab[] = ["sso", "users", "audit", "backup"];

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "security") return { tab: "security" };
  if (parts[0] === "admin") return { tab: "admin", admin: ADMIN_TABS.includes(parts[1] as AdminTab) ? (parts[1] as AdminTab) : "sso" };
  if (parts[0] === "vault" && parts[1]) return { tab: "vault", entry: decodeURIComponent(parts[1]) };
  return { tab: "vault" };
}

export function formatRoute(route: Route): string {
  if (route.tab === "security") return "#/security";
  if (route.tab === "admin") return `#/admin/${route.admin ?? "sso"}`;
  return route.entry ? `#/vault/${encodeURIComponent(route.entry)}` : "#/vault";
}

const subscribe = (listener: () => void) => { window.addEventListener("hashchange", listener); return () => window.removeEventListener("hashchange", listener); };
const read = () => window.location.hash;

export function useRoute(): [Route, (next: Route) => void] {
  const hash = useSyncExternalStore(subscribe, read, () => "");
  const navigate = useCallback((next: Route) => { const target = formatRoute(next); if (window.location.hash !== target) window.location.hash = target; }, []);
  return [parseRoute(hash), navigate];
}
```

- [ ] **Step 4: Run the test**

Run: `cd frontend && npx tsx --test src/lib/route.test.ts` → PASS.

- [ ] **Step 5: Wire it**

- `App.tsx`: replace `navTab` state with `const [route, navigate] = useRoute(); const navTab = route.tab;` and the three nav buttons call `navigate({ tab: "vault" })` etc. (admin button `navigate({ tab: "admin", admin: "sso" })`). Pass `route` and `navigate` to `AdminPanel` and `VaultPage`. A non-admin on `#/admin/...` is redirected: `useEffect(() => { if (route.tab === "admin" && user?.role !== "admin") navigate({ tab: "vault" }); }, [route.tab, user?.role])`.
- `AdminPanel.tsx`: `activeTab = route.admin ?? "sso"`; tab buttons call `navigate({ tab: "admin", admin: "users" })` etc. Remove the `useState`.
- `VaultPage.tsx`: when the user selects an entry (list click, create), after `setSelectedEntryUuid(uuid)` also `navigate({ tab: "vault", entry: uuid })`. On mount and when `route.entry` changes: if `route.entry` differs from `selectedEntryUuid` and the entry exists, `if (await canChangeEntry()) { setIsEditing(false); setSelectedEntryUuid(route.entry); }`; if the user declines, `navigate({ tab: "vault", entry: selectedEntryUuid ?? undefined })` to keep the hash truthful. Delete sets the route entry to undefined.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build` → PASS. With `npm run dev:mock`: refresh on `#/admin/audit` lands on Audit; open an entry, press back, the list shows and no prompt appears; edit an entry, press back, the discard prompt appears and Cancel keeps the hash on the entry.

`AGENTS.md` Child DOX Index add: `- \`frontend/src/lib/route.ts\`: hash routes \`#/vault[/entryUuid]\`, \`#/security\`, \`#/admin/{sso|users|audit|backup}\` drive the top tabs, admin tabs and the selected entry; unknown routes fall back to the vault; a non-admin on an admin route is redirected. \`route.test.ts\` covers parsing and formatting.`

```bash
git add frontend/src/lib/route.ts frontend/src/lib/route.test.ts frontend/src/App.tsx frontend/src/pages/AdminPanel.tsx frontend/src/pages/VaultPage.tsx AGENTS.md
git commit -m "hash routes for tabs, admin tabs and the selected entry"
```

---

### Task 6: The vault works on a phone

**Files:**
- Create: `frontend/src/lib/useMediaQuery.ts`
- Modify: `frontend/src/pages/VaultPage.tsx`
- Modify: `frontend/src/App.tsx` (nav labels)
- Modify: `frontend/src/styles/styles.css`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `useMediaQuery(query: string): boolean` (`matchMedia` via `useSyncExternalStore`, false during SSR). `VaultPage` keeps `pane: "folders" | "list" | "detail"` for narrow layouts.

- [ ] **Step 1: The hook**

```ts
// frontend/src/lib/useMediaQuery.ts
import { useSyncExternalStore } from "react";

export function useMediaQuery(query: string): boolean {
  const subscribe = (listener: () => void) => {
    const mql = window.matchMedia(query);
    mql.addEventListener("change", listener);
    return () => mql.removeEventListener("change", listener);
  };
  return useSyncExternalStore(subscribe, () => window.matchMedia(query).matches, () => false);
}

export const NARROW = "(max-width: 900px)";
export const PHONE = "(max-width: 600px)";
```

- [ ] **Step 2: VaultPage pane state**

- `const narrow = useMediaQuery(NARROW); const [pane, setPane] = useState<"folders" | "list" | "detail">("list");`
- Root element: `<div className={`vault-layout${narrow ? " vault-layout--narrow" : ""}`} data-pane={pane} …>`.
- Selecting an entry (list click, create, route entry) also `setPane("detail")`; selecting a folder (any group, All Items, Recycle Bin) also `setPane("list")`.
- List header gets a button before the search box, visible only when narrow: `<button className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Folders" onClick={() => setPane("folders")}><Folder size={16} /></button>`.
- Detail header gets a back button, visible only when narrow: `<button className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Back to list" onClick={() => setPane("list")}>←</button>` (use the `ChevronLeft` lucide icon instead of the arrow glyph).
- The folder pane gets a close button in its header when narrow (`aria-label="Close folders"`, sets pane to list).

- [ ] **Step 3: Styles**

Append to `styles.css`:

```css
.vault-only-narrow { display: none; }
.vault-layout--narrow { grid-template-columns: 1fr; height: calc(100dvh - var(--nav-height, 57px)); }
.vault-layout--narrow .vault-only-narrow { display: inline-flex; }
.vault-layout--narrow .vault-sidebar, .vault-layout--narrow .vault-list-pane, .vault-layout--narrow .vault-detail-pane { display: none; border-right: 0; }
.vault-layout--narrow[data-pane="folders"] .vault-sidebar { display: flex; }
.vault-layout--narrow[data-pane="list"] .vault-list-pane { display: flex; }
.vault-layout--narrow[data-pane="detail"] .vault-detail-pane { display: block; padding: 1rem; }
.vault-layout--narrow .detail-header { flex-wrap: wrap; gap: 0.5rem; }
.vault-layout--narrow .field-row { flex-wrap: wrap; }
@media (max-width: 600px) {
  .app-nav { padding: 0.5rem 0.75rem; }
  .nav-link-btn span, .nav-user-name { display: none; }
  .settings-page { padding: 1rem 0.75rem; }
  .vault-detail-pane .font-mono { overflow-wrap: anywhere; }
}
```

In `App.tsx` wrap each nav label in a `<span>` (e.g. `<Shield size={16} /> <span>Vault</span>`) and add `aria-label` to each button; give the username element `className="nav-user-name"`. The `.vault-layout` height uses `100dvh` in the narrow rule so mobile browser chrome does not clip the list.

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build` → PASS.

With `npm run dev:mock` at 390px wide: list shows by default, Folders button opens the sidebar, tapping an entry shows detail with a Back button, no horizontal scrollbar on any pane; at 1280px the three panes are unchanged.

`AGENTS.md` Child DOX Index add: `- \`frontend/src/lib/useMediaQuery.ts\` and \`VaultPage\` panes: under 900px the vault is one pane at a time (folders, list, detail) with Folders and Back controls; under 600px nav labels collapse to icons with aria-labels. Desktop keeps the three-column grid.`

```bash
git add frontend/src/lib/useMediaQuery.ts frontend/src/pages/VaultPage.tsx frontend/src/App.tsx frontend/src/styles/styles.css AGENTS.md
git commit -m "one-pane vault under 900px; icon nav under 600px"
```

---

### Task 7: Screenshot pass and PR (controller)

- [ ] **Step 1: Full verification**

```bash
gofmt -l . ; go vet ./... ; go test -race ./...
cd frontend && npm test && npm run build && cd ..
```

- [ ] **Step 2: Screenshots with the mock**

`npm run dev:mock -- --port 5199`; Playwright at 1280×800, 900×800 and 390×844: login is skipped by the mock, create a vault with a 12-character password, add one entry, capture Vault (list and detail on the phone), the delete confirm dialog, the folder prompt dialog, Security, Admin → Audit after a refresh on `#/admin/audit`. Attach the PNGs to the PR. Note any overflow or overlap and fix it in a follow-up commit before opening the PR.

- [ ] **Step 3: Open the PR**

Use the `pull-request` skill. Title: `Phase 3a UI foundation: dialogs, routes, responsive vault, dev mock`. Base: `master` if #59 has merged, else `fix/phase2-functional`.
