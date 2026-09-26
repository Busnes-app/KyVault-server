// Plain DOM. The popup is a view: it asks the background worker for state and
// sends the typed password there once. It never receives the vault key.
import { ext } from "../ext";
import type { EntryView } from "../lib/rank";
import { sameSite } from "../lib/domain";
import type { SecretField } from "../lib/vaultState";
import type { Request, Response } from "../messages";
import { copyText, SECRET_CLIPBOARD_MS } from "../../../frontend/src/lib/clipboard";
import { DEFAULT_GENERATOR, generatePassword } from "../../../frontend/src/lib/generatePassword";

const SEARCH_DEBOUNCE_MS = 150;

const root = document.getElementById("root")!;
const lockButton = document.getElementById("lock") as HTMLButtonElement;

function send(message: Request): Promise<Response> {
  return ext.runtime.sendMessage(message);
}

function text(tag: "p" | "label", content: string, className?: string): HTMLElement {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function optionsButton(): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Open options";
  button.addEventListener("click", () => void ext.runtime.openOptionsPage());
  return button;
}

function showError(res: Extract<Response, { type: "error" }>): void {
  if (res.locked) return renderLocked(res.message);
  root.replaceChildren(text("p", res.message, "error"));
  if (res.revoked) root.append(optionsButton());
}

async function render(): Promise<void> {
  const res = await send({ type: "status" });
  if (res.type !== "status") return showError(res as Extract<Response, { type: "error" }>);
  lockButton.hidden = !res.status.unlocked;
  if (!res.status.paired) {
    root.replaceChildren(text("p", "Pair this extension with your KyVault server first."), optionsButton());
  } else if (!res.status.unlocked) {
    renderLocked();
  } else {
    await renderVault();
  }
}

// hasOffscreen is Chrome only (Firefox has no offscreen API): the background can
// blind-clear the clipboard after the popup closes there, so the toast differs.
const hasOffscreen = typeof ext.offscreen !== "undefined";

function copyButton(label: string, uuid: string, field: SecretField, status: HTMLElement): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", () => void copyField(uuid, field, status));
  return button;
}

async function copyField(uuid: string, field: SecretField, status: HTMLElement): Promise<void> {
  const res = await send({ type: "copy", uuid, field });
  if (res.type === "error") return showError(res);
  if (res.type !== "secret") return;
  const copied = await copyText(res.value, { clearAfterMs: SECRET_CLIPBOARD_MS });
  if (!copied) {
    status.className = "error";
    status.textContent = "Could not copy to the clipboard.";
    return;
  }
  // Keep the deadline armed even if this popup closes before the local timer fires.
  await send({ type: "copied" });
  status.className = "muted";
  status.textContent = hasOffscreen
    ? "Copied. Clears in 30 seconds."
    : "Copied. Clears in 30 seconds while this window is open.";
}

// The background refuses a mismatched fill too; this only explains it before the click.
function fillRefusal(entry: EntryView, tabHost: string | undefined): string | undefined {
  let host = "";
  try {
    host = new URL(entry.url).hostname;
  } catch {
    // no address
  }
  if (!host) return "This login has no website address.";
  if (!tabHost || !sameSite(host, tabHost)) return `This login is for ${host}, not this page.`;
  return undefined;
}

function fillButton(entry: EntryView, tabHost: string | undefined, status: HTMLElement): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Fill";
  const refusal = fillRefusal(entry, tabHost);
  button.disabled = refusal !== undefined;
  if (refusal) button.title = refusal;
  button.addEventListener("click", async () => {
    const res = await send({ type: "fill", uuid: entry.uuid });
    if (res.type === "error" && (res.locked || res.revoked)) return showError(res);
    status.className = res.type === "error" ? "error" : "muted";
    status.textContent = res.type === "error" ? res.message : "Filled.";
  });
  return button;
}

function renderRows(entries: EntryView[], tabHost: string | undefined, list: HTMLElement, status: HTMLElement): void {
  list.replaceChildren();
  if (entries.length === 0) {
    list.append(text("p", "No logins for this site.", "muted"));
    return;
  }
  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "entry-row";
    const heading = document.createElement("div");
    heading.className = "entry-heading";
    heading.append(text("p", entry.title));
    if (entry.reused > 1) heading.append(text("p", "Reused", "badge"));
    const actions = document.createElement("div");
    actions.className = "entry-actions";
    actions.append(fillButton(entry, tabHost, status));
    actions.append(copyButton("Copy user", entry.uuid, "username", status), copyButton("Copy password", entry.uuid, "password", status));
    if (entry.hasTotp) actions.append(copyButton("Copy TOTP", entry.uuid, "totp", status));
    row.append(heading, text("p", entry.username, "muted"), actions);
    list.append(row);
  }
}

async function renderVault(): Promise<void> {
  const container = document.createElement("div");
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = "Search logins";
  search.setAttribute("aria-label", "Search logins");
  const list = document.createElement("div");
  list.className = "entries";
  const status = text("p", "", "muted");
  status.setAttribute("role", "status");
  const save = saveForm((quiet) => load(search.value, quiet));
  container.append(search, list, status, save.form);
  root.replaceChildren(container);

  // quiet: a failure leaves the view as it is (the save form keeps what was typed).
  const load = async (query: string, quiet = false): Promise<void> => {
    const res = await send({ type: "entries", query });
    if (res.type === "error") return quiet ? undefined : showError(res);
    if (res.type !== "entries") return;
    renderRows(res.entries, res.tabHost, list, status);
    save.prefill(res.tabHost, res.tabOrigin);
  };

  let debounce: ReturnType<typeof setTimeout> | undefined;
  search.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => void load(search.value), SEARCH_DEBOUNCE_MS);
  });

  await load("");
  search.focus();
}

function field(labelText: string, input: HTMLInputElement, id: string): HTMLElement {
  input.id = id;
  const label = text("label", labelText);
  label.setAttribute("for", id);
  const wrap = document.createElement("div");
  wrap.className = "field";
  wrap.append(label, input);
  return wrap;
}

// Typed by the user in this popup; page fields are never read. The values go to the
// background once; the form clears only after the save is confirmed.
function saveForm(refresh: (quiet?: boolean) => Promise<void>): { form: HTMLElement; prefill: (host?: string, origin?: string) => void } {
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Save login for this site";
  const form = document.createElement("form");
  const inputs = { title: document.createElement("input"), url: document.createElement("input"), username: document.createElement("input"), password: document.createElement("input") };
  inputs.title.required = true;
  inputs.url.type = "url";
  inputs.username.autocomplete = "off";
  inputs.password.type = "password";
  inputs.password.autocomplete = "new-password";
  inputs.password.required = true;
  const generate = document.createElement("button");
  generate.type = "button";
  generate.textContent = "Generate";
  generate.addEventListener("click", () => {
    inputs.password.value = generatePassword(DEFAULT_GENERATOR);
  });
  const passwordRow = document.createElement("div");
  passwordRow.className = "password-row";
  passwordRow.append(inputs.password, generate);
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Save login";
  const status = text("p", "", "muted");
  status.setAttribute("role", "status");
  const passwordLabel = text("label", "Password");
  inputs.password.id = "save-password";
  passwordLabel.setAttribute("for", inputs.password.id);
  form.append(
    field("Title", inputs.title, "save-title"),
    field("Website address", inputs.url, "save-url"),
    field("Username", inputs.username, "save-username"),
    passwordLabel,
    passwordRow,
    submit,
    status,
  );
  details.append(summary, form);

  let defaults = { title: "", url: "" };
  const reset = () => {
    form.reset();
    inputs.title.value = defaults.title;
    inputs.url.value = defaults.url;
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const login = { title: inputs.title.value, url: inputs.url.value, username: inputs.username.value, password: inputs.password.value };
    submit.disabled = true;
    status.className = "muted";
    status.textContent = "Saving the login.";
    const res = await send({ type: "saveLogin", login });
    submit.disabled = false;
    if (res.type === "error") {
      if (res.locked || res.revoked) return showError(res);
      // The upload may have landed even though the answer did not; the list is the truth.
      // Keep the typed values, and never let the refresh replace this view.
      status.className = "error";
      status.textContent = `${res.message} KyVault could not confirm the save. Check the list above before adding it again.`;
      await refresh(true).catch(() => {});
      return;
    }
    reset();
    status.textContent = "Saved to the vault.";
    await refresh();
  });

  return {
    form: details,
    prefill: (host, origin) => {
      const pristine = inputs.title.value === defaults.title && inputs.url.value === defaults.url;
      defaults = { title: host ?? "", url: origin ?? "" };
      if (pristine) reset();
    },
  };
}

function renderLocked(notice?: string): void {
  lockButton.hidden = true;
  const form = document.createElement("form");
  const label = text("label", "Master password");
  const input = document.createElement("input");
  input.type = "password";
  input.id = "password";
  input.autocomplete = "current-password";
  input.required = true;
  label.setAttribute("for", input.id);
  const button = document.createElement("button");
  button.type = "submit";
  button.textContent = "Unlock";
  const status = text("p", "", "muted");
  status.setAttribute("role", "status");
  if (notice) status.textContent = notice;
  form.append(label, input, button, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = input.value;
    input.value = "";
    button.disabled = true;
    status.className = "muted";
    status.textContent = "Unlocking takes about a second.";
    const res = await send({ type: "unlock", password });
    if (res.type === "error") {
      if (res.revoked) return showError(res);
      button.disabled = false;
      status.className = "error";
      status.textContent = res.message;
      input.focus();
      return;
    }
    await render();
  });
  root.replaceChildren(form);
  input.focus();
}

lockButton.addEventListener("click", async () => {
  await send({ type: "lock" });
  await render();
});

void render();
