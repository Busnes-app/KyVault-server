// Plain DOM. The popup is a view: it asks the background worker for state and
// sends the typed password there once. It never receives the vault key.
import { ext } from "../ext";
import type { Request, Response } from "../messages";

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
  if (res.locked) return renderLocked();
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
    // Reopens the vault if the worker was evicted, and counts as activity.
    const opened = await send({ type: "ensure" });
    if (opened.type === "error") return showError(opened);
    root.replaceChildren(text("p", "The vault is unlocked."));
  }
}

function renderLocked(): void {
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
