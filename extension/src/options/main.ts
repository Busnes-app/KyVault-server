// Plain DOM, no framework. Pairing runs entirely in this click handler
// (parseServerOrigin, then permissions.request, then the redeem fetch) so the
// browser's user-gesture requirement for permissions.request is met; the
// token this produces is written straight to storage.local and never sent
// through the background worker's message channel.
import { ext } from "../ext";
import { parseServerOrigin } from "../lib/serverUrl";
import { browserPairIO, pair } from "../lib/pairing";
import { saveSettings } from "../lib/settings";
import { AUTO_LOCK_MINUTES, parseAutoLockMinutes, type AutoLockMinutes } from "../../../frontend/src/lib/autoLock";
import type { Request, Response, StatusResponse } from "../messages";

const root = document.getElementById("root")!;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

async function notifyBackground(message: Request): Promise<void> {
  await ext.runtime.sendMessage(message);
}

async function getStatus(): Promise<StatusResponse> {
  let response = (await ext.runtime.sendMessage({ type: "status" } satisfies Request)) as Response;
  // A revoked device is forgotten by then; ask again for the unpaired status.
  if (response.type === "error" && response.revoked) response = (await ext.runtime.sendMessage({ type: "status" } satisfies Request)) as Response;
  if (response.type !== "status") throw new Error("Could not read the extension's status.");
  return response.status;
}

function lockField(value: AutoLockMinutes): { label: HTMLLabelElement; select: HTMLSelectElement } {
  const label = el("label");
  label.textContent = "Lock the vault after";
  const select = el("select");
  for (const minutes of AUTO_LOCK_MINUTES) {
    const option = el("option", { value: String(minutes) });
    option.textContent = `${minutes} minute${minutes === 1 ? "" : "s"} idle`;
    select.append(option);
  }
  select.value = String(value);
  return { label, select };
}

async function render(): Promise<void> {
  root.textContent = "";
  // The options page never reads the session token into page memory; it asks
  // the background worker whether it is paired instead.
  const status = await getStatus();
  if (status.paired && status.serverOrigin) {
    renderPaired(status.serverOrigin, status.deviceName || "this device", status.autoLockMinutes);
  } else {
    renderPairingForm(status.autoLockMinutes);
  }
}

function renderPaired(origin: string, deviceName: string, autoLockMinutes: AutoLockMinutes): void {
  const status = el("p");
  status.textContent = `Paired with ${origin} as ${deviceName}.`;

  // The background saves it and restarts an unlocked vault's idle deadline under the new window.
  const lock = lockField(autoLockMinutes);
  const saved = el("p");
  saved.setAttribute("role", "status");
  lock.select.addEventListener("change", async () => {
    await notifyBackground({ type: "setAutoLock", minutes: Number(lock.select.value) });
    saved.textContent = "Saved.";
  });

  const note = el("p");
  note.textContent = "Unpairing also removes this device from Security, then Devices, when the server can be reached.";

  const unpairButton = el("button");
  unpairButton.textContent = "Unpair";
  unpairButton.addEventListener("click", async () => {
    unpairButton.disabled = true;
    await notifyBackground({ type: "unpair" });
    await render();
  });

  root.append(status, lock.label, lock.select, saved, note, unpairButton);
}

function renderPairingForm(autoLockMinutes: AutoLockMinutes): void {
  const intro = el("p");
  intro.textContent = "In KyVault, open Security, then Devices, then Pair a device.";

  const serverLabel = el("label");
  serverLabel.textContent = "Server address";
  const serverInput = el("input", { type: "text", placeholder: "https://vault.example.com" });

  const codeLabel = el("label");
  codeLabel.textContent = "Pairing code or PIN";
  const codeInput = el("input", { type: "text", placeholder: "123456" });

  const nameLabel = el("label");
  nameLabel.textContent = "Device name";
  const nameInput = el("input", { type: "text", maxlength: "64" });
  nameInput.value = "Browser extension";

  const { label: lockLabel, select: lockSelect } = lockField(autoLockMinutes);

  const status = el("p");
  status.setAttribute("role", "status");

  const pairButton = el("button");
  pairButton.textContent = "Pair";
  pairButton.addEventListener("click", async () => {
    status.textContent = "";
    let origin: string;
    try {
      origin = parseServerOrigin(serverInput.value);
    } catch (err) {
      status.textContent = (err as Error).message;
      return;
    }
    pairButton.disabled = true;
    try {
      const io = browserPairIO((pattern) => ext.permissions.request({ origins: [pattern] }));
      const deviceName = nameInput.value.trim() || "Browser extension";
      const { deviceId, sessionToken } = await pair(io, origin, codeInput.value, deviceName);
      await saveSettings({
        serverOrigin: origin,
        sessionToken,
        deviceId,
        deviceName,
        autoLockMinutes: parseAutoLockMinutes(Number(lockSelect.value)),
      });
      await notifyBackground({ type: "paired" });
      await render();
    } catch (err) {
      status.textContent = (err as Error).message;
    } finally {
      pairButton.disabled = false;
    }
  });

  root.append(
    intro,
    serverLabel, serverInput,
    codeLabel, codeInput,
    nameLabel, nameInput,
    lockLabel, lockSelect,
    pairButton, status,
  );
}

render();
